#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3

CAN_USE_WITHOUT_ROWID = sqlite3.sqlite_version.startswith('3.8')


# class LiteKV(object):
#     """Return object that has similar API with redis-py.

#     >>> db = LiteKV(reset=True)
#     >>> db.set('a', '1')
#     >>> db.get('a')
#     '1'
#     >>> db.set('a', '2')
#     >>> db.get('a')
#     '2'
#     >>> db.set('b', '3')
#     >>> list(db.keys())
#     ['a', 'b']
#     >>> db.delete('a')
#     >>> db.get('a') is None
#     True
#     """

#     def __init__(self, filename='tmp.sqlite', db=0, reset=False, rowid=True):
#         self._conn = sqlite3.connect(filename)
#         assert isinstance(db, int), '`db` must be int'
#         self._table_name = "__litekv_db_%s" % db

#         if reset:
#             self._conn.execute("DROP TABLE IF EXISTS %s" % self._table_name)

#         if (not rowid) and CAN_USE_WITHOUT_ROWID:
#             sql = "CREATE TABLE IF NOT EXISTS %s (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;" % self._table_name
#         else:
#             if not rowid:
#                 print 'Warning: as sqlite version is %s smaller than 3.8, WITHOUT ROWID can not be used, argument `rowid` will not affect' % sqlite3.sqlite_version
#             sql = "CREATE TABLE IF NOT EXISTS %s (key TEXT NOT NULL UNIQUE, value TEXT);" % self._table_name
#         self._conn.execute(sql)

#     def get(self, key):
#         cur = self._conn.execute("SELECT * FROM %s WHERE key = '%s'" % (self._table_name, key))
#         rv = cur.fetchone()
#         if rv is None:
#             return None
#         return rv[1].encode('utf8')

#     def set(self, key, value):
#         assert isinstance(value, str)
#         if self.get(key):
#             sql = "UPDATE %s SET value = '%s' WHERE key = '%s'" % (self._table_name, value, key)
#         else:
#             sql = "INSERT INTO %s VALUES ('%s', '%s')" % (self._table_name, key, value)
#         self._conn.execute(sql)
#         self._conn.commit()

#     def delete(self, key):
#         if self.get(key):
#             sql = "DELETE FROM %s WHERE key = '%s'" % (self._table_name, key)
#         self._conn.execute(sql)
#         self._conn.commit()

#     def keys(self):
#         cur = self._conn.execute("SELECT key from %s" % self._table_name)
#         for i in cur:
#             yield i[0].encode('utf8')

#     def close(self):
#         self._conn.close()

try:
    import cPickle as pickle
except ImportError:
    import pickle

from functools import partial

class LiteKV(object):

    def __init__(self, filename='tmp.sqlite', table=0, reset=False, rowid=True):
        self._conn = sqlite3.connect(filename)
        self._table_name = "__litekv_db_%s" % table

        if reset:
            self._conn.execute("DROP TABLE IF EXISTS %s" % self._table_name)

        if (not rowid) and CAN_USE_WITHOUT_ROWID:
            sql = "CREATE TABLE IF NOT EXISTS %s (key TEXT PRIMARY KEY, value BLOB) WITHOUT ROWID;" % self._table_name
        else:
            if not rowid:
                print 'Warning: as sqlite version is %s smaller than 3.8, WITHOUT ROWID can not be used, argument `rowid` will not affect' % sqlite3.sqlite_version
            sql = "CREATE TABLE IF NOT EXISTS %s (key TEXT NOT NULL UNIQUE, value BLOB);" % self._table_name
        self._conn.execute(sql)

    def get(self, key):
        cur = self._conn.execute("SELECT * FROM %s WHERE key = '%s'" % (self._table_name, key))
        rv = cur.fetchone()
        if rv is None:
            return None
        return str(rv[1])

    def set(self, key, value):
        assert isinstance(value, str)
        if self.get(key):
            self._conn.execute(("UPDATE %s SET value = ? WHERE key = ?" % self._table_name), \
                                    (buffer(value), key))
        else:
            self._conn.execute(("INSERT INTO %s VALUES (?, ?)" % self._table_name), \
                            (key, buffer(value)))
        self._conn.commit()

    def delete(self, key):
        if self.get(key):
            sql = "DELETE FROM %s WHERE key = '%s'" % (self._table_name, key)
            self._conn.execute(sql)
            self._conn.commit()


    def iter_keys(self):
        cur = self._conn.execute("SELECT key from %s" % self._table_name)
        for i in cur:
            yield i[0].encode('utf8')

    def keys(self):
        return list(self.iter_keys())

    def close(self):
        self._conn.close()


class ALiteKV(LiteKV):
    dumps = partial(pickle.dumps, protocol=pickle.HIGHEST_PROTOCOL)
    loads = pickle.loads

    def get(self, key):
        rv = super(ALiteKV, self).get(key)
        if rv is not None:
            rv = self.loads(rv)
        return rv

    def set(self, key, value):
        value = self.dumps(value)
        super(ALiteKV, self).set(key, value)

    def pop(self, key):
        v = self.get(key)
        self.delete(key)
        return v


if __name__ == '__main__':
    import os
    import sys
    import time
    import doctest

    # Doctest
    doctest.testmod()

    if len(sys.argv) < 2 or sys.argv[1] != '--benchmark':
        sys.exit()

    # Benchmark
    def clear_db_file():
        filename = 'tmp.sqlite'
        if os.path.exists(filename):
            os.remove(filename)

    def benchmark(db):
        s = '.' * 1 * 1024
        count = 10000
        t1 = time.time()

        print 'Do %s inserts & reads' % count

        for i in xrange(count):
            db.set(str(i), s)

        print count / (time.time() - t1), 'Insertion per second'

        t1 = time.time()
        for i in xrange(count):
            db.get(str(i))

        print count / (time.time() - t1), 'Reads per second'

    print 'With rowid'
    clear_db_file()
    db = LiteKV(reset=True, rowid=True)
    benchmark(db)
    db.close()

    print '\nWithout rowid'
    clear_db_file()
    db = LiteKV(reset=True, rowid=False)
    benchmark(db)
    db.close()

    clear_db_file()
