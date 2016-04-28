# -*- coding:utf-8 -*-

"""
    copied from flask>._compat
"""
import sys

PY2 = sys.version_info[0] == 2

if not PY2:
    integer_types = (int, )

    def reraise(tp, value, tb=None):
        if value.__traceback__ is not tb:
            raise value.with_traceback(tb)
        raise value
else:
    integer_types = (int, long)

    exec('def reraise(tp, value, tb=None):\n raise tp, value, tb')
