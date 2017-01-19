import os

# from websockify.token_plugins import BasePlugin

# class ReadOnlyCredentialFile(BasePlugin):
#     """
#         Inspired by websockify.token_plugins.ReadOnlyTokenFile
#     """
#     def __init__(self, *args, **kwargs):
#         super(ReadOnlyCredentialFile, self).__init__(*args, **kwargs)
#         self._targets = None

#     def _load_targets(self):
#         if os.path.isdir(self.source):
#             cfg_files = [os.path.join(self.source, f) for
#                          f in os.listdir(self.source)]
#         else:
#             cfg_files = [self.source]

#         self._targets = {}
#         for f in cfg_files:
#             for line in [l.strip() for l in open(f).readlines()]:
#                 if line and not line.startswith('#'):
#                     line = line.replace(' ', '')     # remove spaces
#                     tok, password = line.split(':', 1)
#                     self._targets[tok] = password

#     def lookup(self, token):
#         if self._targets is None:
#             self._load_targets()

#         if token in self._targets:
#             return self._targets[token]
#         else:
#             return None


# class CredentialFile(ReadOnlyCredentialFile):
#     """
#         Inspired by websockify.token_plugins.TokenFile
#     """
#     def lookup(self, token):
#         self._load_targets()

#         return super(CredentialFile, self).lookup(token)


class ConfigFile(object):
    """
        Interface to access config file.
        Config file format:
        key: value
        only string is acceptable.
        compatible with websockify token plugin
    """

    def __init__(self, path, realtime=True):
        """
            path: path to config file.
            realtime: if true, reload every time.
        """
        self.cfg_file_path = path
        self.realtime = realtime
        self._cfg = {}
        self.load()

    def load(self, path=None):
        """
            load config
        """
        if path:
            self.cfg_file_path = path

        if not os.path.isfile(self.cfg_file_path):
            open(self.cfg_file_path, 'a').close()

        self._cfg = {}
        with open(self.cfg_file_path, 'r') as f:
            lines = f.readlines()
            for l in lines:
                l = l.strip()
                if l and not l.startswith('#'):
                    key, val = l.split(':', 1)
                    self._cfg[key.strip()] = val.strip()

    def save(self, path=None):
        """
            save config content to config file.
        """
        if path:
            self.cfg_file_path = path

        lines = ['%s: %s\n' % (key, val) for key, val in self._cfg.iteritems()]
        with open(self.cfg_file_path, 'w') as f:
            f.writelines(lines)


    def get(self, key, alt=None):
        if (not self._cfg) or self.realtime:
            self.load()
        return self._cfg.get(key, alt)

    def set(self, key, val):
        self._cfg[key] = str(val)
        if self.realtime:
            self.save()

    def delete(self, key):
        del self._cfg[key]
        if self.realtime:
            self.save()

    def __getitem__(self, key):
        r = self.get(key)
        if r is None:
            raise KeyError, "%r" % key
        return r

    def __setitem__(self, key, val):
        self.set(key, val)

    def __delitem__(self, key):
        self.delete(key)

    def __contains__(self, key):
        return self.get(key, None) is not None

    def lookup(self, key):
        """
            When used as a token plugin for websockify,
            this method will be called.
        """
        return self.get(key, None)


class TokenFile(ConfigFile):
    def lookup(self, token):
        target = super(TokenFile, self).lookup(token)
        host, port = target.rsplit(':', 1)
        return (host, port)

