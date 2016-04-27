import os

from websockify.token_plugins import BasePlugin

class ReadOnlyCredentialFile(BasePlugin):
    """
        Inspired by websockify.token_plugins.ReadOnlyTokenFile
    """
    def __init__(self, *args, **kwargs):
        super(ReadOnlyCredentialFile, self).__init__(*args, **kwargs)
        self._targets = None

    def _load_targets(self):
        if os.path.isdir(self.source):
            cfg_files = [os.path.join(self.source, f) for
                         f in os.listdir(self.source)]
        else:
            cfg_files = [self.source]

        self._targets = {}
        for f in cfg_files:
            for line in [l.strip() for l in open(f).readlines()]:
                if line and not line.startswith('#'):
                    line = line.replace(' ', '')     # remove spaces
                    tok, password = line.split(':', 1)
                    self._targets[tok] = password

    def lookup(self, token):
        if self._targets is None:
            self._load_targets()

        if token in self._targets:
            return self._targets[token]
        else:
            return None


class CredentialFile(ReadOnlyCredentialFile):
    """
        Inspired by websockify.token_plugins.TokenFile
    """
    def lookup(self, token):
        self._load_targets()

        return super(CredentialFile, self).lookup(token)
