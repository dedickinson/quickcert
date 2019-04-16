from pathlib import Path
from interface import implements


from ..interfaces import (PrivateKey,
                          PublicKey,
                          KeyStore)


class FilesystemKeyStore(implements(KeyStore)):

    _BASE_DIR = 'keystore'

    def initialise(self, **kwargs):
        pass

    def add(self, key: PrivateKey, key_path: str, key_name: str, password: str):
        pass

    def get(self, key_path: str, key_name: str) -> str:
        pass

    def remove(self, key_path: str, key_name: str):
        pass
