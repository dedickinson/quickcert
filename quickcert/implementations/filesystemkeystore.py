import os
from pathlib import Path
from interface import implements


from ..interfaces import (PrivateKey,
                          PublicKey,
                          KeyStore)


class FilesystemKeyStore(implements(KeyStore)):

    _BASE_DIR = 'keystore'

    def initialise(self, **kwargs):
        if 'dir' in kwargs:
            self.dir = Path(kwargs.get('dir'), FilesystemKeyStore._BASE_DIR)
        else:
            raise ValueError("Expected a dir parameter")

        # TODO: Log this
        self.dir.mkdir(mode=0o700, exist_ok=True)

    def _key_path(self, key_name: str) -> Path:
        return Path(self.dir, key_name)

    def _public_key_path(self, key_name: str) -> Path:
        return Path(self.dir, "{}.pub".format(key_name))

    def add(self, key: PrivateKey, key_name: str, password: str):
        with open(os.open(self._key_path(key_name), flags=os.O_CREAT | os.O_WRONLY, mode=0o400), "wb") as key_file:
            key_file.write(key.serialize(password))

        with open(os.open(self._public_key_path(key_name), flags=os.O_CREAT | os.O_WRONLY, mode=0o444), "wb") as key_file:
            key_file.write(key.public_key.serialize())

    def exists(self, key_name:str) -> bool:
        if self._key_path(key_name).exists() or self._public_key_path(key_name).exists():
            return True

        return False
    
    def get(self, key_name: str) -> PrivateKey:
        pass

    def remove(self, key_name: str):
        pass
