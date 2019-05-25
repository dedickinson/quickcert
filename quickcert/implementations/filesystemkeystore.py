import os
from pathlib import Path
from interface import implements
import typing

from ..interfaces import (PrivateKey,
                          PublicKey,
                          KeyStore)

from .rsa_minter import RsaPrivateKey


class FilesystemKeyStore(implements(KeyStore)):

    _BASE_DIR = 'keystore'

    def initialise(self, **kwargs):

        self.dir_mode: int = 0o700
        self.file_mode: int = 0o400

        if 'dir' in kwargs:
            self.dir = Path(kwargs.get('dir'), FilesystemKeyStore._BASE_DIR)
        else:
            raise ValueError("Expected a dir parameter")

        # TODO: Log this
        self.dir.mkdir(mode=self.dir_mode, exist_ok=True)

    def _key_path(self, key_name: str) -> Path:
        return Path(self.dir, "{}.key".format(key_name))

    def _public_key_path(self, key_name: str) -> Path:
        return Path(self.dir, "{}.pub".format(key_name))

    def add(self, key: PrivateKey, key_name: str, password: str):
        if self.exists(key_name):
            raise ValueError("The key {} already exists".format(key_name))

        with open(os.open(self._key_path(key_name), flags=os.O_CREAT | os.O_WRONLY, mode=self.file_mode), "wb") as key_file:
            key_file.write(key.serialize(password))

        # with open(os.open(self._public_key_path(key_name), flags=os.O_CREAT | os.O_WRONLY, mode=0o444), "wb") as key_file:
        #    key_file.write(key.public_key.serialize())

    def exists(self, key_name: str) -> bool:
        if self._key_path(key_name).exists():
            return True

        return False

    def get(self, key_name: str, password: str = None) -> PrivateKey:
        if not self.exists(key_name):
            return None

        return RsaPrivateKey.deserialize(self._key_path(key_name), password)

    def remove(self, key_name: str):
        if self.exists(key_name):
            self._key_path(key_name).unlink()
            # self._public_key_path(key_name).unlink()

    def list(self) -> typing.List[str]:
        return [
            os.path.splitext(
                key.name)[0] for key in os.scandir(
                self.dir) if os.path.isfile(key) and os.path.splitext(
                key.name)[1] == '.key']
