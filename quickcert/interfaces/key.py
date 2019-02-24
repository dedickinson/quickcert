import typing

from interface import Interface

from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding


class PublicKey(Interface):

    @property
    def public_bytes(self, encoding, format): pass

    @property
    def key_size(self) -> int: pass

    def encrypt(self, plaintext: bytes,
                padding: AsymmetricPadding) -> bytes: pass


class PrivateKey(Interface):

    def public_key(self) -> PublicKey: pass

    def decrypt(self, ciphertext: bytes,
                padding: AsymmetricPadding) -> bytes: pass

    @property
    def private_bytes(self, encoding, format, encryption_algorithm): pass

    @property
    def key_size(self) -> int: pass


class KeyMinter(Interface):

    def mint(self, **kwargs) -> PrivateKey: pass


class KeyStore(Interface):

    def initialise(self):
        pass

    def add(self, key: PrivateKey, key_path: str, key_name: str, password: str):
        pass

    def get(self, key_path: str, key_name: str) -> str:
        pass

    def remove(self, key_path: str, key_name: str):
        pass
