import typing

from interface import Interface

from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding


class PublicKey(Interface):

    def serialize(self) -> bytes: pass

    @property
    def key_size(self) -> int: pass

    def encrypt(self, plaintext: bytes,
                padding: AsymmetricPadding) -> bytes: pass


class PrivateKey(Interface):

    @property
    def public_key(self) -> PublicKey: pass

    def decrypt(self, ciphertext: bytes,
                padding: AsymmetricPadding) -> bytes: pass

    def serialize(self, password: str) -> bytes: pass

    @property
    def key_size(self) -> int: pass

    @property
    def underlying_key(self): pass


class KeyMinter(Interface):

    def mint(self, **kwargs) -> PrivateKey: pass


class KeyStore(Interface):

    def initialise(self, **kwargs):
        pass

    def add(self, key: PrivateKey, key_name: str, password: str):
        pass

    def exists(self, key_name: str) -> bool:
        pass

    def get(self, key_name: str, password: str = None) -> PrivateKey:
        pass

    def remove(self, key_name: str):
        pass

    def list(self) -> typing.List[str]:
        pass
