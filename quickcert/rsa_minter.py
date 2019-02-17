from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from interface import implements

from .interfaces import KeyMinter, PrivateKey


class RsaKeyConfig:

    _CONST_DEFAULT_KEY_SIZE: int = 2048
    _CONST_KEY_PUBLIC_EXPONENT: int = 65537

    def __init__(self,
                 key_size: int = RsaKeyConfig._CONST_DEFAULT_KEY_SIZE,
                 key_public_exponent: int = RsaKeyConfig._CONST_KEY_PUBLIC_EXPONENT):

        self._key_size = key_size
        self._key_public_exponent = key_public_exponent

    @property
    def key_size(self):
        return self._key_size

    @property
    def key_public_exponent(self):
        return self._key_public_exponent


class RsaKeyMinter(implements(KeyMinter), KeyMinter):

    def __init__(self, config: RsaKeyConfig):
        self.config = config

    def mint(self) -> PrivateKey:
        return rsa.generate_private_key(
            public_exponent=self.config.key_public_exponent,
            key_size=self.config.key_size,
            backend=default_backend()
        )
