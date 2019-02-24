import typing

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from interface import implements

from ..interfaces import KeyMinter, PrivateKey

CONST_DEFAULT_KEY_SIZE: int = 2048
CONST_DEFAULT_KEY_PUBLIC_EXPONENT: int = 65537
CONST_DEFAULT_ENCRYPTION_PADDING = padding.OAEP(
    mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
CONST_DEFAULT_SIGNING_PADDING = padding.PSS(
    mgf=padding.MGF1, salt_length=padding.PSS.MAX_LENGTH)


class RsaKeyMinter(implements(KeyMinter)):

    def prepare_mint_args(self,
                          key_size: int = CONST_DEFAULT_KEY_SIZE,
                          key_public_exponent=CONST_DEFAULT_KEY_PUBLIC_EXPONENT):
        return {
            'key_size': key_size,
            'key_public_exponent': key_public_exponent
        }

    def mint(self,
             **kwargs) -> PrivateKey:

        key_public_exponent = kwargs.get(
            'key_public_exponent', CONST_DEFAULT_KEY_PUBLIC_EXPONENT)
        key_size = kwargs.get('key_size', CONST_DEFAULT_KEY_SIZE)

        return rsa.generate_private_key(
            public_exponent=key_public_exponent,
            key_size=key_size,
            backend=default_backend()
        )
