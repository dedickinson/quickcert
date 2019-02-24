import typing

from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm

from .implementations.rsa_minter import RsaKeyMinter
from .implementations.structures import CertificateStoreEntryImpl
from .implementations.x509_minter import (x509CertificateMinter,
                                          x509CertificateNameAttributes)
from .interfaces import (Certificate, CertificateMinter, CertificateStore,
                         CertificateStoreEntry, CertificateType, KeyMinter,
                         KeyStore, PrivateKey)


class X509CertificateManager:

    def __init__(self,
                 certificate_store: CertificateStore,
                 key_store: KeyStore,
                 certificate_minter: CertificateMinter,
                 key_minter: KeyMinter):

        self._certificate_store = certificate_store
        self._key_store = key_store
        self._key_minter = key_minter
        self._certificate_minter = certificate_minter

    def create_key(self,
                   key_size: int = RsaKeyMinter.CONST_DEFAULT_KEY_SIZE,
                   key_public_exponent: int = RsaKeyMinter._CONST_KEY_PUBLIC_EXPONENT) -> PrivateKey:

        return self._key_minter.mint(properties={
            'key_size':  key_size,
            'key_public_exponent': key_public_exponent
        })

"""     def store_key(self, private_key: PrivateKey, key_path: str, key_name: str):
        self._key_store.add(
            key=private_key,
            key_path=key_path,
            key_name=key_name)

    def create_certificate(self,
                           certificate_type: CertificateType,
                           certificate_name: str,
                           private_key: PrivateKey,
                           subject: x509CertificateNameAttributes,
                           issuer: x509CertificateNameAttributes,
                           hash_algorithm: HashAlgorithm = x509CertificateMinter._DEFAULT_HASH_ALGORITHM,
                           duration_days: int = 360) -> CertificateStoreEntry:

        self._certificate_minter.mint(properties={
            'certificate_type': certificate_type,
            'private_key': private_key,
            'subject': subject,
            'issuer': issuer,
            'hash_algorithm': hash_algorithm,
            'duration_days': duration_days
        })

        return CertificateStoreEntryImpl(name=certificate_name,
                                         certificate_type=certificate_type)

    def store_certificate(self, certificate_entry: CertificateStoreEntry):
        pass """
