from cryptography import x509
from interface import implements

from ..interfaces import (Certificate, CertificateStoreEntry, CertificateType,
                         PrivateKey, PublicKey)


class CertificateStoreEntryImpl(implements(CertificateStoreEntry)):

    def __init__(self, 
                 name: str,
                 certificate_type: CertificateType,
                 certificate: Certificate,
                 key: PrivateKey):

        self._name = name
        self._certificate_type = certificate_type
        self._certificate = certificate
        self._key = key

    @property
    def name(self) -> str:
        return self._name

    @property
    def certificate(self) -> Certificate:
        return self._certificate

    @property
    def private_key(self) -> PrivateKey:
        return self._key

    @property
    def public_key(self) -> PublicKey:
        return self._key.public_key()

    @property
    def certificate_type(self) -> CertificateType:
        return self._certificate_type
