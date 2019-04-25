from interface import Interface

from .certificate import (Certificate, CertificateMinter,
                          CertificateNameAttributes, CertificateStore,
                          CertificateStoreEntry, CertificateType,
                          CertificateDetails)

from .key import KeyMinter, KeyStore, PrivateKey, PublicKey

from .util import Tree


class PasswordValidator(Interface):
    def validate(self, password: str) -> bool: pass

class PasswordGenerator(Interface):
    def generate_password(self, length: int = 32,
                          selection: str = '',
                          validator: PasswordValidator = None) -> str: pass
