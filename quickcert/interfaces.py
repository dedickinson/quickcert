import typing
import datetime

from interface import Interface


class CertificateType(Interface):

    @property
    def name(self) -> str:
        pass

    @property
    def extensions(self) -> typing.List[int]:
        pass


class PublicKey(Interface):

    @property
    def public_bytes(self, encoding, format): pass


class PrivateKey(Interface):

    @property
    def public_key(self) -> PublicKey: pass

    @property
    def private_bytes(self, encoding, format, encryption_algorithm): pass


class CertificateNameAttributes(Interface):

    @property
    def country(self) -> str: pass

    @property
    def state(self) -> str: pass

    @property
    def locality(self) -> str: pass

    @property
    def organization(self) -> str: pass

    @property
    def common_name(self) -> str: pass


class Certificate(Interface):

    @property
    def serial_number(self) -> int: pass

    @property
    def not_valid_before(self) -> datetime: pass

    @property
    def not_valid_after(self) -> datetime: pass

    @property
    def public_key(self) -> PublicKey: pass

    @property
    def issuer(self) -> CertificateNameAttributes: pass

    @property
    def subject(self) -> CertificateNameAttributes: pass

    @property
    def extensions(self): pass

    @property
    def public_bytes(self, encoding) -> bytes: pass


class CertificateMinter(Interface):

    def mint(self) -> Certificate: pass


class KeyMinter(Interface):

    def mint(self) -> PrivateKey: pass


class CertificateStoreEntry(Interface):

    @property
    def name(self) -> str:
        pass

    @property
    def certificate(self) -> Certificate:
        pass

    @property
    def private_key(self) -> PrivateKey:
        pass

    @property
    def public_key(self) -> PublicKey:
        pass

    @property
    def certificate_type(self) -> CertificateType:
        pass


class CertificateStore(Interface):

    def list(self, certificate_type: CertificateType) -> typing.List[str]:
        pass

    def get(self, certificate_type: CertificateType, certificate_name: str) -> CertificateStoreEntry:
        pass

    def exists(self, certificate_type: CertificateType, certificate_name: str) -> bool:
        pass

    def add(self, entry: CertificateStoreEntry):
        pass

    def remove(self, certificate_type: CertificateType, certificate_name: str):
        pass

    def initialise(self):
        pass


class CertificateStoreShadow(Interface):
    """
    Stores the passwords used by keys
    """

    def initialise(self):
        """Setup the shadow store
        """

        pass

    def add(self, certificate_type: CertificateType, certificate_name: str, password: str):
        """Add a password for the designated type/name

        Arguments:
            certificate_type {CertificateType} -- [description]
            certificate_name {str} -- [description]
            password {str} -- [description]
        """

        pass

    def get(self, certificate_type: CertificateType, certificate_name: str) -> str:
        """Get the key file password for the designated type/name

        Arguments:
            certificate_type {CertificateType} -- [description]
            certificate_name {str} -- [description]

        Returns:
            str -- the password
        """

        pass

    def remove(self, certificate_type: CertificateType, certificate_name: str):
        """Remove the key file password for the designated type/name

        Arguments:
            certificate_type {CertificateType} -- [description]
            certificate_name {str} -- [description]
        """

        pass
