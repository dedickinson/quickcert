import typing
import datetime

from interface import Interface

from .key import PublicKey, PrivateKey


class CertificateType(Interface):

    @property
    def name(self) -> str:
        pass

    @property
    def extensions(self) -> typing.List[int]:
        pass


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

    def mint(self, properties: typing.Dict) -> Certificate: pass


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
