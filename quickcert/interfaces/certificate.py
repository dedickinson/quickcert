import typing
import datetime

from interface import Interface

from .key import PublicKey, PrivateKey
from .util import Tree


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
    def version(self) -> str: pass

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

    def public_bytes(self, encoding=None) -> bytes: pass


class CertificateMinter(Interface):

    def mint(self, **kwargs) -> Certificate: pass


class CertificateDetails(Interface):
    @property
    def name(self) -> str: pass

    @property
    def issuer(self) -> 'CertificateDetails': pass

    @property
    def certificate_type(self) -> CertificateType:
        pass


class CertificateStoreEntry(Interface):

    @property
    def certificate(self) -> Certificate:
        pass

    @property
    def details(self) -> CertificateDetails:
        pass


class CertificateStore(Interface):

    def initialise(self, **kwargs):
        pass

    def list(self) -> Tree:
        pass

    def get(self, entry: CertificateStoreEntry) -> CertificateStoreEntry:
        pass

    def exists(self, details: CertificateDetails) -> bool:
        pass

    def add(self, entry: CertificateStoreEntry):
        pass

    def remove(self, entry: CertificateStoreEntry):
        pass
