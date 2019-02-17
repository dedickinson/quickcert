from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.x509.oid import NameOID
from interface import implements

from .interfaces import (CertificateMinter, CertificateNameAttributes,
                         PrivateKey)
from .structures import CertificateType

_CERTIFICATE_TYPE_ROOT = 'root'
_CERTIFICATE_TYPE_INTERMEDIATE = 'intermediate'
_CERTIFICATE_TYPE_SERVER = 'server'
_CERTIFICATE_TYPE_CLIENT = 'client'


class x509RootCertificateType(implements(CertificateType)):

    name = _CERTIFICATE_TYPE_ROOT

    extensions = [
        x509.BasicConstraints(
            ca=True,
            path_length=None)]


class x509IntermediateCertificateType(implements(CertificateType)):

    name = _CERTIFICATE_TYPE_INTERMEDIATE

    extensions = []


class x509ServerCertificateType(implements(CertificateType)):

    name = _CERTIFICATE_TYPE_SERVER

    extensions = [
        x509.BasicConstraints(
            ca=False,
            path_length=None)]


class x509ClientCertificateType(implements(CertificateType)):

    name = _CERTIFICATE_TYPE_CLIENT

    extensions = []


X509_CERTIFICATE_TYPES = {
    _CERTIFICATE_TYPE_ROOT: x509RootCertificateType(),
    _CERTIFICATE_TYPE_INTERMEDIATE: x509IntermediateCertificateType(),
    _CERTIFICATE_TYPE_SERVER: x509ServerCertificateType(),
    _CERTIFICATE_TYPE_CLIENT: x509ClientCertificateType()
}


class x509CertificateNameAttributes(implements(CertificateNameAttributes)):

    def __init__(self,
                 country_name: str = '',
                 state_name: str = '',
                 locality_name: str = '',
                 organization_name: str = '',
                 common_name: str = ''):

        self._country_name = country_name
        self._state_name = state_name
        self._locality_name = locality_name
        self._organization_name = organization_name
        self._common_name = common_name

    @property
    def certificate_attributes(self) -> x509.Name:
        return x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)
        ])

    @property
    def country(self) -> str:
        return self._country_name

    @property
    def state(self) -> str:
        return self._state_name

    @property
    def locality(self) -> str:
        return self._locality_name

    @property
    def organization(self) -> str:
        return self._organization_name

    @property
    def common_name(self) -> str:
        return self._common_name


class x509CertificateMinter(implements(CertificateMinter)):

    _DEFAULT_HASH_ALGORITHM = SHA256()

    def __init__(self,
                 certificate_type: CertificateType,
                 private_key: PrivateKey,
                 subject: x509CertificateNameAttributes,
                 issuer: x509CertificateNameAttributes,
                 hash_algorithm: HashAlgorithm = x509CertificateMinter._DEFAULT_HASH_ALGORITHM,
                 duration_days: int = 360):

        self.key = private_key
        self.subject = subject
        self.issuer = issuer
        self.duration_days = duration_days
        self.certificate_type = certificate_type
        self.hash_algorithm = hash_algorithm

    def mint(self):

        one_day = datetime.timedelta(1, 0, 0)

        builder = x509.CertificateBuilder(
        ).not_valid_before(
            datetime.datetime.today() - one_day
        ).not_valid_after(
            datetime.datetime.today() + (one_day * self.duration_days)
        ).serial_number(
            x509.random_serial_number()
        ).public_key(
            self.key.public_key()
        ).subject_name(
            self.subject.certificate_attributes
        ).issuer_name(
            self.issuer.certificate_attributes
        )

        for extension in self.certificate_type.get_extensions():
            builder = builder.add_extension(
                extension, critical=True)

        return builder.sign(
            private_key=self.key,
            algorithm=self.hash_algorithm,
            backend=default_backend()
        )
