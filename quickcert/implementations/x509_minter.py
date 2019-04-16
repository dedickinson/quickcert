import typing
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from interface import implements

from ..interfaces import (Certificate, CertificateMinter,
                          CertificateNameAttributes, PrivateKey, PublicKey)
from .structures import CertificateType

DEFAULT_HASH_ALGORITHM = SHA256()

CERTIFICATE_TYPE_ROOT_NAME = 'root'
CERTIFICATE_TYPE_INTERMEDIATE_NAME = 'intermediate'
CERTIFICATE_TYPE_SERVER_NAME = 'server'
CERTIFICATE_TYPE_CLIENT_NAME = 'client'


class x509AbstractCertificateType(implements(CertificateType)):
    def __init__(self, name: str, extensions: typing.List):
        self._name = name
        self._extensions = extensions

    @property
    def name(self) -> str:
        return self._name

    @property
    def extensions(self) -> typing.List:
        return self._extensions


class x509RootCertificateType(x509AbstractCertificateType):

    def __init__(self):
        super().__init__(
            name=CERTIFICATE_TYPE_ROOT_NAME,
            extensions=[
                x509.BasicConstraints(
                    ca=True,
                    path_length=None)]
        )


class x509IntermediateCertificateType(x509AbstractCertificateType):
    def __init__(self):
        super().__init__(
            name=CERTIFICATE_TYPE_INTERMEDIATE_NAME,
            extensions=[]
        )


class x509ServerCertificateType(x509AbstractCertificateType):

    def __init__(self):
        super().__init__(
            name=CERTIFICATE_TYPE_SERVER_NAME,
            extensions=[
                x509.BasicConstraints(
                    ca=False,
                    path_length=None)]
        )


class x509ClientCertificateType(x509AbstractCertificateType):
    def __init__(self):
        super().__init__(
            name=CERTIFICATE_TYPE_CLIENT_NAME,
            extensions=[]
        )


X509_CERTIFICATE_TYPES = {
    CERTIFICATE_TYPE_ROOT_NAME: x509RootCertificateType(),
    CERTIFICATE_TYPE_INTERMEDIATE_NAME: x509IntermediateCertificateType(),
    CERTIFICATE_TYPE_SERVER_NAME: x509ServerCertificateType(),
    CERTIFICATE_TYPE_CLIENT_NAME: x509ClientCertificateType()
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


class x509SigningRequest():
    def create(self, subject: x509CertificateNameAttributes,
               private_key: PrivateKey,
               hash_algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM):

        return x509.CertificateSigningRequestBuilder().subject_name(
            name=subject.certificate_attributes
        ).sign(
            private_key=private_key,
            algorithm=hash_algorithm,
            backend=default_backend()
        )


class x509Certificate(implements(Certificate)):

    def __init__(self, certificate: x509.Certificate):
        self._certificate = certificate
        self._issuer_attributes = None
        self._subject_attributes = None

    @property
    def serial_number(self) -> int:
        return self._certificate.serial_number

    @property
    def version(self) -> str:
        if self._certificate == x509.Version.v1:
            return '1'
        elif self._certificate == x509.Version.v3:
            return '3'
        else:
            return 'unknown'

    @property
    def not_valid_before(self) -> datetime:
        return self._certificate.not_valid_before

    @property
    def not_valid_after(self) -> datetime:
        return self._certificate.not_valid_after

    @property
    def public_key(self) -> PublicKey:
        return self._certificate.public_key()

    @property
    def issuer(self) -> CertificateNameAttributes:

        if self._issuer_attributes == None:

            self._issuer_attributes = x509CertificateNameAttributes(
                country_name=self._certificate.issuer.get_attributes_for_oid(
                    NameOID.COUNTRY_NAME)[0].value,
                state_name=self._certificate.issuer.get_attributes_for_oid(
                    NameOID.STATE_OR_PROVINCE_NAME)[0].value,
                locality_name=self._certificate.issuer.get_attributes_for_oid(
                    NameOID.LOCALITY_NAME)[0].value,
                organization_name=self._certificate.issuer.get_attributes_for_oid(
                    NameOID.ORGANIZATION_NAME)[0].value,
                common_name=self._certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[
                    0].value
            )

        return self._issuer_attributes

    @property
    def subject(self) -> CertificateNameAttributes:
        if self._subject_attributes == None:

            self._subject_attributes = x509CertificateNameAttributes(
                country_name=self._certificate.subject.get_attributes_for_oid(
                    NameOID.COUNTRY_NAME)[0].value,
                state_name=self._certificate.subject.get_attributes_for_oid(
                    NameOID.STATE_OR_PROVINCE_NAME)[0].value,
                locality_name=self._certificate.subject.get_attributes_for_oid(
                    NameOID.LOCALITY_NAME)[0].value,
                organization_name=self._certificate.subject.get_attributes_for_oid(
                    NameOID.ORGANIZATION_NAME)[0].value,
                common_name=self._certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[
                    0].value
            )

        return self._subject_attributes

    @property
    def extensions(self): pass

    @property
    def public_bytes(self, encoding=Encoding.PEM) -> bytes:
        return self._certificate.public_bytes()


class x509CertificateMinter(implements(CertificateMinter)):

    def prepare_mint_args(self,
                          certificate_type: x509AbstractCertificateType,
                          private_key: PrivateKey,
                          subject: x509CertificateNameAttributes,
                          issuer: x509CertificateNameAttributes,
                          hash_algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
                          duration_days: int = 360):

        return {
            'certificate_type': certificate_type,
            'private_key': private_key,
            'subject': subject,
            'issuer': issuer,
            'hash_algorithm': hash_algorithm,
            'duration_days': duration_days
        }

    def mint(self,
             **kwargs) -> Certificate:

        # TODO: Handle CSR

        certificate_type = kwargs.get('certificate_type')
        private_key = kwargs.get('private_key')
        subject = kwargs.get('subject')
        issuer = kwargs.get('issuer')
        hash_algorithm = kwargs.get('hash_algorithm', DEFAULT_HASH_ALGORITHM)
        duration_days = kwargs.get('duration_days', 360)

        one_day = timedelta(days=1)

        builder = x509.CertificateBuilder(
        ).not_valid_before(
            datetime.today() - one_day
        ).not_valid_after(
            datetime.today() + (one_day * duration_days)
        ).serial_number(
            x509.random_serial_number()
        ).public_key(
            private_key.public_key()
        ).subject_name(
            subject.certificate_attributes
        ).issuer_name(
            issuer.certificate_attributes
        )

        for extension in certificate_type.extensions:
            builder = builder.add_extension(
                extension, critical=True)

        return x509Certificate(
            builder.sign(
                private_key=private_key,
                algorithm=hash_algorithm,
                backend=default_backend()
            ))
