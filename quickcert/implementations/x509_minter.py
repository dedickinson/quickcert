import typing
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256, HashAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from interface import implements

from ..interfaces import (Certificate, CertificateMinter, CertificateType,
                          CertificateNameAttributes, PrivateKey, PublicKey)


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
                    path_length=1)]
        )


class x509IntermediateCertificateType(x509AbstractCertificateType):
    def __init__(self):
        super().__init__(
            name=CERTIFICATE_TYPE_INTERMEDIATE_NAME,
            extensions=[
                x509.BasicConstraints(
                    ca=True,
                    path_length=0)
            ]
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
            extensions=[
                x509.BasicConstraints(
                    ca=False,
                    path_length=None)
            ]
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

    @staticmethod
    def extract_attributes(
            certificate: 'x509Certificate') -> typing.Tuple[CertificateNameAttributes, CertificateNameAttributes]:
        def list_get(l, i=0, default=None):
            try:
                return l[i].value
            except IndexError:
                return default

        def get_attributes(element):
            return x509CertificateNameAttributes(
                country_name=list_get(element.get_attributes_for_oid(
                    NameOID.COUNTRY_NAME)),
                state_name=list_get(element.get_attributes_for_oid(
                    NameOID.STATE_OR_PROVINCE_NAME)),
                locality_name=list_get(element.get_attributes_for_oid(
                    NameOID.LOCALITY_NAME)),
                organization_name=list_get(element.get_attributes_for_oid(
                    NameOID.ORGANIZATION_NAME)),
                common_name=list_get(element.get_attributes_for_oid(
                    NameOID.COMMON_NAME))
            )

        issuer_attributes = get_attributes(certificate.issuer)
        subject_attributes = get_attributes(certificate.subject)

        return (issuer_attributes, subject_attributes)

    @property
    def certificate_attributes(self) -> x509.Name:
        attributes = []

        if self.country:
            attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME,
                                                 self.country))

        if self.state:
            attributes.append(x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, self.state))

        if self.locality:
            attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME,
                                                 self.locality))

        if self.organization:
            attributes.append(x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, self.organization))

        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME,
                                             value=self.common_name))

        return x509.Name(attributes)

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
    @staticmethod
    def generate(subject: x509CertificateNameAttributes,
                 private_key: PrivateKey,
                 hash_algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM):

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject.certificate_attributes
        )

        return csr.sign(
            private_key=private_key.underlying_key,
            algorithm=hash_algorithm,
            backend=default_backend()
        )


class x509Certificate(implements(Certificate)):

    def __init__(self, certificate: x509.Certificate):
        self._certificate = certificate
        self._issuer_attributes, self._subject_attributes = x509CertificateNameAttributes.extract_attributes(
            certificate)

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
        return self._issuer_attributes

    @property
    def subject(self) -> CertificateNameAttributes:
        return self._subject_attributes

    @property
    def extensions(self): pass

    def public_bytes(self, encoding=Encoding.PEM) -> bytes:
        return self._certificate.public_bytes(encoding)


class x509CertificateMinter(implements(CertificateMinter)):

    @staticmethod
    def prepare_mint_args(
            certificate_type: x509AbstractCertificateType,
            issuer_key: PrivateKey,
            issuer: x509CertificateNameAttributes,
            csr=None,
            hash_algorithm: HashAlgorithm = DEFAULT_HASH_ALGORITHM,
            duration_days: int = 365):

        return {
            'certificate_type': certificate_type,
            'issuer_key': issuer_key,
            'issuer': issuer,
            'csr': csr,
            'hash_algorithm': hash_algorithm,
            'duration_days': duration_days
        }

    def mint(self,
             **kwargs) -> Certificate:

        certificate_type = kwargs.get('certificate_type')
        issuer_key: PrivateKey = kwargs.get('issuer_key')
        issuer = kwargs.get('issuer')
        csr = kwargs.get('csr')
        hash_algorithm = kwargs.get('hash_algorithm', DEFAULT_HASH_ALGORITHM)
        duration_days = kwargs.get('duration_days', 365)

        one_day = timedelta(days=1)

        if csr:
            subject = csr.subject
            public_key = csr.public_key()
        else:
            subject = issuer
            public_key = issuer_key.public_key.underlying_key

        builder = x509.CertificateBuilder().not_valid_before(
            datetime.today() - one_day
        ).not_valid_after(
            datetime.today() + (one_day * duration_days)
        ).serial_number(
            x509.random_serial_number()
        ).public_key(
            public_key
        ).issuer_name(
            issuer.certificate_attributes
        ).subject_name(
            subject
        )

        for extension in certificate_type.extensions:
            builder = builder.add_extension(
                extension, critical=True)

        return x509Certificate(
            builder.sign(
                private_key=issuer_key.underlying_key,
                algorithm=hash_algorithm,
                backend=default_backend()
            ))
