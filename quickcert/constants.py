from . import CertificateType
from cryptography import x509

CONST_DEFAULT_KEY_SIZE: int = 2048

CERTIFICATE_TYPE_ROOT = 'root'
CERTIFICATE_TYPE_INTERMEDIATE = 'intermediate'
CERTIFICATE_TYPE_SERVER = 'server'
CERTIFICATE_TYPE_CLIENT = 'client'

CERTIFICATE_TYPES = {
    CERTIFICATE_TYPE_ROOT: CertificateType(
        CERTIFICATE_TYPE_ROOT,
        extensions=[
            x509.BasicConstraints(
                ca=True,
                path_length=None)]),
    CERTIFICATE_TYPE_INTERMEDIATE: CertificateType(CERTIFICATE_TYPE_INTERMEDIATE),
    CERTIFICATE_TYPE_SERVER: CertificateType(
        CERTIFICATE_TYPE_SERVER,
        extensions=[
            x509.BasicConstraints(
                ca=False,
                path_length=None)]),
    CERTIFICATE_TYPE_CLIENT: CertificateType(CERTIFICATE_TYPE_CLIENT)}
