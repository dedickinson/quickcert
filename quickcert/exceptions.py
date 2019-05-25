
class InvalidCertificateTypeException(Exception):
    """
    Unable to handle requested
    :class:`CertificateType <quickcert.interfaces.CertificateType>`
    """


class CertificateEntryNotFoundException(Exception):
    """The requested certificate can't be found"""


class CertificateAlreadyExistsException(Exception):
    """The requested certificate already exists"""


class IssuerDoesNotExistException(Exception):
    """The certificate issuer doesn't exist"""
