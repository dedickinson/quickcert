class InvalidCertificateTypeException(Exception):
    def __init__(self, message):
        super().__init__(message)

class CertificateEntryNotFoundException(Exception):
    def __init__(self, message):
        super().__init__(message)

class CertificateAlreadyExistsException(Exception):
    def __init__(self, message):
        super().__init__(message)
