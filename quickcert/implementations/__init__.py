"""
Implementations
---------------

The :mod:`implementations <quickcert.implementations>` module contains concrete instantiations
of the various :mod:`interfaces <quickcert.interfaces>`

.. currentmodule:: quickcert.implementations

RSA Keys
~~~~~~~~

.. autoattribute:: quickcert.implementations.CONST_DEFAULT_KEY_SIZE
.. autoattribute:: quickcert.implementations.CONST_DEFAULT_ENCRYPTION_PADDING
.. autoattribute:: quickcert.implementations.CONST_DEFAULT_KEY_PUBLIC_EXPONENT
.. autoattribute:: quickcert.implementations.CONST_DEFAULT_SIGNING_PADDING

.. autoclass:: RsaPublicKey
    :members:

.. autoclass:: RsaPrivateKey
    :members:

.. autoclass:: RsaKeyMinter
    :members:

x509 Certificates
~~~~~~~~~~~~~~~~~

.. autoattribute:: quickcert.implementations.DEFAULT_HASH_ALGORITHM

.. autoattribute:: quickcert.implementations.CERTIFICATE_TYPE_ROOT_NAME
.. autoattribute:: quickcert.implementations.CERTIFICATE_TYPE_INTERMEDIATE_NAME
.. autoattribute:: quickcert.implementations.CERTIFICATE_TYPE_SERVER_NAME
.. autoattribute:: quickcert.implementations.CERTIFICATE_TYPE_CLIENT_NAME

.. autoclass:: x509CertificateMinter
    :members:

.. autoclass:: x509CertificateNameAttributes
    :members:

.. autoclass:: x509SigningRequest
    :members:

.. autoclass:: x509AbstractCertificateType
    :members:

.. autoclass:: x509RootCertificateType
    :show-inheritance:
    :inherited-members:
    :members:

.. autoclass:: x509IntermediateCertificateType
    :show-inheritance:
    :inherited-members:
    :members:

.. autoclass:: x509ServerCertificateType
    :show-inheritance:
    :inherited-members:
    :members:

.. autoclass:: x509ClientCertificateType
    :show-inheritance:
    :inherited-members:
    :members:


Certificate Stores
~~~~~~~~~~~~~~~~~~

.. autoclass:: FilesystemCertificateStore
    :members:

.. autoclass:: CertificateStoreEntryImpl
    :members:

.. autoclass:: CertificateDetailsImpl
    :members:

Key Stores
~~~~~~~~~~

.. autoclass:: FilesystemKeyStore
    :members:

Password Generator
~~~~~~~~~~~~~~~~~~

.. autoclass:: BasicPasswordGenerator
    :members:

.. autoclass:: quickcert.implementations.password_generator.BasicPasswordValidator
    :members:
"""

from .rsa_minter import (
    CONST_DEFAULT_ENCRYPTION_PADDING,
    CONST_DEFAULT_KEY_PUBLIC_EXPONENT,
    CONST_DEFAULT_KEY_SIZE,
    CONST_DEFAULT_SIGNING_PADDING,
    RsaPublicKey,
    RsaPrivateKey,
    RsaKeyMinter)

from .x509_minter import (
    DEFAULT_HASH_ALGORITHM,
    CERTIFICATE_TYPE_ROOT_NAME,
    CERTIFICATE_TYPE_INTERMEDIATE_NAME,
    CERTIFICATE_TYPE_SERVER_NAME,
    CERTIFICATE_TYPE_CLIENT_NAME,
    X509_CERTIFICATE_TYPES,
    x509CertificateMinter,
    x509CertificateNameAttributes,
    x509AbstractCertificateType,
    x509ClientCertificateType,
    x509IntermediateCertificateType,
    x509RootCertificateType,
    x509ServerCertificateType,
    x509SigningRequest)

from .password_generator import BasicPasswordGenerator
from .filesystemkeystore import FilesystemKeyStore
from .filesystemcertstore import FilesystemCertificateStore

from .structures import CertificateStoreEntryImpl, CertificateDetailsImpl
