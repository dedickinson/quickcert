.. _api:

Developer Interface
===================

.. contents:: :local:

The codebase is primarily a veneer over the 
`cryptography <https://cryptography.io>`_ library.



A set of implementation

Implementations
---------------
.. module:: quickcert.implementations

The :mod:`implementations <quickcert.implementations>` module contains concrete instantiations
of the various :mod:`interfaces <quickcert.interfaces>`

RSA Minter
~~~~~~~~~~

.. autoclass:: RsaKeyMinter
    :members:

x509 Minter
~~~~~~~~~~~

.. autoclass:: x509CertificateMinter
    :members:

.. autoclass:: x509CertificateNameAttributes
    :members:

.. autoclass:: x509SigningRequest
    :members:

.. autoclass:: x509RootCertificateType
    :members:

.. autoclass:: x509IntermediateCertificateType
    :members:

.. autoclass:: x509ServerCertificateType
    :members:

.. autoclass:: x509ClientCertificateType
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

Exceptions
~~~~~~~~~~
.. module:: quickcert

.. autoexception:: InvalidCertificateTypeException
.. autoexception:: CertificateEntryNotFoundException
.. autoexception:: CertificateAlreadyExistsException
.. autoexception:: IssuerDoesNotExistException


Interfaces
----------
.. module:: quickcert.interfaces


Key
~~~

.. autoclass:: PrivateKey
    :members:

.. autoclass:: PublicKey
    :members:

.. autoclass:: KeyMinter
    :members:

.. autoclass:: KeyStore
    :members:

Certificate
~~~~~~~~~~~

.. autoclass:: Certificate
    :members:

.. autoclass:: CertificateType
    :members:

.. autoclass:: CertificateNameAttributes
    :members:

.. autoclass:: CertificateMinter
    :members:

.. autoclass:: CertificateDetails
    :members:

.. autoclass:: CertificateStore
    :members:

.. autoclass:: CertificateStoreEntry
    :members:


Other
~~~~~

.. autoclass:: PasswordValidator
    :members:

.. autoclass:: PasswordGenerator
    :members:

.. autoclass:: Tree
    :members: