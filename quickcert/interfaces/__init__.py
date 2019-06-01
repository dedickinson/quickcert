"""
Interfaces
----------

.. currentmodule::quickcert.interfaces

Keys
~~~~


.. autoclass:: PrivateKey
    :members:

.. autoclass:: PublicKey
    :members:

.. autoclass:: KeyMinter
    :members:

.. autoclass:: KeyStore
    :members:

Certificates
~~~~~~~~~~~~

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

"""

from interface import Interface

from .certificate import (Certificate, CertificateMinter,
                          CertificateNameAttributes, CertificateStore,
                          CertificateStoreEntry, CertificateType,
                          CertificateDetails)

from .key import KeyMinter, KeyStore, PrivateKey, PublicKey

from .util import Tree


class PasswordValidator(Interface):
    """Interface for password validators"""

    def validate(self, password: str) -> bool:
        """Validate the provided password

        :param str password: The password to be validated
        :returns: ``true`` if the password is valid, ``false`` otherwise
        """
        pass


class PasswordGenerator(Interface):
    def generate_password(self, length: int = 32,
                          selection: str = '',
                          validator: PasswordValidator = None) -> str:
        """Interface for password generators

        :param int length: The number of characters in the password
        :param str selection: A set of characters from which to draw the password
        :param PasswordValidator validator: A validator that will check the password

        :return: The generated password
        :rtype: str
        """
        pass
