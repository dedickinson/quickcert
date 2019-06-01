"""
A set of interfaces for handling certificates
"""

import typing
import datetime

from interface import Interface

from .key import PublicKey, PrivateKey
from .util import Tree


class CertificateType(Interface):
    """The type of certificate

    This is used to define a specific version of
    a certificate and ensure that it has the correct
    attributes. 
    """

    @property
    def name(self) -> str:
        """A nice name for the type

        :type: str
        """
        pass

    @property
    def extensions(self) -> typing.List[]:
        """A list of attributes (extensions) specific to this certificate type

        :type: typing.List[]
        """
        pass


class CertificateNameAttributes(Interface):
    """
    """

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
    """Represents a certificate"""

    @property
    def serial_number(self) -> int:
        """The certificate's serial number

            :type: int
        """
        pass

    @property
    def version(self) -> str: pass

    @property
    def not_valid_before(self) -> datetime:
        """Indicates the start date for the certificate

            :type: datetime.datetime
        """
        pass

    @property
    def not_valid_after(self) -> datetime:
        """Indicates the end date for the certificate

            :type: datetime.datetime
        """
        pass

    @property
    def public_key(self) -> PublicKey:
        """The public key

            :type: PublicKey
        """
        pass

    @property
    def issuer(self) -> CertificateNameAttributes: pass

    @property
    def subject(self) -> CertificateNameAttributes: pass

    @property
    def extensions(self): pass

    def public_bytes(self, encoding=None) -> bytes: pass


class CertificateMinter(Interface):
    """Minting interface to create certificates

    This is a very loose interface that relies on implementations
    to guide users as to required properties
    """

    def mint(self, **kwargs) -> Certificate:
        """Creates a new certificate

        Implementations will define the required args

        :return: the certificate
        :rtype: Certificate
        """
        pass


class CertificateDetails(Interface):
    """ Meta information about a certificate
    """

    @property
    def name(self) -> str:
        """ The name of the certificate (e.g. the common name)

            :type: str
        """
        pass

    @property
    def issuer(self) -> 'CertificateDetails':
        """ The details for the certificate issuer

            :type: CertificateDetails
        """
        pass

    @property
    def certificate_type(self) -> CertificateType:
        """ The type of certificate

            :type: CertificateType
        """
        pass


class CertificateStoreEntry(Interface):
    """ An entry in the certificate store

        Entries consist of two parts:

            1. Details about the certificate
            2. The certificate itself

    """

    @property
    def certificate(self) -> Certificate:
        """ Get the certificate component of the entry

            :rtype: Certificate
        """
        pass

    @property
    def details(self) -> CertificateDetails:
        """ Get the entry details

            :rtype: CertificateDetails
        """
        pass


class CertificateStore(Interface):

    def initialise(self, **kwargs):
        pass

    def list(self) -> Tree:
        pass

    def get(self, entry: CertificateStoreEntry) -> CertificateStoreEntry:
        """ Use a partial entry to locate and return the full entry (with the certificate)

            :param CertificateStoreEntry entry: An entry object usually just with the details
                so that the store can locate the entry
            :returns: The complete entry including the certificate
            :rtype: CertificateStoreEntry
            :raises CertificateEntryNotFoundException: If the store does not contain the entry
        """
        pass

    def exists(self, details: CertificateDetails) -> bool:
        pass

    def add(self, entry: CertificateStoreEntry):
        pass

    def remove(self, entry: CertificateStoreEntry):
        pass
