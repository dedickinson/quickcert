"""A set of interfaces for handling keys
"""
import typing

from interface import Interface

from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding


class PublicKey(Interface):
    """The public key component of an asymmetric key
    """

    def serialize(self) -> bytes:
        """Prepare bytes ready for writing to file

        :return: ready for writing to a file
        :rtype: bytes
        """
        pass

    @property
    def key_size(self) -> int:
        """The key size in bits

        :type: int
        """
        pass

    def encrypt(self, plaintext: bytes,
                padding: AsymmetricPadding) -> bytes:
        """Encrypt plaintext using the key

        :param plaintext: the text to encrypt
        :type plaintext: bytes
        :param padding: the encryption padding scheme
        :type padding: AsymmetricPadding
        :return: the encrypted plaintext
        :rtype: bytes
        """
        pass


class PrivateKey(Interface):
    """The private key component of an asymmetric key"""

    @property
    def public_key(self) -> PublicKey:
        """The public key for this private key

        :type: PublicKey
        """
        pass

    def decrypt(self, ciphertext: bytes,
                padding: AsymmetricPadding) -> bytes:
        """Decrypts a message encrypted by this key's public key

        Create the encrypted message using :meth:`PublicKey.encrypt`

        :param ciphertext: the encrypted message
        :type ciphertext: bytes
        :param padding: the encryption padding scheme
        :type padding: AsymmetricPadding
        :return: the decrypted message
        :rtype: bytes
        """
        pass

    def serialize(self, password: str = None) -> bytes:
        """Prepare bytes ready for writing to a file

        :param password: the password to protect the key, defaults to None
        :type password: str, optional
        :return: bytes ready to write
        :rtype: bytes
        """
        pass

    @property
    def key_size(self) -> int:
        """The key size in bits

        :type: int
        """
        pass

    @property
    def underlying_key(self):
        """The actual key from the cryptography library
        """
        pass


class KeyMinter(Interface):
    """Minting interface to create keys

    This is a very loose interface that relies on implementations
    to guide users as to required properties"""

    def mint(self, **kwargs) -> PrivateKey:
        """Creates a new key

        :return: the new key
        :rtype: PrivateKey
        """
        pass


class KeyStore(Interface):
    """An interface that provides the methods for working with a key store

    A key store is reasonably simple and relies on each key having a 
    unique name that's used for storing and recalling the key.

    Some entries will use a password when storing/retrieving the key

    """

    def initialise(self, **kwargs):
        """Implementations will define how the key store is initialised

        For example, a filesystem key store may setup directories and permissions
        or a database key store may create a table
        """
        pass

    def add(self, key: PrivateKey, key_name: str, password: str = None):
        """Adds a private key to the store

        :param key: the key to store
        :type key: PrivateKey
        :param key_name: the unique name of the key
        :type key_name: str
        :param password: the password used to secure the key (could be empty)
        :type password: str, optional
        """
        pass

    def exists(self, key_name: str) -> bool:
        """Determines if a key has been stored against the name

        :param key_name: the key name
        :type key_name: str
        :return: True if exists, False otherwise
        :rtype: bool
        """
        pass

    def get(self, key_name: str, password: str = None) -> PrivateKey:
        """Get the key from the store that's aligned to the name

        :param key_name: the key name
        :type key_name: str
        :param password: the password to deserialize the key, defaults to None
        :type password: str, optional
        :return: the private key
        :rtype: PrivateKey
        """
        pass

    def remove(self, key_name: str):
        """Deletes the key from the store

        :param key_name: the key name
        :type key_name: str
        """
        pass

    def list(self) -> typing.List[str]:
        """Lists all keys in the key store

        :return: a list of key names
        :rtype: typing.List[str]
        """
        pass
