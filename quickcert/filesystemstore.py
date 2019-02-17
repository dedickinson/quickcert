import argparse
import configparser
import datetime
import os
import shelve
import shutil
import typing
from pathlib import Path

import argcomplete
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (RSAPrivateKey,
                                                           RSAPublicKey)
from cryptography.x509 import Certificate as x509Certificate
from interface import implements

from .exceptions import (CertificateAlreadyExistsException,
                         CertificateEntryNotFoundException,
                         InvalidCertificateTypeException)
from .interfaces import (Certificate, CertificateStore, CertificateStoreEntry,
                         CertificateStoreShadow, CertificateType, PrivateKey,
                         PublicKey)
from .structures import CertificateStoreEntryImpl
from .x509_minter import X509_CERTIFICATE_TYPES


class CertificateStoreFilesystemShadow(implements(CertificateStoreShadow)):

    def __init__(self, path: Path):
        self.path = Path

    def _key(self, certificate_type: CertificateType, certificate_name: str) -> str:
        return f'{certificate_type.name}/{certificate_name}'

    def initialise(self):
        with shelve.open(self.path, flag='c', writeback=False) as _:
            pass

    def add(self, certificate_type: CertificateType, certificate_name: str, password: str):
        with shelve.open(self.path, flag='w', writeback=True) as db:
            db[self._key(certificate_type, certificate_name)] = password

    def get(self, certificate_type: CertificateType, certificate_name: str) -> str:

        with shelve.open(self.path, flag='r', writeback=False) as db:
            result = db[self._key(certificate_type, certificate_name)]

        return result

    def remove(self, certificate_type: CertificateType, certificate_name: str):
        with shelve.open(self.path, flag='w', writeback=True) as db:
            del db[self._key(certificate_type, certificate_name)]


class CertificateStoreFilesystemConfiguration:

    def __init__(self,
                 path: str,
                 dir_mode: int = 0o700,
                 file_mode: int = 0o400,
                 enforce_mode: bool = True,
                 config_file: str = None,
                 certificate_file_suffix: str = '.cert.pem',
                 key_file_suffix: str = '.key.pem',
                 file_encoding=serialization.Encoding.PEM,
                 shadow_file_path: str = None):

        self.base_path: Path = Path(path).expanduser()
        self.dir_mode: int = dir_mode
        self.file_mode: int = file_mode
        self.enforce_mode: bool = enforce_mode
        self.certificate_file_suffix: str = certificate_file_suffix
        self.key_file_suffix: str = key_file_suffix
        self.file_encoding = file_encoding

        self.shadow_file_path = shadow_file_path or Path(
            self.base_path, 'shadow')

        self.shadow: CertificateStoreFilesystemShadow = CertificateStoreFilesystemShadow(
            self.shadow_file_path)

        if config_file:
            self.config_file_path = Path(config_file)
        else:
            self.config_file_path = Path(self.base_path, 'config.ini')

        self.config = configparser.ConfigParser()
        self.config.read(self.config_file_path)

    def initialise(self):
        if self.config_file_path.exists():
            return

        config = configparser.ConfigParser()
        config['defaults'] = {}
        for _, certificate_type in X509_CERTIFICATE_TYPES:
            config[certificate_type.name] = {}

        with open(os.open(self.config_file_path, os.O_CREAT | os.O_WRONLY, self.file_mode), "w") as configfile:
            config.write(configfile)


class CertificateStoreFilesystem(implements(CertificateStore)):

    def __init__(self, config: CertificateStoreFilesystemConfiguration):
        self.config = config

    def _get_certtype_dir_path(self, certificate_type: CertificateType):
        return Path(self.base_path, certificate_type.name)

    def _get_cert_dir_path(self, certificate_type: CertificateType, certificate_name: str):
        return Path(self._get_certtype_dir_path(certificate_type.name), certificate_name)

    def _get_cert_file_path(self, certificate_type: CertificateType, certificate_name: str):
        return Path(self._get_cert_dir_path(certificate_type, certificate_name),
                    f'{certificate_name}{CertificateStoreFilesystem.CERTIFICATE_FILE_SUFFIX}')

    def _get_key_file_path(self, certificate_type: CertificateType, certificate_name: str):
        return Path(self._get_cert_dir_path(certificate_type, certificate_name),
                    f'{certificate_name}{CertificateStoreFilesystem.KEY_FILE_SUFFIX}')

    def list(self, certificate_type: CertificateType) -> typing.List[str]:
        path = self._get_certtype_dir_path(certificate_type)
        return [dir for dir in path.iterdir()]

    def exists(self, certificate_type: CertificateType, certificate_name: str) -> bool:
        cert_file = self._get_cert_file_path(
            certificate_type, certificate_name)

        key_file = self._get_key_file_path(certificate_type, certificate_name)

        if cert_file.is_file() and key_file.is_file():
            return True

        return False

    def _load_certificate_file(self, certificate_file_path: Path) -> Certificate:
        with open(certificate_file_path, "rb") as cert_file:
            cert_data = cert_file.read()

        return x509.load_pem_x509_certificate(cert_data, default_backend())

    def _load_key_file(self, key_file_path: Path) -> PrivateKey:
        with open(key_file_path, "rb") as key_file:
            key_file_data = key_file.read()

        private_key = serialization.load_pem_private_key(
            key_file_data,
            password=None,
            backend=default_backend()
        )

        return private_key

    def get(self, certificate_type: CertificateType, certificate_name: str) -> CertificateStoreEntry:

        if not self.exists(certificate_type, certificate_name):
            raise CertificateEntryNotFoundException(
                f"A certificate of type {certificate_type} with name {certificate_name} does not exist"
            )

        certificate_path = self._get_cert_file_path(
            certificate_type, certificate_name)

        certificate = self._load_certificate_file(certificate_path)

        key_path = self._get_key_file_path(
            certificate_type, certificate_name)

        private_key = self._load_key_file(key_path)

        return CertificateStoreEntryImpl(name=certificate_name,
                                         certificate_type=certificate_type,
                                         certificate=certificate,
                                         key=private_key)

    def _store_certificate_file(self, certificate: Certificate, certificate_file_path: Path):

        with open(os.open(certificate_file_path, os.O_CREAT | os.O_WRONLY, self.file_mode), "wb") as cert_file:
            cert_file.write(certificate.public_bytes(
                self.config.file_encoding))

    def _store_key_file(self, key: PrivateKey, key_file_path: Path):

        with open(os.open(key_file_path, os.O_CREAT | os.O_WRONLY, self.file_mode), "wb") as key_file:
            key_file.write(key.private_bytes(
                encoding=self.config.file_encoding,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    b"passphrase"),
            ))

    def add(self, entry: CertificateStoreEntry):

        if self.exists(entry.certificate_type, entry.name):
            raise CertificateAlreadyExistsException(
                f"A certificate of type {entry.certificate_type} with name {entry.name} already exists")

        certificate_path = self._get_cert_file_path(
            entry.certificate_type, entry.name)

        key_path = self._get_key_file_path(
            entry.certificate_type, entry.name)

        self._store_certificate_file(
            certificate=entry.certificate,
            certificate_file_path=certificate_path
        )

        self._store_key_file(
            key=entry.private_key,
            key_file_path=key_path
        )

    def remove(self, entry: CertificateStoreEntry):
        if not self.exists(entry.certificate_type, entry.name):
            raise CertificateEntryNotFoundException(
                f"A certificate of type {entry.certificate_type} with name {entry.name} does not exist"
            )

        path = self._get_cert_dir_path(
            certificate_type=entry.certificate_type,
            certificate_name=entry.name
        )

        shutil.rmtree(path)

    def _initialiase_repository(self, path: Path):
        path.mkdir(mode=self.config.mode, exist_ok=True)

        if not path.exists():
            raise FileNotFoundError(f'{path}')

        if self.config.enforce_dir_mode and not (path.stat().st_mode == self.config.mode + 0o40000):
            raise FileNotFoundError(
                f'{path} has incorrect permissions - expected {oct(self.config.mode)}')

    def initialise(self):
        self._initialiase_repository(self.config.base_path)
        self.config.initialise()
        self.shadow.initialise()

        # Setup sub-paths for the various cert types
        for _, certificate_type in X509_CERTIFICATE_TYPES:
            path = self._get_certtype_dir_path(certificate_type)
            self._initialiase_repository(path)
