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
from interface import implements

from ..exceptions import (CertificateAlreadyExistsException,
                          CertificateEntryNotFoundException,
                          InvalidCertificateTypeException,
                          IssuerDoesNotExistException)
from ..interfaces import (Certificate, CertificateDetails, CertificateStore,
                          CertificateStoreEntry, CertificateType, KeyStore,
                          PrivateKey, PublicKey, Tree)
from .structures import CertificateStoreEntryImpl
from .x509_minter import X509_CERTIFICATE_TYPES, x509Certificate


class FilesystemCertTree(Tree):

    def __init__(self, name, dir, ignore_list=[]):
        super().__init__(name)
        self._dir = dir
        self._ignore_list = ignore_list
        self._construct_tree()
        self._dir_icon = '\U0001F4DC'
        # self._dir_join_icon = '\U00002533'
        self._dir_join_icon = ''
        # self._dir_join_icon_base = '\U00002501'
        self._dir_join_icon_base = ''
        self._dir_suffix = ''
        self._pipe_icon = '\U00002503'
        self._file_icon = '\U0001F4C4'
        # self._file_icon_base = '\U00002517'
        self._file_icon_base = '\U0001F4C4'
        # self._file_join_icon = '\U00002501'
        self._file_join_icon = ' '

    def _construct_tree(self):

        for file in sorted(
                os.scandir(
                    self._dir),
                key=lambda f: f.name.lower()):
            if file.name in self._ignore_list:
                continue

            if file.is_dir():
                self.add_child_node(
                    FilesystemCertTree(
                        name=file.name,
                        dir=file,
                        ignore_list=self._ignore_list))
            else:
                self.add_leaf_node(file.name)


class FilesystemCertificateStore(implements(CertificateStore)):

    _BASE_DIR = 'certstore'
    _CERT_FILE_EXTENSION = 'pem'
    _CERT_ENCODING = serialization.Encoding.PEM

    def initialise(self, **kwargs):

        if 'dir' in kwargs:
            self.dir = Path(kwargs.get('dir'),
                            FilesystemCertificateStore._BASE_DIR)
        else:
            raise ValueError("Expected a dir parameter")

        self.dir_mode: int = kwargs.get('dir_mode', 0o700)
        self.file_mode: int = kwargs.get('file_mode', 0o400)
        self.cert_file_extension: str = kwargs.get(
            'cert_file_extension', FilesystemCertificateStore._CERT_FILE_EXTENSION)
        self.cert_encoding: str = kwargs.get(
            'cert_encoding', FilesystemCertificateStore._CERT_ENCODING)

        self.dir.mkdir(mode=self.dir_mode, exist_ok=True)

    def _get_cert_path(self, entry_details: CertificateDetails) -> Path:

        if entry_details.issuer:
            parent = self._get_cert_path(entry_details.issuer)
            return Path(
                self.dir,
                parent,
                entry_details.certificate_type.name,
                entry_details.name)
        else:
            return Path(
                self.dir,
                entry_details.certificate_type.name,
                entry_details.name)

    def _get_cert_file_name(self, entry_details: CertificateDetails) -> str:
        return "{}.{}".format(entry_details.name, self.cert_file_extension)

    def _get_cert_file_path(self, entry_details: CertificateDetails) -> Path:
        return Path(
            self._get_cert_path(entry_details),
            self._get_cert_file_name(entry_details))

    def list(self) -> Tree:
        tree = FilesystemCertTree(name='', dir=self.dir)

        return tree

    def exists(self, details: CertificateDetails) -> bool:
        if self._get_cert_file_path(details).exists():
            return True
        else:
            return False

    def _load_certificate_file(
            self, certificate_file_path: Path) -> Certificate:
        with open(certificate_file_path, "rb") as cert_file:
            cert_data = cert_file.read()

        return x509Certificate(
            x509.load_pem_x509_certificate(
                cert_data, default_backend()))

    def _store_certificate_file(
            self,
            certificate: Certificate,
            certificate_file_path: Path):

        with open(os.open(certificate_file_path, os.O_CREAT | os.O_WRONLY, self.file_mode), "wb") as cert_file:
            cert_file.write(certificate.public_bytes(
                self.cert_encoding
            ))

    def add(self, entry: CertificateStoreEntry):

        if self.exists(entry.details):
            raise CertificateAlreadyExistsException(
                "A certificate of type {} with name {} already exists".format(
                    entry.details.certificate_type.name,
                    entry.details.name
                ))

        if entry.details.issuer:
            if not self.exists(entry.details.issuer):
                raise IssuerDoesNotExistException(
                    "The certificate's issuer ({}) does not exist".format(
                        entry.details.issuer.name
                    ))

        certificate_path = self._get_cert_path(entry.details)

        certificate_path.parent.mkdir(
            mode=self.dir_mode, exist_ok=True, parents=False)
        certificate_path.mkdir(
            mode=self.dir_mode, exist_ok=False, parents=False)

        certificate_file = self._get_cert_file_path(entry.details)

        self._store_certificate_file(entry.certificate, certificate_file)

    def get(self, entry: CertificateStoreEntry) -> CertificateStoreEntry:
        if not self.exists(entry.details):
            raise CertificateEntryNotFoundException(
                "A certificate of type {} with name {} could not be found".format(
                    entry.details.certificate_type.name, entry.details.name))
        cert_file_path = self._get_cert_file_path(entry.details)
        cert = self._load_certificate_file(cert_file_path)

        return CertificateStoreEntryImpl(
            certificate=cert, details=entry.details)

    def remove(self, entry: CertificateStoreEntry):
        path = self._get_cert_path(entry.details)

        if path.exists() and path.relative_to(self.dir):
            shutil.rmtree(path)
