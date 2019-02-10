import os
import argparse
import argcomplete
import datetime
from pathlib import Path
import configparser

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

from .constants import CERTIFICATE_TYPES
from .structures import CertificateType
from .exceptions import InvalidCertificateTypeException


class CertificateStore:

    @classmethod
    def configure_cert_store_path(
            cls,
            path: Path,
            mode: int,
            enforce_dir_mode: bool) -> Path:
        # logger.debug(f'Creating certificate store path: {path}')
        path.mkdir(mode=mode, exist_ok=True)

        if not path.exists():
            raise FileNotFoundError(f'{path}')

        if enforce_dir_mode and not (path.stat().st_mode == mode + 0o40000):
            raise FileNotFoundError(
                f'{path} has incorrect permissions - expected {oct(mode)}')

        return path

    def __init__(self, path: str,
                 dir_mode=0o700, file_mode=0o400,
                 key_size: int = 2048, key_public_exponent: int = 65537,
                 enforce_mode=True, config_file: str = 'config.ini',
                 certificate_types=CERTIFICATE_TYPES):

        self.cert_types = certificate_types

        self.base_path = Path(path).expanduser()
        self.dir_mode = dir_mode
        self.file_mode = file_mode
        self.enforce_mode = enforce_mode
        self.config_file = config_file
        self.key_size = key_size
        self.key_public_exponent = key_public_exponent

        self.config = configparser.ConfigParser()

    def initialise(self):
        # Setup the base path
        CertificateStore.configure_cert_store_path(
            self.base_path, self.dir_mode, self.enforce_mode)

        with open(os.open(Path(self.base_path, 'shadow'), os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
            f.write("""# Passphrase file
[root]

[intermediate]

[server]

[client]
""")

        with open(os.open(Path(self.base_path, 'config.ini'), os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
            f.write("""

""")

        # Setup sub-paths for the various cert types
        for key, val in self.cert_types.items():
            CertificateStore.configure_cert_store_path(
                self.get_cert_path(val), self.dir_mode, self.enforce_mode)

    def list(self, cert_type: CertificateType = None):
        print("List")

    def info(self, cert_path: str):
        tokens = cert_path.split('/')
        cert_type_name = tokens[0]
        if not self.check_valid_cert_type(cert_type_name):
            raise self._get_exception_invalid_certificate_type(cert_type_name)

        cert_name = tokens[1]
        print(f'Type: {cert_type_name}; Name: {cert_name}')

    def get_cert_path(self, cert_type: CertificateType, cert_name=None):
        if cert_name:
            return Path(self.base_path, cert_type.dir, cert_name)

        return Path(self.base_path, cert_type.dir)

    def get_validate_cert_types(self):
        return self.cert_types.keys()

    def check_valid_cert_type(self, cert_type_name: str):
        return cert_type_name in self.cert_types.keys()

    def certificate_exists(self, cert_type_name: str, cert_name: str):
        cert_type = self.cert_types[cert_type_name]
        if self.get_cert_path(cert_type, cert_name).exists():
            return True
        return False

    # def certificate_exists(self, cert_type: CertificateType, cert_name: str):
    #     if self.get_cert_path(cert_type, cert_name).exists():
    #        return True
    #     return False

    def create_certificate(
            self,
            cert_type_name: str,
            cert_name: str,
            passphrase: str = None):

        def create_rsa_key():
            return rsa.generate_private_key(
                public_exponent=self.key_public_exponent,
                key_size=self.key_size,
                backend=default_backend()
            )

        def store_key(name: str, path: Path, key):
            with open(os.open(Path(path, f'{name}.key.pem'), os.O_CREAT | os.O_WRONLY, self.file_mode), "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        b"passphrase"),
                ))

        def create_rsa_cert(
                private_key,
                certificate_type: CertificateType,
                subject: x509.Name,
                issuer: x509.Name,
                certificate_duration_days: int = 360):

            one_day = datetime.timedelta(1, 0, 0)
            public_key = private_key.public_key()

            builder = x509.CertificateBuilder(
            ).not_valid_before(
                datetime.datetime.today() - one_day
            ).not_valid_after(
                datetime.datetime.today() + (one_day * certificate_duration_days)
            ).serial_number(
                x509.random_serial_number()
            ).public_key(
                public_key
            ).subject_name(
                subject
            ).issuer_name(
                issuer
            )

            for extension in certificate_type.extensions:
                builder = builder.add_extension(
                    extension, critical=True)

            certificate = builder.sign(
                private_key=private_key, algorithm=hashes.SHA256(),
                backend=default_backend()
            )

            return certificate

        def store_certificate(name: str, path: Path, certificate):
            with open(os.open(Path(path, f'{name}.cert.pem'), os.O_CREAT | os.O_WRONLY, self.file_mode), "wb") as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))

        if not self.check_valid_cert_type(cert_type_name):
            raise Exception(f'Invalid certificate type: {cert_type_name}')

        cert_type = self.cert_types[cert_type_name]
        cert_path: Path = self.get_cert_path(cert_type, cert_name)

        if self.certificate_exists(cert_type, cert_name):
            raise Exception(
                f'Certificate of type {cert_type_name} with name {cert_name} exists')

        CertificateStore.configure_cert_store_path(
            cert_path, self.dir_mode, self.enforce_mode)

        key = create_rsa_key()
        store_key(cert_name, cert_path, key)

        #Todo: complete
        #cert = create_rsa_cert(key, cert_type, )
        #store_certificate(cert_name, cert_path, cert)

    def _get_exception_invalid_certificate_type(self, cert_type_name: str):
        return InvalidCertificateTypeException(
            f'Invalid certificate type: {cert_type_name}. Allowed types: {list(self.get_validate_cert_types())}')
