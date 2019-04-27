import argparse
from collections import namedtuple
from typing import Dict, List, NamedTuple
import json

from ..implementations import (X509_CERTIFICATE_TYPES, CertificateDetailsImpl,
                               CertificateStoreEntryImpl,
                               x509CertificateMinter,
                               x509CertificateNameAttributes)
from ..interfaces import (Certificate, CertificateDetails, CertificateMinter,
                          CertificateStore, KeyStore, PrivateKey)

from ..exceptions import CertificateEntryNotFoundException


def configure_cli_cert_parser(parser: argparse.ArgumentParser):
    cert_type_choices = [
        cert_type for cert_type in X509_CERTIFICATE_TYPES.keys()]

    epilog = """
The cert_path defines the certificate's type ({}),
its parent(s) and its name.

For example:
    - A root cert called 'myroot':
        /root/myroot
    - A server cert issued by 'myroot':
        /root/myroot/server/myservercert
    - A client cert issued by 'myroot':
        /root/myroot/client/myclientcert
    - An intermediate cert issued by 'myroot':
        /root/myroot/intermediate/myintermediatecert
    - A server cert issued by 'myintermediatecert':
        /root/myroot/intermediate/myintermediatecert/server/myservercert
    - A client cert issued by 'myintermediatecert':
        /root/myroot/intermediate/myintermediatecert/client/myclientcert
    - A 'self-issued' server cert:
        /server/mywebservercert

You can provide a key password using --password, use no password
with --no-password, or be prompted for a password""".format(
        ','.join(cert_type_choices)
    )
    parser_create = parser.add_parser(
        'create_cert',
        description='Creates a new certificate',
        epilog=epilog,
        help='Create a certificate',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser_create.add_argument('cert_path',
                               type=str,
                               help='the certificate path')

    parser_create.add_argument('--no-store',
                               action='store_true',
                               help='don\'t store the cert, just send it to stdout')

    parser_create.add_argument('--key-name',
                               type=str,
                               required=True,
                               help='the key name')

    parser_create.add_argument('--country',
                               type=str,
                               required=False,
                               help='name attribute')

    parser_create.add_argument('--state',
                               type=str,
                               required=False,
                               help='name attribute')

    parser_create.add_argument('--locality',
                               type=str,
                               required=False,
                               help='name attribute')

    parser_create.add_argument('--organization',
                               type=str,
                               required=False,
                               help='name attribute')

    parser_create.add_argument('--common-name',
                               type=str,
                               required=False,
                               help='name attribute (the name param is used for common name if not provided)')

    parser_create.add_argument('--duration',
                               type=str,
                               required=False,
                               default=360,
                               help='certificate duration (in days). Default is 360.')

    parser_create_pwdgrp = parser_create.add_mutually_exclusive_group(
        required=False)

    parser_create_pwdgrp.add_argument('--password',
                                      type=str,
                                      help='the password for the key')

    parser_create_pwdgrp.add_argument('--no-password',
                                      action='store_true',
                                      help="don't use password for the key")

    list_certs = parser.add_parser(
        'list_certs',
        help='Lists the certificates in the certificate store')

    list_certs.add_argument('--json',
                            action='store_true')

    parser_info = parser.add_parser(
        'get_cert',
        help='Get information about a certificate')

    parser_info.add_argument(
        'cert_path',
        type=str,
        help='The type/name of the cert - e.g. /server/www.example.com')

    parser_delete = parser.add_parser(
        'delete_cert',
        help='Delete a certificate (and all of the sub-certificates)')

    parser_delete.add_argument(
        'cert_path',
        type=str,
        help='The type/name of the cert - e.g. server/www.example.com')


def get_certificate_details(cert_path: str) -> CertificateDetailsImpl:

    return CertificateDetailsImpl.determine_certificate_details(cert_path)


def create_cert(cert_store: CertificateStore, key_store: KeyStore,
                cert_minter: CertificateMinter, cert_path: str,
                key_name: str, key_password: str,
                country: str = None, state: str = None, locality: str = None, organization: str = None,
                common_name: str = None, duration_days: int = 360, store: bool = True):

    if not key_name:
        exit("No key name was provided")

    if not key_store.exists(key_name):
        exit("The requested key ({}) does not exist".format(key_name))

    if duration_days <= 0:
        exit("Duration days must be positive")

    if not cert_path:
        exit("No value was provided for cert_path")

    cert_details = get_certificate_details(cert_path)

    if not common_name:
        common_name = cert_details.name

    subject = x509CertificateNameAttributes(
        common_name=common_name,
        country_name=country,
        state_name=state,
        locality_name=locality,
        organization_name=organization
    )

    issuer = None

    private_key: PrivateKey = key_store.get(key_name=key_name,
                                            password=key_password)

    cert_args = x509CertificateMinter.prepare_mint_args(
        certificate_type=cert_details.certificate_type,
        private_key=private_key,
        subject=subject,
        issuer=subject,
        duration_days=duration_days
    )

    certificate: Certificate = cert_minter.mint(**cert_args)

    if store:
        entry = CertificateStoreEntryImpl(details=cert_details,
                                          certificate=certificate)
        cert_store.add(entry)
    else:
        print(str(certificate.public_bytes(), 'utf-8'))


def list_certs(cert_store: CertificateStore, json_format:bool):

    tree = cert_store.list()

    if json_format:
        print(json.dumps(tree, default=tree.transform))
    else:
        print(tree.format_string(include_leaves=False,
                                 include_root=False, compact=True))


def get_cert(cert_store: CertificateStore, cert_path: str):
    entry = CertificateStoreEntryImpl(details=get_certificate_details(cert_path),
                                      certificate=None)
    try:
        cert_entry = cert_store.get(entry)
    except CertificateEntryNotFoundException as e:
        exit(e)

    print(str(cert_entry.certificate.public_bytes(), 'utf-8'))


def delete_cert(cert_store: CertificateStore, cert_path: str):
    entry = CertificateStoreEntryImpl(details=get_certificate_details(cert_path),
                                      certificate=None)
    cert_store.remove(entry)
