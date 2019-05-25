import argparse
from collections import namedtuple
from typing import Dict, List, NamedTuple
import json

from ..implementations import (X509_CERTIFICATE_TYPES, CertificateDetailsImpl,
                               CertificateStoreEntryImpl,
                               x509CertificateMinter,
                               x509CertificateNameAttributes,
                               x509RootCertificateType,
                               x509IntermediateCertificateType,
                               x509ServerCertificateType,
                               x509ClientCertificateType,
                               x509SigningRequest)
from ..interfaces import (Certificate, CertificateDetails, CertificateMinter,
                          CertificateStore, KeyStore, PrivateKey)

from .cli_util import prompt_for_password

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
""".format(
        ','.join(cert_type_choices)
    )
    parser_create = parser.add_parser(
        'create-cert',
        description='Creates a new certificate',
        epilog=epilog,
        help='Create a certificate',
        formatter_class=argparse.RawDescriptionHelpFormatter)

    parser_create.add_argument('cert_path',
                               type=str,
                               help='the certificate path')

    parser_create.add_argument('--issuer-key-name',
                               type=str,
                               required=True,
                               help='the issuing key name')

    parser_create_issuer_pwdgrp = parser_create.add_mutually_exclusive_group(
        required=False)

    parser_create_issuer_pwdgrp.add_argument('--issuer-key-password',
                                             type=str,
                                             help='the password for the key')

    parser_create_issuer_pwdgrp.add_argument(
        '--issuer-key-no-password',
        action='store_true',
        help="don't use password for the key")

    parser_create.add_argument(
        '--signing-key-name',
        type=str,
        required=False,
        help='the signing key name (not required for a Root cert)')

    parser_create_signing_pwdgrp = parser_create.add_mutually_exclusive_group(
        required=False)

    parser_create_signing_pwdgrp.add_argument('--signing-key-password',
                                              type=str,
                                              help='the password for the key')

    parser_create_signing_pwdgrp.add_argument(
        '--signing-key-no-password',
        action='store_true',
        help="don't use password for the key")

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

    parser_create.add_argument(
        '--common-name',
        type=str,
        required=False,
        help='name attribute (the name elment in cert_path is used for common name if not provided)')

    parser_create.add_argument(
        '--duration',
        type=str,
        required=False,
        default=365,
        help='certificate duration (in days). Default is 365.')

    parser_create.add_argument(
        '--no-store',
        action='store_true',
        help='don\'t store the cert, just send it to stdout')

    list_certs = parser.add_parser(
        'list-certs',
        help='Lists the certificates in the certificate store')

    list_certs.add_argument('--json',
                            action='store_true')

    parser_info = parser.add_parser(
        'get-cert',
        help='Get information about a certificate')

    parser_info.add_argument(
        'cert_path',
        type=str,
        help='The type/name of the cert - e.g. /server/www.example.com')

    parser_delete = parser.add_parser(
        'delete-cert',
        help='Delete a certificate (and all of the sub-certificates)')

    parser_delete.add_argument(
        'cert_path',
        type=str,
        help='The type/name of the cert - e.g. server/www.example.com')


def get_certificate_details(cert_path: str) -> CertificateDetailsImpl:

    return CertificateDetailsImpl.determine_certificate_details(cert_path)


def create_cert(
        cert_store: CertificateStore,
        key_store: KeyStore,
        cert_minter: CertificateMinter,
        cert_path: str,
        issuer_key_name: str,
        issuer_key_password: str,
        issuer_key_no_password: bool = False,
        signing_key_name: str = None,
        signing_key_password: str = None,
        signing_key_no_password: bool = False,
        country: str = None,
        state: str = None,
        locality: str = None,
        organization: str = None,
        common_name: str = None,
        duration_days: int = 365,
        store: bool = True):
    """Creates a new certificate

    This function handles the creation of a new certificate. The general notes
    below are based on the cert_path:

    ``/server/myserver`` & ``/client/myclient``
        A self-signed certificate in which the issuer and the subject are the same.
        No signing_key_name is needed.

    ``/root/myroot``
        A root CA in which the issuer and the subject are the same
        No signing_key_name is needed.

    ``/root/myroot/intermediate/myintermediate``
        An intermediate CA with the issuer being ``/root/myroot``
        A signing_key_name is needed

    ``/root/myroot/intermediate/myintermediate/server/myserver``
        A server certificate with the issuer being ``/root/myroot/intermediate/myintermediate``
        A signing_key_name is needed

    ``/root/myroot/server/myserver``
        A server certificate with the issuer being ``/root/myroot``
        A signing_key_name is needed


    Arguments:
        cert_store {CertificateStore} -- [description]
        key_store {KeyStore} -- [description]
        cert_minter {CertificateMinter} -- [description]
        cert_path {str} -- [description]
        issuer_key_name {str} -- [description]
        issuer_key_password {str} -- [description]

    Keyword Arguments:
        signing_key_name {str} -- [description] (default: {None})
        signing_key_password {str} -- [description] (default: {None})
        country {str} -- [description] (default: {None})
        state {str} -- [description] (default: {None})
        locality {str} -- [description] (default: {None})
        organization {str} -- [description] (default: {None})
        common_name {str} -- [description] (default: {None})
        duration_days {int} -- [description] (default: {365})
        store {bool} -- [description] (default: {True})
    """

    if not issuer_key_name:
        exit("No issuer key name was provided")

    if not key_store.exists(issuer_key_name):
        exit("The requested issuer key ({}) does not exist".format(issuer_key_name))

    if duration_days <= 0:
        exit("Duration days must be positive")

    if not cert_path:
        exit("No value was provided for cert_path")

    cert_details = get_certificate_details(cert_path)

    if cert_store.exists(cert_details):
        exit("The certificate already exists")

    if not common_name:
        common_name = cert_details.name

    subject = x509CertificateNameAttributes(
        common_name=common_name,
        country_name=country,
        state_name=state,
        locality_name=locality,
        organization_name=organization
    )

    signing_key: PrivateKey = None
    csr = None

    if isinstance(cert_details.certificate_type, x509RootCertificateType):
        # Root certificate
        issuer = subject
    elif ((type(cert_details.certificate_type) in [x509ClientCertificateType, x509ServerCertificateType])
          and (cert_details.issuer is None)):
        # Self-signed server/client cert
        issuer = subject
    else:
        # An intermediate cert or signed client/server cert
        if not signing_key_name:
            exit("No signing key name was provided")

        if not key_store.exists(signing_key_name):
            exit("The requested signing key ({}) does not exist".format(
                signing_key_name))

        # Check the issuer's certificate
        if cert_details.issuer.certificate_type in [
                x509RootCertificateType, x509IntermediateCertificateType]:
            exit("The certificate's issuer must be a Root or Intermediate CA")

        if not cert_store.exists(cert_details.issuer):
            exit("The issuing certificate {} doesn't exist.".format(
                cert_details.issuer.name))

        issuer_cert = cert_store.get(CertificateStoreEntryImpl(
            details=cert_details.issuer,
            certificate=None
        ))

        issuer = issuer_cert.certificate.subject

        # Get the signing key (for use with a CSR)
        if signing_key_no_password:
            signing_password = None
        elif signing_key_password:
            signing_password = signing_key_password
        else:
            signing_password = prompt_for_password(
                prompt="Enter password for key {}: ".format(signing_key_name), validate=False)

        try:
            signing_key = key_store.get(key_name=signing_key_name,
                                        password=signing_password)
        except ValueError as e:
            exit("Failed to access the signing key ({}) - {}".format(issuer_key_name,
                                                                     e))

        csr = x509SigningRequest.generate(
            private_key=signing_key,
            subject=subject
        )

    # Load the Issuer Key
    if issuer_key_no_password:
        issuer_password = None
    elif issuer_key_password:
        issuer_password = issuer_key_password
    else:
        issuer_password = prompt_for_password(
            prompt="Enter password for key {}: ".format(issuer_key_name), validate=False)

    try:
        issuer_key: PrivateKey = key_store.get(key_name=issuer_key_name,
                                               password=issuer_password)
    except ValueError as e:
        exit("Failed to access the issuer key ({}) - {}".format(issuer_key_name,
                                                                e))

    if not csr:
        csr = x509SigningRequest.generate(
            private_key=issuer_key,
            subject=issuer
        )

    cert_args = x509CertificateMinter.prepare_mint_args(
        certificate_type=cert_details.certificate_type,
        issuer_key=issuer_key,
        issuer=issuer,
        csr=csr,
        duration_days=duration_days
    )

    certificate: Certificate = cert_minter.mint(**cert_args)

    if store:
        entry = CertificateStoreEntryImpl(details=cert_details,
                                          certificate=certificate)
        cert_store.add(entry)
    else:
        print(str(certificate.public_bytes(), 'utf-8'))


def list_certs(cert_store: CertificateStore, json_format: bool):

    tree = cert_store.list()

    if json_format:
        print(json.dumps(tree, default=tree.transform))
    else:
        print(tree.format_string(include_leaves=False,
                                 include_root=False, compact=True))


def get_cert(cert_store: CertificateStore, cert_path: str):
    entry = CertificateStoreEntryImpl(
        details=get_certificate_details(cert_path),
        certificate=None)
    try:
        cert_entry = cert_store.get(entry)
    except CertificateEntryNotFoundException as e:
        exit(e)

    print(str(cert_entry.certificate.public_bytes(), 'utf-8'))


def delete_cert(cert_store: CertificateStore, cert_path: str):
    entry = CertificateStoreEntryImpl(
        details=get_certificate_details(cert_path),
        certificate=None)
    cert_store.remove(entry)
