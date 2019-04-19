


def configure_cli_key_parser(parser):
    parser_create = parser.add_parser(
        'create_cert',
        help='Create a certificate')

    parser_create.add_argument('cert_type', type=str,
                                choices=['root', 'intermediate',
                                        'server', 'client'],
                                help='the type of certificate')

    parser_create.add_argument('name', type=str,
                                help='the certificate name')

    parser_create.add_argument('--key-size', type=str,
                                required=False,
                                default=QuickCertCli.default_key_size,
                                help='the key size')

    parser_create_passphrase_group = parser_create.add_mutually_exclusive_group(
        required=False)

    parser_create_passphrase_group.add_argument(
        '--passphrase',
        action='store_const',
        const=True,
        help='If flagged you\'ll be asked to provide a passphrase for the key')

    parser_create_passphrase_group.add_argument(
        '--no-passphrase',
        action='store_const',
        const=True,
        help='If flagged no passphrase is used for the key')

    parser_create_passphrase_group.add_argument(
        '--random-passphrase',
        action='store_const',
        const=True,
        help='If flagged a random passphrase is created for the key (default)')

    subparsers.add_parser(
        'list',
        help='Lists the certificates in the certificate store')

    parser_info = subparsers.add_parser(
        'info',
        help='Get information about a certificate')

    parser_info.add_argument(
        'cert_path',
        type=str,
        help='The type/name of the cert - e.g. server/www.example.com')

def create_cert(self, cert_type: str, name: str, passphrase: str):
    self.cert_store.create_certificate(cert_type, name, passphrase)

def init_cert_store(self):
    self.cert_store.initialise()

def list_certs(self):
    self.cert_store.list()

def get_info(self, cert_path: str):
    self.cert_store.info(cert_path)