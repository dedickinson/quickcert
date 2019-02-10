#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK


class QuickCertCli:

    default_path: str = '~/.qcert'
    default_key_size: int = 2048
    prog_version = '0.1'

    def create_argparser(self):

        shared_arg_dict = {
            'certificate_store': {
                'default': QuickCertCli.default_path,
                'help': 'The cert store path'
            }
        }

        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            description='Lazy toolkit for creating certs')

        parser.add_argument('--version', action='version',
                            version=f'%(prog)s {QuickCertCli.prog_version}')

        parser = argparse.ArgumentParser(fromfile_prefix_chars='@')

        parser.add_argument(
            '--certificate_store', **shared_arg_dict['certificate_store'])

        subparsers = parser.add_subparsers(title='commands',
                                           dest='cmd',
                                           help='sub-command help')

        parser_init = subparsers.add_parser(
            'init',
            help='Initialises the certificate store')

        parser_list = subparsers.add_parser(
            'list',
            help='Lists the certificates in the certificate store')

        parser_list = subparsers.add_parser(
            'info',
            help='Get information about a certificate')

        parser_list.add_argument(
            'cert_path',
            type=str,
            help='The type/name of the cert - e.g. server/www.example.com')

        parser_create = subparsers.add_parser(
            'create',
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

        parser_pubkey = subparsers.add_parser(
            'public_key',
            help='Outputs the public key from the requested key')

        parser_pubkey.add_argument('name', type=str,
                                   help='the key name')

        parser_genrnd = subparsers.add_parser(
            'random',
            help='Outputs a random string')

        return parser

    def create_cert(self, cert_type: str, name: str, passphrase: str):
        self.cert_store.create_certificate(cert_type, name, passphrase)

    def init_cert_store(self):
        self.cert_store.initialise()

    def list_certs(self):
        self.cert_store.list()

    def get_info(self, cert_path: str):
        self.cert_store.info(cert_path)

    def get_random(self) -> str:
        print(produce_amount_keys(1)[0])

    def run(self):
        parser = self.create_argparser()

        # Refer to https://github.com/kislyuk/argcomplete
        argcomplete.autocomplete(parser)

        args = parser.parse_args()

        if not args.cmd:
            parser.print_help()
            quit()

        self.cert_store = CertificateStore(args.certificate_store)

        if args.cmd == 'create':
            if args.passphrase:
                passphrase = input('Please provide a passphrase: ')
            elif args.no_passphrase:
                passphrase = ''
            else:
                passphrase = produce_amount_keys(1)[0]

            self.create_cert(args.cert_type, args.name, passphrase)
        elif args.cmd == 'init':
            self.init_cert_store()
        elif args.cmd == 'list':
            self.list_certs()
        elif args.cmd == 'info':
            self.get_info(args.cert_path)
        elif args.cmd == 'random':
            self.get_random()
