#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import os
import sys
import string
from pathlib import Path

import argcomplete
from appdirs import user_config_dir, user_data_dir

from ..__version__ import (__copyright__, __description__, __license__,
                           __title__, __version__)
from ..interfaces import PrivateKey
from ..implementations import BasicPasswordGenerator, FilesystemKeyStore, RsaKeyMinter, FilesystemCertificateStore, x509CertificateMinter

from .cli_cert import configure_cli_cert_parser, list_certs, create_cert, delete_cert, get_cert
from .cli_key import configure_cli_key_parser, create_key, list_keys, delete_key, get_key
from .cli_random import configure_cli_random_parser, get_random
from .cli_util import prompt_for_password


class QuickCertCli:

    ENV_CONFIG_DIR = 'QCERT_CONFIG_DIR'
    ENV_DATA_DIR = 'QCERT_DATA_DIR'

    def __init__(self):
        self.configuration_dir = Path(
            os.getenv(QuickCertCli.ENV_CONFIG_DIR, user_config_dir()), __title__)

        self.data_dir = Path(
            os.getenv(QuickCertCli.ENV_DATA_DIR, user_data_dir()), __title__)

        self.password_generator = BasicPasswordGenerator()
        self.key_store = FilesystemKeyStore()
        self.key_minter = RsaKeyMinter()

        self.cert_store = FilesystemCertificateStore()
        self.cert_minter = x509CertificateMinter()

    def initialise(self):
        # TODO: Log this
        self.data_dir.mkdir(mode=0o700, exist_ok=True)
        self.key_store.initialise(dir=self.data_dir)
        self.cert_store.initialise(dir=self.data_dir)

    def create_argparser(self):

        shared_arg_dict = {
            'data_dir': {
                'default': self.data_dir,
                'help': 'The base directory for key and certificate storage. Can also be set using the {} environment variable'.format(QuickCertCli.ENV_DATA_DIR)
            },
            'config_dir': {
                'default': self.configuration_dir,
                'help': 'The configuration file path. Can also be set using the {} environment variable'.format(QuickCertCli.ENV_CONFIG_DIR)
            }
        }

        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            fromfile_prefix_chars='@',
            description=__description__,
            epilog="This application is not intended for production use.")

        parser.add_argument('--version', '-v', action='version',
                            version='{} {}'.format(__title__, __version__))

        parser.add_argument(
            '--data-dir', **shared_arg_dict['data_dir'])

        # parser.add_argument(
        #   '--config-dir', **shared_arg_dict['config_dir'])

        subparsers = parser.add_subparsers(title='commands',
                                           dest='cmd',
                                           help='sub-command help')

        # subparsers.add_parser(
        #    'init',
        #    help='Initialises the cert & key store')

        subparsers.add_parser(
            'config',
            help='Displays configuration')

        configure_cli_random_parser(subparsers)
        configure_cli_key_parser(subparsers)
        configure_cli_cert_parser(subparsers)

        return parser

    def display_configuration(self):
        print("Base directory: {}".format(self.data_dir))
        print("Key store: {}".format(self.key_store.dir))
        print("Certificate store: {}".format(self.cert_store.dir))

    def handle_request(self, args):
        if args.data_dir:
            self.data_dir = Path(args.data_dir)

        self.initialise()

        if args.cmd == 'config':
            self.display_configuration()
        elif args.cmd == 'random':
            get_random(self.password_generator, args.length, args.charset)
        elif args.cmd == 'list_keys':
            list_keys(self.key_store)
        elif args.cmd == 'delete_key':
            delete_key(key_store=self.key_store,
                       key_name=args.key_name)
        elif args.cmd == 'get_key':
            get_key(key_store=self.key_store,
                    key_name=args.key_name)
        elif args.cmd == 'create_key':
            if args.no_password:
                password = None
            elif args.password:
                password = args.password
            else:
                password = prompt_for_password()

            create_key(key_minter=self.key_minter,
                       key_store=self.key_store,
                       key_size=args.key_size,
                       key_name=args.name,
                       password=password,
                       store=(not args.no_store))
        elif args.cmd == 'create_cert':
            if args.no_password:
                password = None
            elif args.password:
                password = args.password
            else:
                password = prompt_for_password()

            create_cert(
                cert_minter=self.cert_minter,
                cert_store=self.cert_store,
                key_store=self.key_store,
                cert_path=args.cert_path,
                common_name=args.common_name,
                key_name=args.key_name,
                key_password=password,
                country=args.country,
                state=args.state,
                locality=args.locality,
                organization=args.organization,
                store=(not args.no_store)
            )
        elif args.cmd == 'list_certs':
            list_certs(cert_store=self.cert_store)
        elif args.cmd == 'get_cert':
            get_cert(cert_store=self.cert_store,
                       cert_path=args.cert_path)
        elif args.cmd == 'delete_cert':
            delete_cert(cert_store=self.cert_store,
                        cert_path=args.cert_path)
        else:
            sys.exit("Unknown command")

    def run(self):
        parser = self.create_argparser()

        # Refer to https://github.com/kislyuk/argcomplete
        argcomplete.autocomplete(parser)

        args = parser.parse_args()

        if not args.cmd:
            parser.print_help()
            sys.exit(0)

        try:
            self.handle_request(args)
        except KeyboardInterrupt:
            sys.exit("Interrupted")


if __name__ == "__main__":
    cli = QuickCertCli()
    cli.run
