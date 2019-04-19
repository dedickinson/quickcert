#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import os
import sys
import string
from pathlib import Path

import argcomplete
from appdirs import user_config_dir, user_data_dir

from .__version__ import (__copyright__, __description__, __license__,
                          __title__, __version__)
from .interfaces import PrivateKey
from .implementations import BasicPasswordGenerator, FilesystemKeyStore, RsaKeyMinter

from .cli_cert import configure_cli_key_parser
from .cli_key import configure_cli_key_parser, create_key, list_keys, delete_key, get_key
from .cli_random import configure_cli_random_parser, get_random
from .cli_util import prompt_for_password


class QuickCertCli:

    ENV_CONFIG_DIR = 'QCERT_CONFIG_DIR'
    ENV_DATA_DIR = 'QCERT_DATA_DIR'

    def __init__(self):
        self.configuration_dir = os.getenv(
            QuickCertCli.ENV_CONFIG_DIR, user_config_dir())

        self.data_dir = Path(
            os.getenv(QuickCertCli.ENV_DATA_DIR, user_data_dir()), 'quickcert')

        # TODO: Log this
        self.data_dir.mkdir(mode=0o700, exist_ok=True)

        self.password_generator = BasicPasswordGenerator()

        self.key_store = FilesystemKeyStore()
        self.key_store.initialise(dir=self.data_dir)
        self.key_minter = RsaKeyMinter()

    def create_argparser(self):

        shared_arg_dict = {
            'certificate_store': {
                'default': self.data_dir,
                'help': 'The certificate store path. Can also be set using the {} environment variable'.format(QuickCertCli.ENV_DATA_DIR)
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

        # parser.add_argument(
        #    '--certificate_store', **shared_arg_dict['certificate_store'])

        # parser.add_argument(
        #    '--config_dir', **shared_arg_dict['config_dir'])

        subparsers = parser.add_subparsers(title='commands',
                                           dest='cmd',
                                           help='sub-command help')

        subparsers.add_parser(
            'init',
            help='Initialises the certificate store')

        # configure_cli_cert_parser(subparsers)
        configure_cli_random_parser(subparsers)
        configure_cli_key_parser(subparsers)

        return parser

    def handle_request(self, args):

        if args.cmd == 'random':
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
