#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import argparse
import os
import sys
import string
from pathlib import Path
from getpass import getpass

import argcomplete
from appdirs import user_config_dir, user_data_dir

from .__version__ import (__copyright__, __description__, __license__,
                          __title__, __version__)
from .interfaces import PrivateKey
from .implementations import BasicPasswordGenerator, FilesystemKeyStore, RsaKeyMinter


class QuickCertCli:

    default_key_size: int = 2048
    ENV_CONFIG_DIR = 'QCERT_CONFIG_DIR'
    ENV_DATA_DIR = 'QCERT_DATA_DIR'

    def __init__(self):
        self.configuration_dir = os.getenv(
            QuickCertCli.ENV_CONFIG_DIR, user_config_dir())

        self.data_dir = Path(os.getenv(QuickCertCli.ENV_DATA_DIR, user_data_dir()),'quickcert')

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

        parser.add_argument('--version', action='version',
                            version='{} {}'.format(__title__, __version__))

        parser.add_argument(
            '--certificate_store', **shared_arg_dict['certificate_store'])

        parser.add_argument(
            '--config_dir', **shared_arg_dict['config_dir'])

        subparsers = parser.add_subparsers(title='commands',
                                           dest='cmd',
                                           help='sub-command help')

        parser_init = subparsers.add_parser(
            'init',
            help='Initialises the certificate store')

        parser_list = subparsers.add_parser(
            'list',
            help='Lists the certificates in the certificate store')

        parser_info = subparsers.add_parser(
            'info',
            help='Get information about a certificate')

        parser_info.add_argument(
            'cert_path',
            type=str,
            help='The type/name of the cert - e.g. server/www.example.com')

        parser_create_key = subparsers.add_parser(
            'create_key',
            help='Create a key',
            description='You can set a password using --password, use no password with --no-password, or be prompted for a password',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        parser_create_key.add_argument('name', type=str,
                                       help='the key name')

        parser_create_key.add_argument('--key-size', type=str,
                                       required=False,
                                       default=QuickCertCli.default_key_size,
                                       help='the key size')

        parser_create_key.add_argument('--no-store',
                                       action='store_true',
                                       help='don\'t store the key, just send it to stdout')

        parser_create_key_pwdgrp = parser_create_key.add_mutually_exclusive_group(required=False)

        parser_create_key_pwdgrp.add_argument('--password',
                                       type=str,
                                       help='the password for the key')

        parser_create_key_pwdgrp.add_argument('--no-password',
                                       action='store_true', 
                                       help="don't use password for the key")

        parser_create = subparsers.add_parser(
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

        parser_pubkey = subparsers.add_parser(
            'public_key',
            help='Outputs the public key from the requested key')

        parser_pubkey.add_argument('name', type=str,
                                   help='the key name')

        parser_genrnd = subparsers.add_parser(
            'random',
            help='Outputs a random string',
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        parser_genrnd.add_argument(
            '--length',
            type=int,
            default=32,
            required=False,
            help='the password length'
        )

        parser_genrnd.add_argument(
            '--charset',
            type=str,
            default=string.ascii_uppercase + string.ascii_lowercase + string.digits + '_$#%-!',
            required=False,
            help='the character set to use in the password'
        )

        return parser

    def create_key(self, key_name: str, key_size: int, password: str, store: bool):
        self.key_minter.prepare_mint_args(key_size=key_size)
        key: PrivateKey = self.key_minter.mint()
        if store:
            if (self.key_store.exists(key_name)):
                sys.exit("Error: Key already exists")
            else:
                self.key_store.add(key=key, key_name=key_name, password=password)
        else:
            print(str(key.serialize(password),'utf-8'))

    def create_cert(self, cert_type: str, name: str, passphrase: str):
        self.cert_store.create_certificate(cert_type, name, passphrase)

    def init_cert_store(self):
        self.cert_store.initialise()

    def list_certs(self):
        self.cert_store.list()

    def get_info(self, cert_path: str):
        self.cert_store.info(cert_path)

    def get_random(self, length: int, charset: str) -> str:
        print(self.password_generator.generate_password(
            length=length, selection=charset))

    def prompt_for_password(self) -> str:

        p1 = getpass(prompt='Enter a password: ')
        p2 = getpass(prompt='Re-enter a password: ')

        if p1 == p2:
            return p1
        else:
            print("Passwords don't match")
            return self.prompt_for_password()

    def handle_request(self, args):
        if args.cmd == 'create_cert':
            if args.passphrase:
                passphrase = input('Please provide a passphrase: ')
            """ elif args.no_passphrase:
                passphrase = ''
            else:
                passphrase = produce_amount_keys(1)[0] """

            self.create_cert(args.cert_type, args.name, passphrase)
        elif args.cmd == 'create_key':
            if args.no_password:
                password = None
            elif args.password:
                password = args.password
            else:
                password = self.prompt_for_password()

            self.create_key(key_size=args.key_size,
                            key_name=args.name,
                            password=password,
                            store=(not args.no_store))

        elif args.cmd == 'init':
            self.init_cert_store()
        elif args.cmd == 'list':
            self.list_certs()
        elif args.cmd == 'info':
            self.get_info(args.cert_path)
        elif args.cmd == 'random':
            self.get_random(args.length, args.charset)

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
    print("x")
    cli = QuickCertCli()
    cli.run
