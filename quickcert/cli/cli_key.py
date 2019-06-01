import sys
import argparse
import json

from ..interfaces import PrivateKey, KeyStore, KeyMinter


def configure_cli_key_parser(
        parser: argparse.ArgumentParser,
        default_key_size: int = 2048):
    """Configures the arg parser for certificate-related activities

    :param parser: the base argparser to add to
    :type parser: argparse.ArgumentParser
    :param default_key_size: sets the default key size for all relevant commands
        , defaults to 2048
    :type default_key_size: int, optional
    """

    parser_create_key = parser.add_parser(
        'create-key',
        help='Create a key',
        description='You can set a password using --password, use no password with --no-password, or be prompted for a password',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser_create_key.add_argument('name', type=str,
                                   help='the key name')

    parser_create_key.add_argument('--key-size', type=str,
                                   required=False,
                                   default=default_key_size,
                                   help='the key size')

    parser_create_key.add_argument(
        '--no-store',
        action='store_true',
        help='don\'t store the key, just send it to stdout')

    parser_create_key_pwdgrp = parser_create_key.add_mutually_exclusive_group(
        required=False)

    parser_create_key_pwdgrp.add_argument('--password',
                                          type=str,
                                          help='the password for the key')

    parser_create_key_pwdgrp.add_argument(
        '--no-password',
        action='store_true',
        help="don't use password for the key")

    list_keys = parser.add_parser(
        'list-keys',
        help='Lists keys in the store',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    list_keys.add_argument('--json',
                           action='store_true')

    parser_delete_key = parser.add_parser(
        'delete-key',
        help='Delete a key from the store',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser_delete_key.add_argument('key_name', type=str,
                                   help='the key name')

    parser_get_key = parser.add_parser(
        'get-key',
        help='Get a key from the store',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser_get_key.add_argument('key_name', type=str,
                                help='the key name')

    parser_get_key_pwdgrp = parser_get_key.add_mutually_exclusive_group(
        required=False)

    parser_get_key_pwdgrp.add_argument('--password',
                                       type=str,
                                       help='the password for the key')

    parser_get_key_pwdgrp.add_argument('--no-password',
                                       action='store_true',
                                       help="don't use password for the key")


def create_key(
        key_minter: KeyMinter,
        key_store: KeyStore,
        key_name: str,
        key_size: int,
        password: str,
        store: bool = True):
    """Creates a key and stores it

    :param key_minter: creates the key
    :type key_minter: KeyMinter
    :param key_store: stores the key
    :type key_store: KeyStore
    :param key_name: the name of the key
    :type key_name: str
    :param key_size: the key size
    :type key_size: int
    :param password: the password for the key
    :type password: str
    :param store: if set to False, the key will just be sent to stdout and not stored
        , defaults to True
    :type store: bool
    """

    key_minter.prepare_mint_args(key_size=key_size)
    key: PrivateKey = key_minter.mint()
    if store:
        if (key_store.exists(key_name)):
            sys.exit("Error: Key already exists")
        else:
            key_store.add(key=key, key_name=key_name, password=password)
    else:
        print(str(key.public_key.serialize(), 'utf-8'))


def list_keys(key_store: KeyStore, json_format: bool = False):
    """Lists the keys in the store

    :param key_store: the key store
    :type key_store: KeyStore
    :param json_format: output in json format
    :type json_format: bool
    """
    if json_format:
        print(json.dumps({
            'keys': key_store.list()
        }))
    else:
        for key in key_store.list():
            print('\U0001F5DD {}'.format(key))


def delete_key(key_store: KeyStore, key_name: str):
    """Delete the key from the store

    :param key_store: the key store
    :type key_store: KeyStore
    :param key_name: the key name
    :type key_name: str
    """
    key_store.remove(key_name)


def get_key(
        key_store: KeyStore,
        key_name: str,
        password: str = None,
        private: bool = False):
    """Gets the key from the key store

    By default the public key is returned

    :param key_store: the key store
    :type key_store: KeyStore
    :param key_name: the key name
    :type key_name: str
    :param password: the key's password, defaults to None
    :type password: str, optional
    :param private: return the private key if True, defaults to False
    :type private: bool, optional
    """
    key: PrivateKey = key_store.get(key_name, password)

    if not key:
        exit("Error: key not found")

    print(str(key.public_key.serialize(), 'utf-8'))
