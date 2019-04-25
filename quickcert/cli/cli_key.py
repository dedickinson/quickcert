import sys
import argparse

from ..interfaces import PrivateKey, KeyStore, KeyMinter


def configure_cli_key_parser(parser, default_key_size: int = 2048):

    parser_create_key = parser.add_parser(
        'create_key',
        help='Create a key',
        description='You can set a password using --password, use no password with --no-password, or be prompted for a password',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser_create_key.add_argument('name', type=str,
                                   help='the key name')

    parser_create_key.add_argument('--key-size', type=str,
                                   required=False,
                                   default=default_key_size,
                                   help='the key size')

    parser_create_key.add_argument('--no-store',
                                   action='store_true',
                                   help='don\'t store the key, just send it to stdout')

    parser_create_key_pwdgrp = parser_create_key.add_mutually_exclusive_group(
        required=False)

    parser_create_key_pwdgrp.add_argument('--password',
                                          type=str,
                                          help='the password for the key')

    parser_create_key_pwdgrp.add_argument('--no-password',
                                          action='store_true',
                                          help="don't use password for the key")

    parser.add_parser(
        'list_keys',
        help='Lists keys in the store',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser_delete_key = parser.add_parser(
        'delete_key',
        help='Delete a key from the store',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser_delete_key.add_argument('key_name', type=str,
                                   help='the key name')

    parser_get_key = parser.add_parser(
        'get_key',
        help='Get a key from the store',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser_get_key.add_argument('key_name', type=str,
                                   help='the key name')


def create_key(key_minter: KeyMinter, key_store: KeyStore, key_name: str, key_size: int, password: str, store: bool):
    key_minter.prepare_mint_args(key_size=key_size)
    key: PrivateKey = key_minter.mint()
    if store:
        if (key_store.exists(key_name)):
            sys.exit("Error: Key already exists")
        else:
            key_store.add(key=key, key_name=key_name, password=password)
    else:
        print(str(key.public_key.serialize(), 'utf-8'))


def list_keys(key_store: KeyStore):
    for key in key_store.list():
        print(key)


def delete_key(key_store: KeyStore, key_name: str):
    key_store.remove(key_name)

def get_key(key_store: KeyStore, key_name: str, password=None, private=False):
    key: PrivateKey = key_store.get(key_name, password)

    if not key:
        exit("Error: key not found")

    print(str(key.public_key.serialize(), 'utf-8'))
