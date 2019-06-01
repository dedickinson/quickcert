import argparse
import string

from ..interfaces import PasswordGenerator


def configure_cli_random_parser(parser):
    parser_genrnd = parser.add_parser(
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
        default=string.ascii_uppercase +
        string.ascii_lowercase +
        string.digits +
        '_$#%-!',
        required=False,
        help='the character set to use in the password')


def get_random(
        password_generator: PasswordGenerator,
        length: int,
        charset: str) -> str:
    """Generate a random string of desired length from a set of characters

    :param password_generator: A password generator object
    :type password_generator: PasswordGenerator
    :param length: The password length
    :type length: int
    :param charset: The set of characters to draw from
    :type charset: str
    :return: a random string (that could be handy for a password)
    :rtype: str
    """

    print(password_generator.generate_password(
        length=length, selection=charset))
