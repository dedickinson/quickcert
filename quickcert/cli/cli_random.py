import argparse
import string


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
        default=string.ascii_uppercase + string.ascii_lowercase + string.digits + '_$#%-!',
        required=False,
        help='the character set to use in the password'
    )


def get_random(password_generator, length: int, charset: str) -> str:
    print(password_generator.generate_password(
        length=length, selection=charset))
