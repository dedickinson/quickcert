import string
import secrets


def generate_password(length: int = 32,
                      selection: str = string.ascii_uppercase + string.ascii_lowercase + string.digits + '_$#%-!') -> str:
    """Generates a random password

    Keyword Arguments:
        length {int} -- number of characters in the password (default: {32})
        selection {str} -- string of characters to select from (default: {string.ascii_uppercase+string.ascii_lowercase+string.digits+'_$#%-!'})

    Returns:
        str -- a password with length characters, derived from the selection
    """

    if length <= 0:
        return ''

    possible_chars = ''.join(set(selection))

    return ''.join(secrets.choice(possible_chars) for _ in range(length))
