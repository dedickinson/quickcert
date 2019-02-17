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

    return ''.join(secrets.choice(selection) for _ in range(length))
