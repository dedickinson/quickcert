import string
import secrets

from interface import implements

from ..interfaces import PasswordGenerator, PasswordValidator

_lowercase_set = set(string.ascii_lowercase)
_uppercase_set = set(string.ascii_uppercase)
_numeric_set = set(string.digits)
_symbol_set = set('_$#%-!^')
_password_set = _lowercase_set | _uppercase_set | _numeric_set | _symbol_set


class BasicPasswordValidator(implements(PasswordValidator)):

    def validate(self, password: str) -> bool:
        pset = set(password)

        if (pset & _lowercase_set) and (pset & _uppercase_set) and (pset & _numeric_set) and (pset & _symbol_set):
            return True

        return False


class BasicPasswordGenerator(implements(PasswordGenerator)):

    def generate_password(self, length: int = 32,
                          selection: str = ''.join(_password_set),
                          validator: PasswordValidator = BasicPasswordValidator()) -> str:
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

        while True:
            # TODO: This isn't a great approach for short passwords
            password = ''.join(secrets.choice(possible_chars)
                               for _ in range(length))
            if validator.validate(password):
                return password
