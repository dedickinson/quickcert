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
    """Checks that the password has uppercase, lowercase, number and symbol characters"""

    def validate(self, password: str) -> bool:
        """See :class:`PasswordValidator <quickcert.interfaces.PasswordValidator>`"""
        pset = set(password)

        if (pset & _lowercase_set) and (pset & _uppercase_set) and (
                pset & _numeric_set) and (pset & _symbol_set):
            return True

        return False


class BasicPasswordGenerator(implements(PasswordGenerator)):

    def generate_password(
            self,
            length: int = 32,
            selection: str = ''.join(_password_set),
            validator: PasswordValidator = BasicPasswordValidator()) -> str:
        """Generates a random password

        :param int length: number of characters in the password (default: {32})
        :param str selection: string of characters to select from (default: {string.ascii_uppercase+string.ascii_lowercase+string.digits+'_$#%-!'})
        :param PasswordValidator validator: a validator (default: :class:`BasicPasswordValidator <quickcert.implementations.password_generator.BasicPasswordValidator>`)
        :return: a password with length characters, derived from the selection
        :rtype: str
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
