from getpass import getpass


def prompt_for_password(prompt: str = 'Enter a password: ',
                        verify_prompt: str = 'Re-enter the password: ',
                        validate: bool = True) -> str:
    """ Utility for password prompts

    Allows for password validation. If the passwords don't match,
    the function is called again until the passwords match

    :param prompt: The first prompt, defaults to 'Enter a password: '
    :type prompt: str, optional
    :param verify_prompt: The validation prompt, defaults to 'Re-enter the password: '
    :type verify_prompt: str, optional
    :param validate: ``True`` if validation needed, ``False`` otherwise, defaults to True
    :type validate: bool, optional
    :return: The password entered by the user
    :rtype: str
    """

    p1 = getpass(prompt=prompt)

    if validate:
        p2 = getpass(prompt=verify_prompt)

        if p1 == p2:
            return p1
        else:
            print("Passwords don't match")
            return prompt_for_password()
    else:
        return p1
