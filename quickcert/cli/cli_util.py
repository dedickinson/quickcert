from getpass import getpass


def prompt_for_password(prompt: str = 'Enter a password: ',
                        verify_prompt: str = 'Re-enter the password: ',
                        validate: bool = True) -> str:

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
