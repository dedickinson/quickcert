from getpass import getpass


def prompt_for_password() -> str:

    p1 = getpass(prompt='Enter a password: ')
    p2 = getpass(prompt='Re-enter a password: ')

    if p1 == p2:
        return p1
    else:
        print("Passwords don't match")
        return prompt_for_password()
