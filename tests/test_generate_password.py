import string

import pytest

from quickcert import utils


@pytest.mark.parametrize("ln", [1, 8, 12, 24, 32, 7, 11, 0])
def test_generate_password_length(ln):
    assert(len(utils.generate_password(length=ln)) == ln)


@pytest.mark.parametrize("ln", [-1, -8, -0])
def test_generate_password_negative_length(ln):
    assert(len(utils.generate_password(length=ln)) == 0)


@pytest.mark.parametrize("ln", [1, 8, 12, 24, 32, 7, 11, 0])
def test_generate_password_default_characters(ln):
    default_chars = string.ascii_uppercase + \
        string.ascii_lowercase + string.digits + '_$#%-!'

    # Try this a few times to make sure
    for _ in range(25):
        password = utils.generate_password(length=ln)
        for ch in password:
            assert(ch in default_chars)


@pytest.mark.parametrize("selection", [string.ascii_lowercase,
                                       string.ascii_uppercase,
                                       string.digits,
                                       string.punctuation,
                                       string.printable,
                                       'lkdgioghoisg89438945jndgfioKJHUII%YF*('
                                       ])
def test_generate_password_characters(selection):
    password = utils.generate_password(selection=selection)

    for ch in password:
        assert(ch in selection)
