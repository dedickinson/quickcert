from quickcert.implementations import RsaKeyMinter, CONST_DEFAULT_ENCRYPTION_PADDING
import pytest


def test_basic():
    minter = RsaKeyMinter()

    for _ in range(20):
        key = minter.mint()
        assert(key)
        assert(key.public_key)


@pytest.mark.parametrize("key_size", [1024, 2048, 4096])
def test_key_sizes(key_size):
    minter = RsaKeyMinter()

    key = minter.mint(key_size=key_size)
    assert(key.key_size == key_size)

    assert(key.public_key().key_size == key_size)


@pytest.mark.parametrize("key_size", [1024, 2048, 4096])
def test_mint_args(key_size):
    minter = RsaKeyMinter()

    mint_args = minter.prepare_mint_args(key_size=key_size)

    key = minter.mint(**mint_args)
    assert(key.key_size == key_size)

    assert(key.public_key().key_size == key_size)


@pytest.mark.parametrize("input", ['mittens',
                                   'jknsdvkjsdui48y3489*&@#$&^*#%',
                                   '',
                                   '123456789'])
def test_key_encryption(input):
    minter = RsaKeyMinter()

    key = minter.mint()
    public_key = key.public_key()

    encrypted = public_key.encrypt(
        plaintext=str.encode(input), padding=CONST_DEFAULT_ENCRYPTION_PADDING)

    decrypted = key.decrypt(ciphertext=encrypted,
                            padding=CONST_DEFAULT_ENCRYPTION_PADDING)

    assert(decrypted == str.encode(input))
