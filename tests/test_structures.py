import pytest

from quickcert.implementations import (CONST_DEFAULT_ENCRYPTION_PADDING,
                                       RsaKeyMinter, x509CertificateMinter,
                                       x509CertificateNameAttributes,
                                       x509RootCertificateType)
from quickcert.implementations.structures import CertificateStoreEntryImpl
from quickcert.interfaces.key import PrivateKey


# @pytest.mark.skip(reason="not yet implemented")
def test_create_CertificateStoreEntryImpl():
    minter = x509CertificateMinter()

    key_minter = RsaKeyMinter()
    key: PrivateKey = key_minter.mint()

    attributes = x509CertificateNameAttributes(
        country_name='AU',
        state_name='Queensland',
        locality_name='Brisbane',
        organization_name='Test Co',
        common_name='example.com'
    )

    certificate_type = x509RootCertificateType()

    minter_args = minter.prepare_mint_args(
        certificate_type=certificate_type,
        private_key=key,
        subject=attributes,
        issuer=attributes
    )

    certificate = minter.mint(**minter_args)
    certificate_name = 'Test Certificate'

    entry = CertificateStoreEntryImpl(
        name=certificate_name,
        certificate_type=certificate_type,
        certificate=certificate,
        key=key
    )

    assert(entry.name == certificate_name)

    secret_message = b'hello, world'
    secret_ciphertext = key.public_key().encrypt(
        plaintext=secret_message, padding=CONST_DEFAULT_ENCRYPTION_PADDING)
    assert(entry.private_key.decrypt(ciphertext=secret_ciphertext,
                                     padding=CONST_DEFAULT_ENCRYPTION_PADDING) == secret_message)

    assert(entry.certificate_type.name == certificate_type.name)
