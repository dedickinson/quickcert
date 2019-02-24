from quickcert.implementations import (x509CertificateMinter,
                                       x509CertificateNameAttributes,
                                       x509ClientCertificateType,
                                       x509IntermediateCertificateType,
                                       x509RootCertificateType,
                                       x509ServerCertificateType,
                                       RsaKeyMinter)


def test_cert_types():
    assert(x509RootCertificateType())
    assert(x509IntermediateCertificateType())
    assert(x509ServerCertificateType())
    assert(x509ServerCertificateType())

    assert(x509CertificateMinter())


def test_basic_mint():
    minter = x509CertificateMinter()

    key_minter = RsaKeyMinter()
    key = key_minter.mint()

    attributes = x509CertificateNameAttributes(
            country_name='AU',
            state_name='Queensland',
            locality_name='Brisbane',
            organization_name='Test Co',
            common_name='example.com'
        )

    minter_args = minter.prepare_mint_args(
        certificate_type=x509RootCertificateType(),
        private_key=key,
        subject=attributes,
        issuer=attributes
    )

    certificate = minter.mint(**minter_args)

    assert(certificate)
    assert(certificate.public_key.public_numbers() == key.public_key().public_numbers())
    assert(certificate.issuer.common_name == attributes.common_name)
