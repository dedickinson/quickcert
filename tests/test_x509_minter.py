from quickcert.implementations import (RsaKeyMinter, x509CertificateMinter,
                                       x509CertificateNameAttributes,
                                       x509ClientCertificateType,
                                       x509IntermediateCertificateType,
                                       x509RootCertificateType,
                                       x509ServerCertificateType)


def test_cert_type_names():
    assert(x509RootCertificateType().name == 'root')
    assert(x509IntermediateCertificateType().name == 'intermediate')
    assert(x509ServerCertificateType().name == 'server')
    assert(x509ClientCertificateType().name == 'client')


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
    assert(certificate.public_key.public_numbers()
           == key.public_key().public_numbers())

    assert(certificate.issuer.common_name == attributes.common_name)
    assert(certificate.issuer.locality == attributes.locality)
    assert(certificate.issuer.organization == attributes.organization)
    assert(certificate.issuer.state == attributes.state)
    assert(certificate.issuer.country == attributes.country)

    assert(certificate.subject.common_name == attributes.common_name)
    assert(certificate.subject.locality == attributes.locality)
    assert(certificate.subject.organization == attributes.organization)
    assert(certificate.subject.state == attributes.state)
    assert(certificate.subject.country == attributes.country)
