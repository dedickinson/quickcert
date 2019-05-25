import typing
from typing import Dict, List, NamedTuple

from cryptography import x509
from interface import implements

from ..interfaces import (Certificate, CertificateDetails,
                          CertificateStoreEntry, CertificateType, PrivateKey,
                          PublicKey)

from .x509_minter import X509_CERTIFICATE_TYPES


class CertificateDetailsImpl(implements(CertificateDetails)):

    def __init__(self,
                 name: str,
                 issuer: CertificateDetails,
                 certificate_type: CertificateType):
        self._name = name
        self._issuer = issuer
        self._certificate_type = certificate_type

    @property
    def name(self) -> str:
        return self._name

    @property
    def issuer(self) -> 'CertificateDetails':
        return self._issuer

    @property
    def certificate_type(self) -> CertificateType:
        return self._certificate_type

    @classmethod
    def determine_certificate_details(
            cls, cert_path: str) -> CertificateDetails:
        def _parse_certificate_path(elements: List[str]) -> Dict[str, str]:
            if len(elements) == 1:
                # This is a shortcut and assumes a root cert is provided
                result = {'root': elements[0]}
            elif len(elements) == 2 and elements[0] in ['server', 'client']:
                # This is a cert that's being "self issued"
                result = {elements[0]: elements[1]}
            else:
                del elements[0]
                result = {k: v for k, v in zip(*[iter(elements)] * 2)}

            return result

        elements = cert_path.split('/')
        path_elements = _parse_certificate_path(elements)

        if 'server' in path_elements:
            cert_name = path_elements['server']
            cert_type = X509_CERTIFICATE_TYPES['server']
        elif 'client' in path_elements:
            cert_name = path_elements['client']
            cert_type = X509_CERTIFICATE_TYPES['client']
        elif 'intermediate' in path_elements:
            cert_name = path_elements['intermediate']
            cert_type = X509_CERTIFICATE_TYPES['intermediate']
        elif 'root' in path_elements:
            cert_name = path_elements['root']
            cert_type = X509_CERTIFICATE_TYPES['root']
        else:
            raise ValueError(
                "The certificate type could not be determined ({})".format(
                    path_elements.keys()))

        if len(elements) > 2:
            cert_issuer = cls.determine_certificate_details(
                cert_path.rsplit('/', 2)[0])
        else:
            cert_issuer = None

        return CertificateDetailsImpl(
            name=cert_name,
            certificate_type=cert_type,
            issuer=cert_issuer
        )


class CertificateStoreEntryImpl(implements(CertificateStoreEntry)):

    def __init__(self,
                 certificate: Certificate,
                 details: CertificateDetails):

        self._details = details
        self._certificate = certificate

    @property
    def certificate(self) -> str:
        return self._certificate

    @property
    def details(self) -> CertificateDetails:
        return self._details
