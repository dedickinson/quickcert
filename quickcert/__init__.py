"""
quickcert
---------

Exceptions
~~~~~~~~~~
.. autoexception:: InvalidCertificateTypeException
.. autoexception:: CertificateEntryNotFoundException
.. autoexception:: CertificateAlreadyExistsException
.. autoexception:: IssuerDoesNotExistException

"""

import logging
from logging import NullHandler

from .__version__ import (__author__, __author_email__, __build__,
                          __copyright__, __description__, __license__,
                          __title__, __url__, __version__)

from .exceptions import (CertificateAlreadyExistsException,
                         CertificateEntryNotFoundException,
                         InvalidCertificateTypeException,
                         IssuerDoesNotExistException)

logging.getLogger(__name__).addHandler(NullHandler())
