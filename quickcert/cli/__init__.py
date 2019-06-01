"""
CLI
---

The :mod:`cli <quickcert.cli>` module contains both the command line
implementation of QuickCert but also a range of helper functions.

.. autoclass:: QuickCertCli
    :members:

Certificates
~~~~~~~~~~~~

.. autofunction:: get_certificate_details
.. autofunction:: create_cert
.. autofunction:: get_cert
.. autofunction:: delete_cert
.. autofunction:: list_certs

Keys
~~~~

.. autofunction:: get_key
.. autofunction:: create_key
.. autofunction:: delete_key
.. autofunction:: list_keys

Utility
~~~~~~~

.. autofunction:: get_random

"""

from .cli import QuickCertCli

from .cli_cert import (get_certificate_details, create_cert,
                       get_cert, delete_cert, list_certs)

from .cli_key import (get_key, create_key, delete_key, list_keys)

from .cli_random import get_random
