import os
import base64
import math
from itertools import islice, repeat, filterfalse

import numpy as np
from cryptography import x509
from cryptography.x509.oid import NameOID


def produce_amount_keys(amount_of_keys):
    # See:
    # https://stackoverflow.com/questions/48421142/fastest-way-to-generate-a-random-like-unique-string-with-random-length-in-python

    def unique_everseen(iterable, key=None):
        "List unique elements, preserving order. Remember all elements ever seen."
        # unique_everseen('AAAABBBCCDAABBB') --> A B C D
        # unique_everseen('ABBCcAD', str.lower) --> A B C D
        seen = set()
        seen_add = seen.add
        if key is None:
            for element in filterfalse(seen.__contains__, iterable):
                seen_add(element)
                yield element
        else:
            for element in iterable:
                k = key(element)
                if k not in seen:
                    seen_add(k)
                    yield element

    def gen_keys(
            _urandom=os.urandom,
            _encode=base64.b32encode,
            _randint=np.random.randint):
        # (count / math.log(256, 32)), rounded up, gives us the number of bytes
        # needed to produce *at least* count encoded characters
        factor = math.log(256, 32)
        input_length = [None] * 12 + \
            [math.ceil(l / factor) for l in range(12, 20)]
        while True:
            count = _randint(12, 20)
            yield _encode(_urandom(input_length[count]))[:count].decode('ascii')

    return list(islice(unique_everseen(gen_keys()), amount_of_keys))


def build_certificate_attributes(
        cls,
        country_name: str = '',
        state_name: str = '',
        locality_name: str = '',
        organization_name: str = '',
        common_name: str = '') -> x509.Name:

    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
