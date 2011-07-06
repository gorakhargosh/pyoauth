#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Cryptographic utility functions.

import os
import math
import binascii
import hmac
from hashlib import sha1, md5


def sha1_digest(*inputs):
    """
    Calculates a SHA-1 digest of a variable number of inputs.

    :param inputs:
        A variable number of inputs for which the digest will be calculated.
    :returns:
        A byte string containing the SHA-1 message digest.
    """
    md = sha1()
    for i in inputs:
        md.update(i)
    return md.digest()


def sha1_hexdigest(*inputs):
    return binascii.b2a_hex(sha1_digest(*inputs))


def md5_digest(*inputs):
    """
    Calculates a MD5 digest of a variable number of inputs.

    :param inputs:
        A variable number of inputs for which the digest will be calculated.
    :returns:
        A byte string containing the MD5 message digest.
    """
    md = md5()
    for i in inputs:
        md.update(i)
    return md.digest()


def hmac_sha1_digest(key, data):
    return hmac.new(key, data, sha1).digest()


def hmac_sha1_base64(key, data):
    return binascii.b2a_base64(hmac_sha1_digest(key, data))[:-1]


def generate_random_uint_string(bit_strength=64, decimal=True):
    """
    Generates a random ASCII-encoded unsigned integral number in decimal
    or hexadecimal representation.

    :param bit_strength:
        Bit strength.
    :param decimal:
        ``True`` (default) if you want the decimal representation; ``False`` for
        hexadecimal.
    :returns:
        A string representation of a randomly-generated ASCII-encoded
        hexadecimal/decimal-representation unsigned integral number
        based on the bit strength specified.
    """
    if bit_strength % 8 or bit_strength <= 0:
        raise ValueError("This function expects a bit strength: got `%r`." % (bit_strength, ))
    n_bytes = bit_strength / 8
    value = binascii.b2a_hex(os.urandom(n_bytes))
    if decimal:
        value = bytes(int(value, 16))
    return value


def generate_random_hex_string(length=8):
    """
    Generates a random ASCII-encoded hexadecimal string of an even length.

    :param length:
        Length of the string to be returned. Default 32.
        The length MUST be a positive even number.
    :returns:
        A string representation of a randomly-generated hexadecimal string.
    """
    if length % 2 or length <= 0:
        raise ValueError("This function expects a positive even number length: got length `%r`." % (length, ))
    return binascii.b2a_hex(os.urandom(length/2))


def bit_count(n):
    if n==0:
        return 0
    s = "%x" % n
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    return int(math.floor(math.log(n, 2))+1)
