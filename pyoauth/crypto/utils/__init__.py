#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Cryptographic utility functions.

"""
:module: pyoauth.crypto.utils
:synopsis: Cryptographic utility functions.

Functions:
----------
.. autofunction:: base64_decode
.. autofunction:: base64_encode
.. autofunction:: sha1_digest
.. autofunction:: sha1_hexdigest
.. autofunction:: sha1_base64_digest
.. autofunction:: md5_digest
.. autofunction:: md5_hexdigest
.. autofunction:: hmac_sha1_digest
.. autofunction:: hmac_sha1_base64_digest
.. autofunction:: bit_count
.. autofunction:: byte_count
.. autofunction:: bytes_to_long
.. autofunction:: long_to_bytes
"""

import math
import binascii
import hmac
from hashlib import sha1, md5


def base64_decode(encoded):
    """
    Decodes a base-64 encoded string into a byte string.

    :param encoded:
        Base-64 encoded byte string.
    :returns:
        byte string.
    """
    return binascii.a2b_base64(encoded)


def base64_encode(byte_string):
    """
    Encodes a byte string using Base 64 and removes the last new line character.

    :param byte_string:
        The byte string to encode.
    :returns:
        Base64 encoded string without newline characters.
    """
    return binascii.b2a_base64(byte_string)[:-1]


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
    """
    Calculates hexadecimal representation of the SHA-1 digest of a variable
    number of inputs.

    :param inputs;
        A variable number of inputs for which the digest will be calculated.
    :returns:
        Hexadecimal representation of the SHA-1 digest.
    """
    return binascii.b2a_hex(sha1_digest(*inputs))


def sha1_base64_digest(value):
    """
    Calculates Base-64-encoded SHA-1 digest of a variable
    number of inputs.

    :param inputs;
        A variable number of inputs for which the digest will be calculated.
    :returns:
        Base-64-encoded SHA-1 digest.
    """
    return base64_encode(sha1_digest(value))


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


def md5_hexdigest(*inputs):
    """
    Calculates hexadecimal representation of the MD5 digest of a variable
    number of inputs.

    :param inputs;
        A variable number of inputs for which the digest will be calculated.
    :returns:
        Hexadecimal representation of the MD5 digest.
    """
    return binascii.b2a_hex(md5_digest(*inputs))


def hmac_sha1_digest(key, data):
    """
    Calculates a HMAC SHA-1 digest.

    :param key:
        The key for the digest.
    :param data:
        The data for which the digest will be calculted.
    :returns:
        HMAC SHA-1 Digest.
    """
    return hmac.new(key, data, sha1).digest()


def hmac_sha1_base64_digest(key, data):
    """
    Calculates a base64-encoded HMAC SHA-1 signature.

    :param key:
        The key for the signature.
    :param data:
        The data to be signed.
    :returns:
        Base64-encoded HMAC SHA-1 signature.
    """
    return base64_encode(hmac_sha1_digest(key, data))


def bit_count(num):
    """
    Determines the number of bits in a long value.

    :param num:
        Long value.
    :returns:
        Returns the number of bits in the long value.
    """
    #if num == 0:
    #    return 0
    if not num:
        return 0
    s = "%x" % num
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    #return int(math.floor(math.log(n, 2))+1)


def byte_count(num):
    """
    Determines the number of bytes in a long.

    :param num:
        Long value.
    :returns:
        The number of bytes in the long integer.
    """
    #if num == 0:
    #    return 0
    if not num:
        return 0
    bits = bit_count(num)
    return int(math.ceil(bits / 8.0))

