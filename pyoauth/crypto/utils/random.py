#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Random number and string generation utilities.
#
# Released into public domain.

"""
:module: pyoauth.crypto.utils.random
:synopsis: Random number and string generation utilities.

Functions:
----------
.. autofunction:: generate_random_long
.. autofunction:: generate_random_uint_string
.. autofunction:: generate_random_hex_string
"""

import binascii
from pyoauth.types import bytes
from pyoauth.crypto.utils.prng import generate_random_bytes
from pyoauth.crypto.utils import bit_count, byte_count, base64_encode
from pyoauth.crypto.utils.bytearray import generate_random_bytearray, bytearray_to_long


def generate_random_long(low, high):
    """
    Generates a random long integer.

    :param low:
        Low
    :param high:
        High
    :returns:
        Random long integer value.
    """
    if low >= high:
        raise ValueError("High must be greater than low.")
    num_bits = bit_count(high)
    num_bytes = byte_count(high)
    last_bits = num_bits % 8
    while 1:
        byte_array = generate_random_bytearray(num_bytes)
        if last_bits:
            byte_array[0] = byte_array[0] % (1 << last_bits)
        n = bytearray_to_long(byte_array)
        if n >= low and n < high:
            return n


def bytes_to_hex(byte_string):
    return binascii.b2a_hex(byte_string)

def bytes_to_base64(byte_string):
    return base64_encode(byte_string)

def bytes_to_decimal(byte_string):
    return bytes(int(bytes_to_hex(byte_string), 16))

_byte_base_encoding_map = {
    16: bytes_to_hex,
    10: bytes_to_decimal,
    64: bytes_to_base64
}
def generate_random_uint_string(bit_strength=64, base=10):
    """
    Generates a random ASCII-encoded unsigned integral number in decimal
    or hexadecimal representation.

    :param bit_strength:
        Bit strength.
    :param base:
        One of:
            1. 10 (default)
            2. 16
            3. 64
    :returns:
        A string representation of a randomly-generated ASCII-encoded
        hexadecimal/decimal-representation unsigned integral number
        based on the bit strength specified.
    """
    allowed_bases = (10, 16, 64)
    if bit_strength % 8 or bit_strength <= 0:
        raise ValueError("This function expects a bit strength: got `%r`." % (bit_strength, ))
    #num_bytes = bit_strength / 8
    num_bytes = bit_strength >> 3

    random_bytes = generate_random_bytes(num_bytes)
    try:
        return _byte_base_encoding_map[base](random_bytes)
    except KeyError:
        raise ValueError("Base must be one of %r" % (allowed_bases, ))


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
    return binascii.b2a_hex(generate_random_bytes(length/2))

