#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Random number and string generation utilities.


import binascii
from pyoauth.types import bytes
from pyoauth.crypto.utils.prng import generate_random_bytes
from pyoauth.crypto.utils import bit_count, byte_count
from pyoauth.crypto.utils.bytearray import bytearray_random, bytearray_to_long


def generate_random_number(low, high):
    if low >= high:
        raise AssertionError()
    howManyBits = bit_count(high)
    howManyBytes = byte_count(high)
    lastBits = howManyBits % 8
    while 1:
        byte_array = bytearray_random(howManyBytes)
        if lastBits:
            byte_array[0] = byte_array[0] % (1 << lastBits)
        n = bytearray_to_long(byte_array)
        if n >= low and n < high:
            return n


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
    value = binascii.b2a_hex(generate_random_bytes(n_bytes))
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
    return binascii.b2a_hex(generate_random_bytes(length/2))

