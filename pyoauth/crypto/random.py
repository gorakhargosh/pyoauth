#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Random number and string generation utilities.
#
# Released into public domain.

"""
:module: pyoauth.crypto.random
:synopsis: Random number and string generation utilities.

Functions:
----------
.. autofunction:: generate_random_bytes
.. autofunction:: generate_random_long
.. autofunction:: generate_random_uint_string
.. autofunction:: generate_random_hex_string
.. autofunction:: generate_random_bytearray
"""

import os
from pyoauth.types import byte_count, bit_count
from pyoauth.types.bytearray import \
    bytearray_to_long, bytes_to_bytearray
from pyoauth.types.codec import\
    bytes_to_base64, \
    bytes_to_decimal, \
    bytes_to_hex


try:
    # Operating system unsigned random.
    os.urandom(1)
    def generate_random_bytes(count):
        """
        Generates a random byte string with ``count`` bytes.

        :param count:
            Number of bytes.
        :returns:
            Random byte string.
        """
        return os.urandom(count)
except Exception:
    try:
        urandom_device = open("/dev/urandom", "rb")
        def generate_random_bytes(count):
            """
            Generates a random byte string with ``count`` bytes.

            :param count:
                Number of bytes.
            :returns:
                Random byte string.
            """
            return urandom_device.read(count)
    except IOError:
        #Else get Win32 CryptoAPI PRNG
        try:
            import win32prng
            def generate_random_bytes(count):
                """
                Generates a random byte string with ``count`` bytes.

                :param count:
                    Number of bytes.
                :returns:
                    Random byte string.
                """
                s = win32prng.generate_random_bytes(count)
                assert len(s) == count
                return s
        except ImportError:
            # What the fuck?!
            def generate_random_bytes(count):
                """
                Should generate a random byte string with ``count`` bytes
                but barfs instead.

                :param count:
                    Number of bytes.
                :returns:
                    WTF.
                """
                raise NotImplementedError("What the fuck?! No PRNG available.")


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


_BYTE_BASE_ENCODING_MAP = {
    10: bytes_to_decimal,
    16: bytes_to_hex,
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
    if bit_strength % 8 or bit_strength <= 0:
        raise ValueError("This function expects a bit strength: got `%r`." % (bit_strength, ))
    #num_bytes = bit_strength / 8
    num_bytes = bit_strength >> 3

    random_bytes = generate_random_bytes(num_bytes)
    try:
        return _BYTE_BASE_ENCODING_MAP[base](random_bytes)
    except KeyError:
        raise ValueError("Base must be one of %r" % (_BYTE_BASE_ENCODING_MAP.keys(), ))


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
    return bytes_to_hex(generate_random_bytes(length/2))


def generate_random_bytearray(count):
    """
    Generates a random byte array.

    :param count:
        The number of bytes.
    :returns:
        A random byte array.
    """
    return bytes_to_bytearray(generate_random_bytes(count))
