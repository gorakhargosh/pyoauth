#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Types for compatibility.
#
# ===================================================================
# The contents of this file are dedicated to the public domain. To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================


"""
:module: pyoauth.types.codec
:synopsis: Number representation codecs.


.. autofunction:: base64_decode
.. autofunction:: base64_encode
.. autofunction:: bytes_to_hex
.. autofunction:: hex_to_bytes
.. autofunction:: bytes_to_base64
.. autofunction:: base64_to_bytes
.. autofunction:: bytes_to_decimal
.. autofunction:: decimal_to_bytes
.. autofunction:: base64_to_bytearray
.. autofunction:: bytearray_to_base64
.. autofunction:: long_to_base64
.. autofunction:: base64_to_long
"""

import binascii
from pyoauth.types import bytes
from pyoauth.types.bytearray import bytes_to_bytearray, bytearray_to_bytes
from pyoauth.types.number import bytes_to_long, long_to_bytes


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


def bytes_to_hex(byte_string):
    """
    Converts a byte string to its hex representation.

    :param byte_string:
        Byte string.
    :returns:
        Hex-encoded byte string.
    """
    return binascii.b2a_hex(byte_string)


def hex_to_bytes(encoded):
    """
    Converts a hex byte string to its byte representation.

    :param encoded:
        Hex string.
    :returns:
        Byte string.
    """
    return binascii.a2b_hex(encoded)


def bytes_to_base64(byte_string):
    """
    Converts a byte string to its Base64 representation.
    (Mostly for consistency.)

    :param byte_string:
        Byte string.
    :returns:
        Base64-encoded byte string.
    """
    return base64_encode(byte_string)


def base64_to_bytes(encoded):
    """
    Decodes a base-64 encoded string into a byte string.

    :param encoded:
        Base-64 encoded byte string.
    :returns:
        byte string.
    """
    return base64_decode(encoded)


def bytes_to_decimal(byte_string):
    """
    Converts a byte string to its decimal representation.

    :param byte_string:
        Byte string.
    :returns:
        Decimal-encoded byte string.
    """
    #return bytes(int(bytes_to_hex(byte_string), 16))
    return bytes(bytes_to_long(byte_string))


def decimal_to_bytes(encoded):
    """
    Converts a decimal encoded string to its byte representation.

    :param encoded:
        Decimal encoded string.
    :returns:
        Byte string.
    """
    return long_to_bytes(long(encoded))


def long_to_base64(num):
    """
    Base-64 encodes a long.

    :param num:
        A long integer.
    :returns:
        Base-64 encoded byte string.
    """
    byte_string = long_to_bytes(num)
    return base64_encode(byte_string)


def base64_to_long(encoded):
    """
    Base-64 decodes a string into a long.

    :param encoded:
        The encoded byte string.
    :returns:
        Long value.
    """
    byte_string = base64_decode(encoded)
    return bytes_to_long(byte_string)


def base64_to_bytearray(encoded):
    """
    Converts a base-64 encoded value into a byte array.

    :param encoded:
        The base-64 encoded value.
    :returns:
        Byte array.
    """
    return bytes_to_bytearray(base64_decode(encoded))


def bytearray_to_base64(byte_array):
    """
    Base-64 encodes a byte array.

    :param byte_array:
        The byte array.
    :returns:
        Base-64 encoded byte array without newlines.
    """
    return base64_encode(bytearray_to_bytes(byte_array))
