#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:module: pyoauth.crypto.utils.bytearray
:synopsis: Byte arrays.

Functions:
----------
.. autofunction:: bytearray_create
.. autofunction:: bytearray_create_zeros
.. autofunction:: bytearray_concat
.. autofunction:: bytearray_to_string
.. autofunction:: bytearray_from_string
.. autofunction:: bytearray_random
.. autofunction:: bytearray_to_long
.. autofunction:: bytearray_from_long
"""

from array import array
from pyoauth.crypto.utils import byte_count
from pyoauth.crypto.utils.random import generate_random_bytes


def bytearray_create(sequence):
    """
    Creates a byte array from a given sequence.

    :param sequence:
        The sequence from which a byte array will be created.
    :returns:
        A byte array.
    """
    return array('B', sequence)


def bytearray_create_zeros(count):
    """
    Creates a zero-filled byte array of with ``count`` bytes.

    :param count:
        The number of zero bytes.
    :returns:
        Zero-filled byte array.
    """
    return array('B', [0] * count)


def bytearray_concat(arr1, arr2):
    """
    Concatenates two byte arrays.

    :param arr1:
        Byte array 1
    :param arr2:
        Byte array 2
    :returns:
        Concatenated byte array.
    """
    return arr1 + arr2


def bytearray_to_string(arr):
    """
    Converts a byte array into a string.

    :param arr:
        The byte array.
    :returns:
        String.
    """
    return arr.tostring()


def bytearray_from_string(value):
    """
    Converts a string into a byte array.

    :param value:
        String value.
    :returns:
        Byte array.
    """
    return bytearray_create_zeros(0).fromstring(value)


def bytearray_random(count):
    """
    Generates a random byte array.

    :param count:
        The number of bytes.
    :returns:
        A random byte array.
    """
    return bytearray_from_string(generate_random_bytes(count))


def bytearray_to_long(byte_array):
    """
    Converts a byte array to long.

    :param byte_array:
        The byte array.
    :returns:
        Long.
    """
    total = 0L
    multiplier = 1L
    for count in range(len(byte_array)-1, -1, -1):
        byte = byte_array[count]
        total += multiplier * byte
        multiplier *= 256
    return total


def bytearray_from_long(n):
    """
    Converts a long into a byte array.

    :param n:
        Long value
    :returns:
        Long.
    """
    bytes_count = byte_count(n)
    byte_array = bytearray_create_zeros(bytes_count)
    for count in range(bytes_count - 1, -1, -1):
        byte_array[count] = int(n % 256)
        n >>= 8
    return byte_array
