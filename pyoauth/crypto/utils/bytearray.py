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

"""

from array import array

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
