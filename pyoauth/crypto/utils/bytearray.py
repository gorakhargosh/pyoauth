#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:module: pyoauth.crypto.utils.bytearray
:synopsis: Byte arrays.
"""

import array

def bytearray_create(seq):
    return array.array('B', seq)

def bytearray_create_zeros(howMany):
    return array.array('B', [0] * howMany)

def bytearray_concat(a1, a2):
    return a1+a2

def bytearray_to_string(bytes):
    return bytes.tostring()

def bytearray_from_string(s):
    bytes = bytearray_create_zeros(0)
    bytes.fromstring(s)
    return bytes
