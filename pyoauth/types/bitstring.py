#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
:module: pyoauth.types.bitstring
:synopsis: Utilities for working with bit strings.
:author: Arne Roomann-Kurrik <kurrik@gmail.com>

Type conversion
---------------
.. autofunction:: bits_to_long
.. autofunction:: long_to_bitstring
"""

from pyoauth.types import bytes

try:
    # Check whether we have reduce as a built-in.
    reduce_test = reduce((lambda num1, num2: num1 + num2), [1, 2, 3, 4])
except Exception:
    # Python 3k
    from functools import reduce


def bits_to_long(bits):
    """
    Converts a bit sequence to a long value.

    :param bits:
        Bit sequence.
    :returns:
        Long value.
    """
    return reduce((lambda first, second: (first << 1) + second), bits)


def long_to_bitstring(num):
    """
    Converts a long into the bit string.

    :param num:
        Long value
    :returns:
        A bit string.
    """
    bit_string = ''
    while num > 1:
      bit_string = bytes(num & 1) + bit_string
      num >>= 1
    bit_string = bytes(num) + bit_string
    return bit_string

