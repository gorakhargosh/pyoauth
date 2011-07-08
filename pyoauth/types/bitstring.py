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

Functions:
----------
.. autofunction:: bits_to_long
.. autofunction:: long_to_bitstring
"""

try:
    a = reduce((lambda a, b: a + b), [1, 2, 3, 4])
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
    return reduce((lambda x, y: (x << 1) + y), bits)


def long_to_bitstring(num):
    """
    Converts a long into the bit string.

    :param num:
        Long value
    :returns:
        A bit string.
    """
    buf = ''
    while num > 1:
      buf = str(num & 1) + buf
      num >>= 1
    buf = str(num) + buf
    return buf