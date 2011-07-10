#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Unicode utilities.
#
# Copyright (C) 2009 Facebook
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
:module: pyoauth.types.unicode
:synopsis: Unicode encoding utility functions.

.. autofunction:: unicode_to_utf8
.. autofunction:: bytes_to_unicode
.. autofunction:: to_utf8_if_unicode
.. autofunction:: to_unicode_if_bytes
.. autofunction:: to_unicode_recursively
"""

from pyoauth.types import is_unicode, is_bytes


def unicode_to_utf8(value):
    """
    Converts a string argument to a UTF-8 encoded byte string if it is a
    Unicode string.

    :param value:
        If already a byte string or None, it is returned unchanged.
        Otherwise it must be a Unicode string and is encoded as UTF-8.
    """
    if value is None or is_bytes(value):
        return value
    assert is_unicode(value)
    return value.encode("utf-8")


def bytes_to_unicode(value, encoding="utf-8"):
    """
    Converts bytes to a Unicode string decoding it according to the encoding
    specified.

    :param value:
        If already a Unicode string or None, it is returned unchanged.
        Otherwise it must be a byte string.
    :param encoding:
        The encoding used to decode bytes. Defaults to UTF-8
    """
    if value is None or is_unicode(value):
        return value
    assert is_bytes(value)
    return value.decode(encoding)


def to_utf8_if_unicode(value):
    """
    Converts an argument to a UTF-8 encoded byte string if the argument
    is a Unicode string.

    :param value:
        The value that will be UTF-8 encoded if it is a string.
    :returns:
        UTF-8 encoded byte string if the argument is a Unicode string; otherwise
        the value is returned unchanged.
    """
    return unicode_to_utf8(value) if is_unicode(value) else value


def to_unicode_if_bytes(value, encoding="utf-8"):
    """
    Converts an argument to Unicode string if the argument is a byte string
    decoding it as specified by the encoding.

    :param value:
        The value that will be converted to a Unicode string.
    :param encoding:
        The encoding used to decode bytes. Defaults to UTF-8.
    :returns:
        Unicode string if the argument is a byte string. Otherwise the value
        is returned unchanged.
    """
    return bytes_to_unicode(value, encoding) if is_bytes(value) else value


def to_unicode_recursively(obj):
    """
    Walks a simple data structure, converting byte strings to unicode.

    Supports lists, tuples, and dictionaries.
    """
    if isinstance(obj, dict):
        return dict((to_unicode_recursively(k),
                     to_unicode_recursively(v)) for (k, v) in obj.iteritems())
    elif isinstance(obj, list):
        return list(to_unicode_recursively(i) for i in obj)
    elif isinstance(obj, tuple):
        return tuple(to_unicode_recursively(i) for i in obj)
    elif is_bytes(obj):
        return bytes_to_unicode(obj)
    else:
        return obj
