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
:module: pyoauth.unicode
:synopsis: Unicode encoding utility functions.

Functions
---------
.. autofunction:: to_utf8

.. autofunction:: to_unicode

.. autofunction:: to_utf8_if_string

.. autofunction:: to_unicode_if_string

.. autofunction:: is_unicode_string

.. autofunction:: is_byte_string

"""


try:
    # Python 2.6+
    bytes
except:
    # Python 2.5
    bytes = str

try:
    # Not Python3
    unicode
except:
    # Python3.
    unicode = str
    basestring = (str, bytes)


_UTF8_TYPES = (bytes, type(None))
def to_utf8(value):
    """
    Converts a string argument to a UTF-8 encoded byte string if it is a
    Unicode string.

    :param value:
        If already a byte string or None, it is returned unchanged.
        Otherwise it must be a Unicode string and is encoded as UTF-8.
    """
    if isinstance(value, _UTF8_TYPES):
        return value
    assert isinstance(value, unicode)
    return value.encode("utf-8")


_UNICODE_TYPES = (unicode, type(None))
def to_unicode(value):
    """
    Converts a string argument to a Unicode string if it is a byte string.

    :param value:
        If already a Unicode string or None, it is returned unchanged.
        Otherwise it must be a byte string and is decoded as UTF-8.
    """
    if isinstance(value, _UNICODE_TYPES):
        return value
    assert isinstance(value, bytes)
    return value.decode("utf-8")


def to_utf8_if_string(value):
    """
    Converts an argument to a UTF-8 encoded byte string if the argument
    is a string.

    :param value:
        The value that will be UTF-8 encoded if it is a string.
    :returns
        UTF-8 encoded byte string if the argument is a Unicode string; otherwise
        the value is returned unchanged.
    """
    if is_bytes_or_unicode_string(value):
        return to_utf8(value)
    else:
        return value


def to_unicode_if_string(value):
    """
    Converts an argument to Unicode string if the argument is a string.
    The string will be decoded as UTF-8.

    :param value:
        The value that will be converted to a Unicode string.
    :returns:
        Unicode string if the argument is a byte string. Otherwise the value
        is returned unchanged.
    """
    if is_bytes_or_unicode_string(value):
        return to_unicode(value)
    else:
        return value


def is_unicode_string(value):
    """
    Determines whether the given value is a Unicode string.

    :param value:
        The value to test.
    :returns:
        ``True`` if ``value`` is a Unicode string; ``False`` otherwise.
    """
    return isinstance(value, unicode)


def is_byte_string(value):
    """
    Determines whether the given value is a byte string.

    :param value:
        The value to test.
    :returns:
        ``True`` if ``value`` is a byte string; ``False`` otherwise.
    """
    return isinstance(value, bytes)


def is_bytes_or_unicode_string(value):
    """
    Determines whether the given value is an instance of a string irrespective
    of whether it is a byte string or a Unicode string.

    :param value:
        The value to test.
    :returns:
        ``True`` if ``value`` is a string; ``False`` otherwise.
    """
    return isinstance(value, basestring)
