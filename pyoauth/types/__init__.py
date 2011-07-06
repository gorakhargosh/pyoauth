#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Types for compatibility.
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


try:
    bytes = bytes
except Exception:
    bytes = str


try:
    # Not Python3
    unicode_string = unicode
except Exception:
    # Python3.
    unicode_string = str
    basestring = (str, bytes)


def is_sequence(value):
    try:
        list(value)
        return True
    except TypeError, e:
        assert "is not iterable" in bytes(e)
        return False


def is_unicode(value):
    """
    Determines whether the given value is a Unicode string.

    :param value:
        The value to test.
    :returns:
        ``True`` if ``value`` is a Unicode string; ``False`` otherwise.
    """
    return isinstance(value, unicode_string)


def is_bytes(value):
    """
    Determines whether the given value is a byte string.

    :param value:
        The value to test.
    :returns:
        ``True`` if ``value`` is a byte string; ``False`` otherwise.
    """
    return isinstance(value, bytes)


def is_bytes_or_unicode(value):
    """
    Determines whether the given value is an instance of a string irrespective
    of whether it is a byte string or a Unicode string.

    :param value:
        The value to test.
    :returns:
        ``True`` if ``value`` is a string; ``False`` otherwise.
    """
    return isinstance(value, basestring)
