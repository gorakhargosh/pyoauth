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
:module: pyoauth.types
:synopsis: Common portable Python type conversion and detection.

Type detection
--------------
.. autofunction:: is_sequence
.. autofunction:: is_unicode
.. autofunction:: is_bytes
.. autofunction:: is_bytes_or_unicode
"""

import math

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


def byte_count(num):
    """
    Determines the number of bytes in a long.

    :param num:
        Long value.
    :returns:
        The number of bytes in the long integer.
    """
    #if num == 0:
    #    return 0
    if not num:
        return 0
    bits = bit_count(num)
    return int(math.ceil(bits / 8.0))


def bit_count(num):
    """
    Determines the number of bits in a long value.

    :param num:
        Long value.
    :returns:
        Returns the number of bits in the long value.
    """
    #if num == 0:
    #    return 0
    if not num:
        return 0
    s = "%x" % num
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    #return int(math.floor(math.log(n, 2))+1)
