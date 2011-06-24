# -*- coding: utf-8 -*-
# Unicode utilities.
#
# Copyright (C) 2007-2010 Leah Culver, Joe Stump, Mark Paschal, Vic Fryzel
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
#
# MIT License
# -----------
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


def to_unicode(s):
    if not isinstance(s, unicode):
        if not isinstance(s, str):
            raise TypeError("You are required to pass either unicode or string here, not: %r (%s)" % (type(s), s))
        try:
            s = s.decode("utf-8")
        except UnicodeDecodeError, e:
            raise TypeError('Expected unicode object or UTF-8 encoded string: got Python string containing non-UTF-8: %r instead. The UnicodeDecodeError that resulted from attempting to interpret it as UTF-8 was: %s' % (s, e,))
    return s

def to_utf8(s):
    return to_unicode(s).encode("utf-8")

def to_unicode_if_string(s):
    if isinstance(s, basestring):
        return to_unicode(s)
    else:
        return s

def to_utf8_if_string(s):
    if isinstance(s, basestring):
        return to_utf8(s)
    else:
        return s


def is_unicode(s):
    return isinstance(s, unicode)

