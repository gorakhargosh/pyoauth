#!/usr/bin/env python
# -*- coding: utf-8 -*-


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
