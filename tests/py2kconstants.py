#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

from mom.builtins import b

test_unicode_string = u'\u00ae'
test_utf8_bytes = b('\xc2\xae')


percent_encode_test_cases = [
    ('abcABC123', 'abcABC123'),
    ('-._~', '-._~'),
    ('%', '%25'),
    ('+', '%2B'),
    ('&=*', '%26%3D%2A'),
    (u'\u000A', '%0A'),
    (u'\u0020', '%20'),
    (u'\u007F', '%7F'),
    (u'\u0080', '%C2%80'),
    (u'\u3001', '%E3%80%81'),
]
test_unicode_aeiou = u'åéîøü'
test_unicode_angstrom = u"å"
