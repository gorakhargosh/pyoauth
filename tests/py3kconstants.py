#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import absolute_import

test_unicode_string = '\u00ae'
test_utf8_bytes = b'\xc2\xae'

percent_encode_test_cases = [
    ('abcABC123', b'abcABC123'),
    ('-._~', b'-._~'),
    ('%', b'%25'),
    ('+', b'%2B'),
    ('&=*', b'%26%3D%2A'),
    ('\u000A', b'%0A'),
    ('\u0020', b'%20'),
    ('\u007F', b'%7F'),
    ('\u0080', b'%C2%80'),
    ('\u3001', b'%E3%80%81'),
]
test_unicode_aeiou = 'åéîøü'
test_unicode_angstrom = "å"
