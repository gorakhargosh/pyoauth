#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
# Copyright 2012 Google, Inc.
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


from __future__ import absolute_import

test_unicode_string = '\u00ae'
test_utf8_bytes = b'\xc2\xae'

percent_encode_test_cases = [
    # Decoded, encoded
    (b'abcABC123', b'abcABC123'),
    (b'-._~', b'-._~'),
    (b'%', b'%25'),
    (b'+', b'%2B'),
    (b'&=*', b'%26%3D%2A'),
    ('\u000A', b'%0A'),
    ('\u0020', b'%20'),
    ('\u007F', b'%7F'),
    ('\u0080', b'%C2%80'),
    ('\u3001', b'%E3%80%81'),
]

percent_decode_test_cases = [
    # Decoded, encoded
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
