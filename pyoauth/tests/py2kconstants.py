#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
# Copyright (C) 2012 Google, Inc.
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

from mom.builtins import b

test_unicode_string = u'\u00ae'
test_utf8_bytes = b('\xc2\xae')

percent_encode_test_cases = [
    # Decoded, encoded.
    (b('abcABC123'), 'abcABC123'),
    (b('-._~'), '-._~'),
    (b('%'), '%25'),
    (b('+'), '%2B'),
    (b('&=*'), '%26%3D%2A'),
    (u'\u000A', '%0A'),
    (u'\u0020', '%20'),
    (u'\u007F', '%7F'),
    (u'\u0080', '%C2%80'),
    (u'\u3001', '%E3%80%81'),
]

percent_decode_test_cases = [
    # Decoded, encoded.
    (u'abcABC123', 'abcABC123'),
    (u'-._~', '-._~'),
    (u'%', '%25'),
    (u'+', '%2B'),
    (u'&=*', '%26%3D%2A'),
    (u'\u000A', '%0A'),
    (u'\u0020', '%20'),
    (u'\u007F', '%7F'),
    (u'\u0080', '%C2%80'),
    (u'\u3001', '%E3%80%81'),
]
test_unicode_aeiou = u'åéîøü'
test_unicode_angstrom = u"å"
