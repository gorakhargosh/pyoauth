#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Compatibility module.
#
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

from __future__ import absolute_import

from mom.builtins import is_bytes, b
from mom.codec.text import utf8_decode

try:
    # Python 3.
    from urllib.parse import urlparse, urlunparse, parse_qs, quote, \
        unquote_to_bytes, urljoin, unquote
    def unquote_plus(v):
        if is_bytes(v):
            v = v.replace(b('+'), b(' '))
        else:
            v = v.replace('+', ' ')
        return utf8_decode(unquote_to_bytes(v))
except ImportError:
    # Python 2.5+
    from urlparse import urlparse, urlunparse, urljoin
    from urllib import quote, unquote_plus, unquote
    try:
        # Python 2.6+
        from urlparse import parse_qs
    except ImportError:
        from cgi import parse_qs

__all__ = [
    "urlunparse",
    "parse_qs",
    "unquote_plus",
    "quote",
    "urlparse",
    "urljoin",
]

urljoin = urljoin
urlunparse = urlunparse
parse_qs = parse_qs
unquote_plus = unquote_plus
quote = quote
urlparse = urlparse
unquote = unquote
