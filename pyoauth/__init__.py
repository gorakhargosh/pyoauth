#!usr/bin/env python
# -*- coding: utf-8 -*-
# PyOAuth package.
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

# Signature methods.
SIGNATURE_METHOD_HMAC_SHA1 = "HMAC-SHA1"
SIGNATURE_METHOD_RSA_SHA1 = "RSA-SHA1"
SIGNATURE_METHOD_PLAINTEXT = "PLAINTEXT"
SIGNATURE_METHODS = [
    SIGNATURE_METHOD_HMAC_SHA1,
    SIGNATURE_METHOD_RSA_SHA1,
    SIGNATURE_METHOD_PLAINTEXT,
]

class OAuthToken(object):
    def __init__(self, key, secret):
        self._key = key
        self._secret = secret

    @property
    def key(self):
        return self._key

    @property
    def secret(self):
        return self._secret


class Error(RuntimeError):
    """Generic exception class."""

    def __init__(self, message='OAuth error occurred.'):
        self._message = message

    @property
    def message(self):
        """A hack to get around the deprecation errors in 2.6."""
        return self._message

    def __str__(self):
        return self._message


class OAuthMissingSignature(Error):
    pass
