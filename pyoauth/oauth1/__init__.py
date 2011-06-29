#!/usr/bin/env python
# -*- coding: utf-8 -*-
# OAuth 1.0 implementation.
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

"""
:module: pyoauth.oauth1
:synopsis: Implements OAuth 1.0.

Classes
-------
.. autoclass:: Credentials
   :members:
   :show-inheritance:
"""

from pyoauth.decorators import deprecated


# Signature methods.
SIGNATURE_METHOD_HMAC_SHA1 = "HMAC-SHA1"
SIGNATURE_METHOD_RSA_SHA1 = "RSA-SHA1"
SIGNATURE_METHOD_PLAINTEXT = "PLAINTEXT"
SIGNATURE_METHODS = [
    SIGNATURE_METHOD_HMAC_SHA1,
    SIGNATURE_METHOD_RSA_SHA1,
    SIGNATURE_METHOD_PLAINTEXT,
]


class Credentials(object):
    """
    Convenience wrapper for a pair of OAuth 1.0 credentials.
    """
    def __init__(self, identifier, shared_secret):
        """
        OAuth Credentials.

        :param identifier:
            Identifier (old: key)
        :param shared_secret:
            Shared secret (old: secret)
        """
        self._identifier = identifier
        self._shared_secret = shared_secret

    @property
    def identifier(self):
        return self._identifier

    @property
    def shared_secret(self):
        return self._shared_secret

    @property
    @deprecated
    def key(self):
        return self._identifier

    @property
    @deprecated
    def secret(self):
        return self._shared_secret
