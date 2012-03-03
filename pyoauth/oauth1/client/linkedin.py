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

from mom.builtins import is_bytes_or_unicode, b
from pyoauth.error import SignatureMethodNotSupportedError
from pyoauth.oauth1 import SIGNATURE_METHOD_RSA_SHA1
from pyoauth.oauth1.client import Client

class LinkedInClient(Client):
    """
    Creates an instance of a LinkedIn OAuth 1.0 client.

    :see: http://developer.linkedin.com/docs/DOC-1251
    """
    _TEMP_URI = b("https://api.linkedin.com/uas/oauth/requestToken")
    _AUTH_URI = b("https://www.linkedin.com/uas/oauth/authorize")
    _TOKEN_URI = b("https://api.linkedin.com/uas/oauth/accessToken")
    _TOKEN_INVALIDATE_URI = \
        b("https://api.linkedin.com/uas/oauth/invalidateToken")

    def __init__(self,
                 http_client,
                 client_credentials,
                 use_authorization_header=True,
                 strict=False):
        super(LinkedInClient, self).__init__(
            http_client,
            client_credentials=client_credentials,
            temporary_credentials_uri=self._TEMP_URI,
            token_credentials_uri=self._TOKEN_URI,
            authorization_uri=self._AUTH_URI,
            use_authorization_header=use_authorization_header,
            strict=strict,
        )

    @classmethod
    def check_signature_method(cls, signature_method):
        if signature_method == SIGNATURE_METHOD_RSA_SHA1:
            raise SignatureMethodNotSupportedError(
                "LinkedIn OAuth does not support the `%r` signature method." %
                signature_method
            )
