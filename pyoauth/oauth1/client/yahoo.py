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
from pyoauth.constants import HTTP_POST, OAUTH_VALUE_CALLBACK_OOB
from pyoauth.error import SignatureMethodNotSupportedError
from pyoauth.oauth1 import SIGNATURE_METHOD_HMAC_SHA1, SIGNATURE_METHOD_RSA_SHA1

from pyoauth.oauth1.client import Client


class YahooClient(Client):
    """
    Creates an instance of a Yahoo! OAuth 1.0 client.

    :see: http://developer.yahoo.com/oauth/guide/oauth-auth-flow.html
    """
    _TEMP_URI = b("https://api.login.yahoo.com/oauth/v2/get_request_token")
    _AUTH_URI = b("https://api.login.yahoo.com/oauth/v2/request_auth")
    _TOKEN_URI = b("https://api.login.yahoo.com/oauth/v2/get_token")

    def __init__(self, http_client, client_credentials,
                 xoauth_lang_pref=b("EN-US"),
                 use_authorization_header=False, strict=False):
        self._xoauth_lang_pref = xoauth_lang_pref or None
        super(YahooClient, self).__init__(
            http_client,
            client_credentials,
            self._TEMP_URI,
            self._TOKEN_URI,
            self._AUTH_URI,
            use_authorization_header=use_authorization_header,
            strict=strict
        )

    @classmethod
    def check_signature_method(cls, signature_method):
        if signature_method == SIGNATURE_METHOD_RSA_SHA1:
            raise SignatureMethodNotSupportedError(
                "Yahoo! OAuth 1.0 does not support the `%r` signature method."
                % signature_method
            )

    def fetch_temporary_credentials(self,
                                    method=HTTP_POST, params=None,
                                    body=None, headers=None,
                                    realm=None,
                                    async_callback=None,
                                    oauth_signature_method=\
                                        SIGNATURE_METHOD_HMAC_SHA1,
                                    oauth_callback=OAUTH_VALUE_CALLBACK_OOB,
                                    **kwargs):
        params = params or {}
        params.update(dict(xoauth_lang_pref=self._xoauth_lang_pref))

        return super(YahooClient, self).fetch_temporary_credentials(
            method=method,
            params=params,
            body=body, headers=headers,
            realm=realm,
            async_callback=async_callback,
            oauth_signature_method=oauth_signature_method,
            oauth_callback=oauth_callback,
            **kwargs
        )
