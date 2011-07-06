#!/usr/bin/env python
# -*- coding: utf-8 -*-
# OAuth-Sandbox client.
#
# Copyright (C) 2009 Facebook
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
from pyoauth.oauth1 import SIGNATURE_METHOD_HMAC_SHA1


class OAuthSandbox(object):
    """
    OAuth Sandbox client at ``http://oauth-sandbox.sevengoslings.net/``

    URLs
    ~~~~
    Two-legged resource URL: ``http://oauth-sandbox.sevengoslings.net/two_legged``
    Three-legged resource URL: ``http://oauth-sandbox.sevengoslings.net/three_legged``
    """
    _OAUTH_VERSION = "1.0a"
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_REQUEST_TOKEN_URL = "http://oauth-sandbox.sevengoslings.net/request_token"
    _OAUTH_ACCESS_TOKEN_URL = "http://oauth-sandbox.sevengoslings.net/access_token"
    _OAUTH_AUTHORIZATION_URL = "http://oauth-sandbox.sevengoslings.net/authorize"


    TEST_OAUTH_CONSUMER_KEY = "ac19e45c6b01a767"
    TEST_OAUTH_CONSUMER_SECRET = "59806917a29a94ee77190ec06c50"

    def __init__(self,
                 consumer_key,
                 consumer_secret,
                 signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                 request_token_url=None,
                 authorization_url=None,
                 access_token_url=None
                 ):
        self._consumer_key = consumer_key
        self._consumer_secret = consumer_secret
        self._signature_method = signature_method
        self._request_token_url = request_token_url or self._OAUTH_REQUEST_TOKEN_URL
        self._access_token_url = access_token_url or self._OAUTH_ACCESS_TOKEN_URL
        self._authorization_url = authorization_url or self._OAUTH_AUTHORIZATION_URL


    def _get_request_token_url(self, callback_uri=None, extra_params=None):
        url = self._request_token_url
        oauth_params = dict(
            oauth_consumer_key=self._consumer_key,
            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
        )
