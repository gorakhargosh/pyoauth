#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Yahoo! OAuth 1.0 Client.
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


from pyoauth.error import SignatureMethodNotSupportedError
from pyoauth.oauth1 import SIGNATURE_METHOD_HMAC_SHA1, SIGNATURE_METHOD_RSA_SHA1

from pyoauth.oauth1.client import Client

class YahooClient(Client):
    """
    Creates an instance of a Yahoo! OAuth 1.0 client.

    :see: http://developer.yahoo.com/oauth/guide/oauth-auth-flow.html
    """
    _OAUTH_TEMPORARY_CREDENTIALS_REQUEST_URI = "https://api.login.yahoo.com/oauth/v2/get_request_token"
    _OAUTH_RESOURCE_OWNER_AUTHORIZATION_URI = "https://api.login.yahoo.com/oauth/v2/request_auth"
    _OAUTH_TOKEN_CREDENTIALS_REQUEST_URI = "https://api.login.yahoo.com/oauth/v2/get_token"

    def __init__(self, client_credentials):
        super(YahooClient, self).__init__(
            client_credentials=client_credentials,
            temporary_credentials_request_uri=self._OAUTH_TEMPORARY_CREDENTIALS_REQUEST_URI,
            token_credentials_request_uri=self._OAUTH_TEMPORARY_CREDENTIALS_REQUEST_URI,
            resource_owner_authorization_uri=self._OAUTH_RESOURCE_OWNER_AUTHORIZATION_URI,
            use_authorization_header=True
        )

    @classmethod
    def _check_signature_method(cls, signature_method):
        if signature_method == SIGNATURE_METHOD_RSA_SHA1:
            raise SignatureMethodNotSupportedError("Yahoo! OAuth 1.0 does not support the `%r` signature method." % signature_method)

    def build_temporary_credentials_request(self,
                                            xoauth_lang_pref=None,
                                            method="POST",
                                            payload_params=None,
                                            headers=None,
                                            realm=None,
                                            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                                            oauth_callback="oob",
                                            **extra_oauth_params):
        payload_params = payload_params or {}
        yahoo_params = dict()
        if xoauth_lang_pref:
            yahoo_params["xoauth_lang_pref"] = xoauth_lang_pref
        payload_params.update(yahoo_params)

        YahooClient._check_signature_method(oauth_signature_method)

        return super(YahooClient, self).build_temporary_credentials_request(
            method=method,
            payload_params=payload_params,
            headers=headers,
            realm=realm,
            oauth_signature_method=oauth_signature_method,
            oauth_callback=oauth_callback,
            **extra_oauth_params
        )

    def build_token_credentials_request(self,
                                        temporary_credentials,
                                        oauth_verifier,
                                        method="POST",
                                        payload_params=None,
                                        headers=None,
                                        realm=None,
                                        oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                                        **extra_oauth_params):
        YahooClient._check_signature_method(oauth_signature_method)

        return super(YahooClient, self).build_token_credentials_request(
            temporary_credentials=temporary_credentials,
            oauth_verifier=oauth_verifier,
            method=method,
            payload_params=payload_params,
            headers=headers,
            realm=realm,
            oauth_signature_method=oauth_signature_method,
            **extra_oauth_params
        )

    def build_resource_request(self,
                               token_credentials,
                               method,
                               url,
                               payload_params=None,
                               headers=None,
                               realm=None,
                               oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                               **extra_oauth_params):
        YahooClient._check_signature_method(oauth_signature_method)

        return super(YahooClient, self).build_resource_request(
            token_credentials=token_credentials,
            method=method,
            url=url,
            payload_params=payload_params,
            headers=headers,
            realm=realm,
            oauth_signature_method=oauth_signature_method,
            **extra_oauth_params
        )
