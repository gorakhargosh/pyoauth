#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Google OAuth 1.0 Client.
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
from pyoauth.oauth1 import SIGNATURE_METHOD_HMAC_SHA1, SIGNATURE_METHOD_PLAINTEXT

from pyoauth.oauth1.client import Client

class GoogleClient(Client):
    """
    Creates an instance of a Google OAuth 1.0 client.

    :see: http://code.google.com/apis/accounts/docs/OAuth_ref.html
    """
    _OAUTH_TEMPORARY_CREDENTIALS_REQUEST_URI = "https://www.google.com/accounts/OAuthGetRequestToken"
    _OAUTH_RESOURCE_OWNER_AUTHORIZATION_URI = "https://www.google.com/accounts/OAuthAuthorizeToken"
    _OAUTH_TOKEN_CREDENTIALS_REQUEST_URI = "https://www.google.com/accounts/OAuthGetAccessToken"

    def __init__(self,
                 client_credentials,
                 use_authorization_header=True):
        super(GoogleClient, self).__init__(
            client_credentials=client_credentials,
            temporary_credentials_request_uri=self._OAUTH_TEMPORARY_CREDENTIALS_REQUEST_URI,
            token_credentials_request_uri=self._OAUTH_TEMPORARY_CREDENTIALS_REQUEST_URI,
            resource_owner_authorization_uri=self._OAUTH_RESOURCE_OWNER_AUTHORIZATION_URI,
            use_authorization_header=use_authorization_header
        )

    @classmethod
    def _check_signature_method(cls, signature_method):
        if signature_method == SIGNATURE_METHOD_PLAINTEXT:
            raise SignatureMethodNotSupportedError("Google OAuth 1.0 does not support the `%r` signature method." % signature_method)

    def build_temporary_credentials_request(self,
                                            scope,
                                            xoauth_displayname=None,
                                            method="POST",
                                            payload_params=None,
                                            headers=None,
                                            realm=None,
                                            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                                            oauth_callback="oob",
                                            **extra_oauth_params):
        payload_params = payload_params or {}
        google_params = dict(
            scope=scope,
        )
        if xoauth_displayname:
            google_params["xoauth_displayname"] = xoauth_displayname
        payload_params.update(google_params)

        GoogleClient._check_signature_method(oauth_signature_method)

        return super(GoogleClient, self).build_temporary_credentials_request(
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
        GoogleClient._check_signature_method(oauth_signature_method)

        return super(GoogleClient, self).build_token_credentials_request(
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
        GoogleClient._check_signature_method(oauth_signature_method)

        return super(GoogleClient, self).build_resource_request(
            token_credentials=token_credentials,
            method=method,
            url=url,
            payload_params=payload_params,
            headers=headers,
            realm=realm,
            oauth_signature_method=oauth_signature_method,
            **extra_oauth_params
        )
