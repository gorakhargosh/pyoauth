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

"""
:module: pyoauth.oauth1.client.google
:synopsis: Google OAuth 1.0 client implementation.

.. autoclass:: GoogleClient
   :members:
   :show-inheritance:
"""

from mom.builtins import is_bytes_or_unicode

from pyoauth.error import SignatureMethodNotSupportedError
from pyoauth.oauth1 import \
    SIGNATURE_METHOD_HMAC_SHA1, SIGNATURE_METHOD_PLAINTEXT
from pyoauth.oauth1.client import Client


class GoogleClient(Client):
    """
    Creates an instance of a Google OAuth 1.0 client.

    :see: http://code.google.com/apis/accounts/docs/OAuth_ref.html
    """
    _TEMP_URI = "https://www.google.com/accounts/OAuthGetRequestToken"
    _AUTH_URI = "https://www.google.com/accounts/OAuthAuthorizeToken"
    _TOKEN_URI = "https://www.google.com/accounts/OAuthGetAccessToken"

    def __init__(self,
                 http_client,
                 client_credentials,
                 use_authorization_header=True):
        super(GoogleClient, self).__init__(
            http_client,
            client_credentials=client_credentials,
            temporary_credentials_uri=self._TEMP_URI,
            token_credentials_uri=self._TOKEN_URI,
            authorization_uri=self._AUTH_URI,
            use_authorization_header=use_authorization_header
        )

    @classmethod
    def _check_signature_method(cls, signature_method):
        if signature_method == SIGNATURE_METHOD_PLAINTEXT:
            raise SignatureMethodNotSupportedError(
                "Google OAuth does not support the `%r` signature method." % \
                signature_method
            )

    def fetch_temporary_credentials(self,
                                    method="POST", params=None,
                                    body=None, headers=None,
                                    realm=None,
                                    async_callback=None,
                                    oauth_signature_method=\
                                        SIGNATURE_METHOD_HMAC_SHA1,
                                    oauth_callback="oob",
                                    **kwargs):
        """

        :param scopes:
            A list of scopes to use with the credential request.
        :param xoauth_displayname:
            The display name of the application.
        """
        params = params or {}
        xoauth_displayname = kwargs.get('xoauth_displayname')
        try:
            scopes = kwargs['scopes']
        except KeyError:
            raise KeyError("Missing keyword argument: `scopes`")
        scope = scopes if is_bytes_or_unicode(scopes) else " ".join(scopes)
        google_params = dict(scope=scope)
        if xoauth_displayname:
            google_params["xoauth_displayname"] = xoauth_displayname
        params.update(google_params)

        GoogleClient._check_signature_method(oauth_signature_method)

        return super(GoogleClient, self).fetch_temporary_credentials(
            method=method,
            params=params,
            body=body, headers=headers,
            realm=realm,
            async_callback=async_callback,
            oauth_signature_method=oauth_signature_method,
            oauth_callback=oauth_callback,
            **kwargs
        )


    def parse_temporary_credentials_response(cls, response, strict=False):
        """
        Non-compliant server.
        """
        return Client.parse_temporary_credentials_response(response, strict)


    def parse_token_credentials_response(cls, response, strict=False):
        """
        Non-compliant server.
        """
        return Client.parse_token_credentials_response(response, strict)
