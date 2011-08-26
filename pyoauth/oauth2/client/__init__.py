#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
:module: pyoauth.oauth2.client
:synopsis: OAuth 2.0 client implementation.

.. autoclass:: BearerClient
"""

from __future__ import absolute_import

import logging

from mom.codec.json import json_decode
from pyoauth.constants import HEADER_CONTENT_TYPE
from pyoauth.error import OAuthError, HttpError
from pyoauth.http import RequestAdapter, CONTENT_TYPE_FORM_URLENCODED
from pyoauth.url import url_add_query, oauth_url_sanitize, urlencode_s


class BearerClient(object):
    """
    Bearer client server-side workflow.
    """
    def __init__(self, http_client, client_credentials, auth_uri, token_uri):
        self._http_client = http_client
        self._client_credentials = client_credentials
        self._auth_uri = oauth_url_sanitize(auth_uri)
        self._token_uri = oauth_url_sanitize(token_uri)

    def get_authorization_url(self, redirect_uri, **extra_query_params):
        """
        Determines the authorization URL to which the user should redirected
        by client.

        :param redirect_uri:
            The callback URI to which the OAuth 2.0 server will redirect with
            the response attached to the query string.
        :param extra_query_params:
            Keyword arguments for additional query parameters to be added
            to the URL query string.
        :returns:
            Fully-formed URL to which the client can redirect for
            user-authorization.
        """
        query = {
            'response_type': 'code',
            'redirect_uri': redirect_uri,
            'client_id': self._client_credentials.identifier,
        }
        if extra_query_params:
            query.update(extra_query_params)
        url = url_add_query(self._auth_uri, query)
        return url

    def fetch_access_token(self, code, redirect_uri, error=None,
                           method="POST", payload_params=None,
                           async_callback=None):
        """
        Fetches an access token and a refresh token.

        :param code:
            The code returned by the OAuth 2.0 server to your callback URI.
            Set to ``None`` if an error occurred.
        :param redirect_uri:
            The URL to which the OAuth 2.0 server should redirect.
        :param error:
            Set this to the error query parameter from your callback handler
            if available. (Default ``None``.)
        :param method:
            (Default POST). The HTTP method to use.
        :param payload_params:
            Additional params to he URL-encoded into the body. (Existing
            parameters may be overridden).
        :param async_callback:
            (Optional) Asynchronous callback handler that will be called with the
            received token. If none is specified, this function returns
            the token instead.

        :returns:
            Access token and refresh token (if ``async_callback`` is
            unspecified). If ``async_callback`` is specified, ``None``
            will be returned.
        """
        # TODO: Add async_callback signature and example in documentation.
        if error:
            raise OAuthError(error)

        if not code:
            raise ValueError("argument ``code`` not specified")

        body = urlencode_s({
            "code": code,
            "client_id": self._client_credentials.identifier,
            "client_secret": self._client_credentials.shared_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        })
        if payload_params:
            body.update(payload_params)
        headers = {
            HEADER_CONTENT_TYPE: CONTENT_TYPE_FORM_URLENCODED,
        }
        response = self._http_client.fetch(
            RequestAdapter(method=method, url=self._token_uri,
                           body=body, headers=headers))
        if response.error:
            raise HttpError(
                "[fetch access token] OAuth 2.0 server response " \
                "error: %d - %s" % (response.status, response.reason))
        logging.info(response.content_type)
        token = json_decode(response.content)
        logging.info(token)
        return token

    def fetch_refreshed_access_token(self,
                                     refresh_token,
                                     method="POST",
                                     payload_params=None):
        """
        Fetches a refreshed access token from the OAuth 2.0 server.

        :param refresh_token:
            The previously-obtained refresh token.
        :param method:
            (Default POST) The HTTP method to use for the request.
        :param payload_params:
            (Default ``None``) Additional payload parameters to be URL-encoded
            and added into the request body.
        :returns:
            Refreshed access token.
        """
        # TODO: Add async_callback.
        body = urlencode_s({
            "client_id": self._client_credentials.identifier,
            "client_secret": self._client_credentials.shared_secret,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        })
        if payload_params:
            body.update(payload_params)
        headers = {
            HEADER_CONTENT_TYPE: CONTENT_TYPE_FORM_URLENCODED,
        }
        response = self._http_client.fetch(RequestAdapter(method=method,
                                                          url=self._token_uri,
                                                          body=body,
                                                          headers=headers))
        if response.error:
            raise HttpError(
                "[refresh access token] OAuth 2.0 server response " \
                "error: %d - %s" % (response.status, response.reason))
        logging.info(response.content_type)
        token = json_decode(response.content)
        logging.info(token)
        return token
