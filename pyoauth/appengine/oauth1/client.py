#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2009 Facebook
# Copyright (C) 2010, 2011 Tipfy.org
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
:module: pyoauth.oauth1.appengine.client
:synopsis: OAuth 1.0 client support for App Engine.
"""

from __future__ import absolute_import

import logging
from pyoauth._compat import urljoin
from pyoauth.error import InvalidHttpRequestError
from pyoauth.oauth1 import Credentials
from pyoauth.appengine import cached_property
from pyoauth.appengine.httpclient import HttpAdapterMixin


class OAuthMixin(HttpAdapterMixin):
    """
    Framework-agnostic OAuth 1.0 handler mixin implementation.
    """
    @cached_property
    def oauth_client(self):
        raise NotImplementedError("This cached_property must be overridden by the derivative mixin author to return an OAuth client instance.")

    @cached_property
    def _oauth_client_credentials(self):
        return Credentials(identifier=self.oauth_client_identifier,
                           shared_secret=self.oauth_client_shared_secret)

    def authorize_redirect(self, callback_uri="oob", realm=None):
        """
        Redirects the resource owner to obtain OAuth authorization for this
        service.

        You should call this method to log the user in, and then call
        :func:`get_authenticated_user` in the handler you registered
        as your callback URL to complete the authorization process.

        This method sets a cookie called
        ``_oauth_temporary_credentials`` which is subsequently used (and
        cleared) in :func:`get_authenticated_user` for security purposes.

        :param callback_uri:
            The callback URI path. For example, ``/auth/ready?format=json``
            The host on which this handler is running will be used as the
            base URI for this path.
        :param realm:
            The OAuth authorization realm.
        """
        self._oauth_auth_redirect(callback_uri=callback_uri, realm=realm, authenticate=False)

    def authenticate_redirect(self, callback_uri="oob", realm=None):
        """
        Just like authorize_redirect(), but auto-redirects if authorized.

        This is generally the right interface to use if you are using
        single sign-on.

        Override this method in subclasses if authentication URLs are not
        supported.
        """
        # Ask for temporary credentials, and when we get them, redirect
        # to authentication URL.
        self._oauth_auth_redirect(callback_uri=callback_uri, realm=realm, authenticate=True)

    def _oauth_auth_redirect(self, callback_uri, realm, authenticate):
        """
        Redirects the resource owner to obtain OAuth authorization for this
        service.

        You should call this method to log the user in, and then call
        :func:`get_authenticated_user` in the handler you registered
        as your callback URL to complete the authorization process.

        This method sets a cookie called
        ``_oauth_temporary_credentials`` which is subsequently used (and
        cleared) in :func:`get_authenticated_user` for security purposes.

        :param callback_uri:
            The callback URI path. For example, ``/auth/ready?format=json``
            The host on which this handler is running will be used as the
            base URI for this path.
        :param realm:
            The OAuth authorization realm.
        :param authenticate:
            Internal parameter. Not meant for use in client code.

            When set to ``True``, the resource owner will be redirected
            to an "authentication" URL instead of an "authorization" URL.
            Authentication URLs automatically redirect back to the application
            if the application is already authorized.
        """
        callback_uri = callback_uri or "oob"
        if callback_uri and callback_uri != "oob":
            callback_uri = urljoin(self._oauth_request_full_url, callback_uri)

        # Ask for temporary credentials, and when we get them, redirect
        # to either the authentication or authorization URL.
        request = self.oauth_client.build_temporary_credentials_request(realm=realm,
                                                                        oauth_callback=callback_uri)
        self._oauth_fetch(request, self._on_oauth_temporary_credentials, authenticate=authenticate)

    def get_authenticated_user(self, callback, realm=None):
        """
        Gets the OAuth authorized user and access token on callback.

        This method should be called from the handler for your registered
        OAuth callback URL to complete the registration process. We call
        callback with the authenticated user, which in addition to standard
        attributes like 'name' includes the 'access_key' attribute, which
        contains the OAuth access you can use to make authorized requests
        to this service on behalf of the user.

        :param callback:
            The callback that will be called upon successful authorization
            with the user object as its first argument.
        :param realm:
            The realm for the authorization header.
        """
        oauth_token = self._oauth_request_get("oauth_token")
        oauth_verifier = self._oauth_request_get("oauth_verifier")

        # Obtain the temporary credentials saved in the browser cookie.
        temporary_credentials = self._oauth_get_temporary_credentials_from_cookie()
        if not temporary_credentials:
            callback(None)
            return

        # Verify that the oauth_token matches the one sent by the server
        # in the query string.
        try:
            self.oauth_client.check_verification_code(
                temporary_credentials,
                oauth_token,
                oauth_verifier
            )
        except InvalidHttpRequestError, e:
            logging.exception(e)
            callback(None)
            return

        # Ask for token credentials.
        request = self.oauth_client.build_token_credentials_request(temporary_credentials=temporary_credentials,
                                                                    oauth_verifier=oauth_verifier,
                                                                    realm=realm
                                                                    )
        self._oauth_fetch(request, self._on_oauth_token_credentials, callback=callback)

    def _on_oauth_temporary_credentials(self, authenticate, response):
        if response:
            try:
                # Obtain the temporary credentials from the response
                # and save them temporarily in a session cookie.
                params, credentials = \
                    self.oauth_client.parse_temporary_credentials_response(response)
                self._oauth_set_temporary_credentials_cookie(credentials)
                if authenticate:
                    # Redirects to the authentication URL.
                    self._oauth_redirect(self.oauth_client.get_authentication_url(credentials))
                else:
                    # Redirects to the authorization URL.
                    self._oauth_redirect(self.oauth_client.get_authorization_url(credentials))
            except Exception, e:
                logging.exception(e)
                self._oauth_abort(500)
        else:
            logging.warning("Could not get OAuth response when requesting temporary credentials.")
            self._oauth_abort(500)

    def _on_oauth_token_credentials(self, callback, response):
        if response:
            try:
                params, credentials = \
                    self.oauth_client.parse_token_credentials_response(response)
                self._oauth_get_user(credentials, callback)
            except Exception, e:
                logging.exception(e)
                callback(None)
                return
        else:
            logging.warning("OAuth token credentials could not be fetched.")
            callback(None)
            return

    def _oauth_get_temporary_credentials_from_cookie(self, name="_oauth_temporary_credentials"):
        # Get the temporary credentials stored in the secure cookie and clear
        # the cookie.
        cookie = self._oauth_get_secure_cookie(name)
        if cookie:
            self._oauth_delete_cookie(name)
            return Credentials(**cookie)
        else:
            logging.warning("Missing OAuth temporary credentials cookie.")
            return None

    def _oauth_set_temporary_credentials_cookie(self, credentials, cookie_name="_oauth_temporary_credentials"):
        self._oauth_set_secure_cookie(cookie_name, credentials.to_dict())

    def _oauth_get_user(self, token_credentials, callback):
        raise NotImplementedError("OAuth mixin subclass authors must implement this.")

    def _on_oauth_get_user(self, token_credentials, callback, user):
        if not user:
            callback(None)
        else:
            user["oauth_token_credentials"] = token_credentials.to_dict()
            callback(user)

