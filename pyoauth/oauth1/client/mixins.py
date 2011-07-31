#!/usr/bin/env python
# -*- coding: utf-8 -*-
# OpenID Mixin (Google OAuth+OpenID Hybrid style)
#
# Copyright (C) 2009 Facebook.
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

from __future__ import absolute_import, with_statement

import logging

from urllib import urlencode
from functools import partial
from mom.functional import select_dict, map_dict
from pyoauth._compat import urljoin
from pyoauth.url import url_add_query
from pyoauth.http import RequestAdapter, CONTENT_TYPE_FORM_URLENCODED
from pyoauth.error import InvalidHttpRequestError
from pyoauth.oauth1 import Credentials


class OpenIdMixin(object):
    """
    Abstract implementation of OpenID and Attribute Exchange.
    Useful for Hybrid OAuth+OpenID auth.

    See GoogleMixin for example implementation. Use it with an
    HttpAdapterMixin class.

    http://code.google.com/apis/accounts/docs/OpenID.html
    """

    # Implement this in subclasses.
    _OPENID_ENDPOINT = None

    ATTRIB_EMAIL = "http://axschema.org/contact/email"
    ATTRIB_COUNTRY = "http://axschema.org/contact/country/home"
    ATTRIB_LANGUAGE = "http://axschema.org/pref/language"
    ATTRIB_USERNAME = "http://axschema.org/namePerson/friendly"
    ATTRIB_FIRST_NAME = "http://axschema.org/namePerson/first"
    ATTRIB_FULL_NAME = "http://axschema.org/namePerson"
    ATTRIB_LAST_NAME = "http://axschema.org/namePerson/last"
    SPEC_IDENTIFIER_SELECT= "http://specs.openid.net/auth/2.0/identifier_select"
    SPEC_OPENID_NS = "http://specs.openid.net/auth/2.0"
    SPEC_OAUTH_NS = "http://specs.openid.net/extensions/oauth/1.0"
    SPEC_AX_NS = "http://openid.net/srv/ax/1.0"

    def authenticate_redirect(self, callback_uri=None, ax_attrs=None,
                              oauth_scope=None):
        """
        Redirects to the authentication URL for this service.

        After authentication, the service will redirect back to the given
        callback URI.

        We request the given attributes for the authenticated user by default
        (name, email, language, and username). If you don't need all those
        attributes for your app, you can request fewer with the ax_attrs keyword
        argument.

        :param callback_uri:
            The URL to redirect to after authentication.
        :param ax_attrs:
            List of Attribute Exchange attributes to be fetched.
        :returns:
            None
        """
        ax_attrs = ax_attrs or ("name", "email",
                                "language", "username", "country")
        callback_uri = callback_uri or self.adapter_request_path
        args = self._openid_args(callback_uri, ax_attrs, oauth_scope)
        self.adapter_redirect(url_add_query(self._OPENID_ENDPOINT, args))

    def get_authenticated_user(self, callback):
        """
        Fetches the authenticated user data upon redirect.

        This method should be called by the handler that handles the callback
        URL to which the service redirects when the authenticate_redirect()
        or authorize_redirect() methods are called.

        :param callback:
            A function that is called after the authentication attempt. It is
            called passing a dictionary with the requested user attributes or
            None if the authentication failed.
        """
        request_arguments = self.adapter_request_params
        http = self.adapter_http_client

        # Verify the OpenID response via direct request to the OP
        args = map_dict(lambda k, v: (k, v[-1]), request_arguments)
        args["openid.mode"] = u"check_authentication"
        url = self._OPENID_ENDPOINT

        response = http.fetch(RequestAdapter(
            "POST", url, urlencode(args), {
                "content-type": CONTENT_TYPE_FORM_URLENCODED,
            }
        ))
        self._on_authentication_verified(callback, response)

    def _openid_args(self, callback_uri, ax_attrs=None, oauth_scope=None):
        """
        Builds and returns the OpenID arguments used in the authentication
        request.

        :param callback_uri:
            The URL to redirect to after authentication.
        :param ax_attrs:
            List of Attribute Exchange attributes to be fetched.
        :param oauth_scope:
            OAuth scope.
        :returns:
            A dictionary of arguments for the authentication URL.
        """
        ax_attrs = ax_attrs or ()
        url = urljoin(self.adapter_request_full_url, callback_uri)
        request_host = self.adapter_request_host
        request_protocol = self.adapter_request_scheme

        args = {
            "openid.ns": self.SPEC_OPENID_NS,
            "openid.claimed_id": self.SPEC_IDENTIFIER_SELECT,
            "openid.identity": self.SPEC_IDENTIFIER_SELECT,
            "openid.return_to": url,
            "openid.realm": request_protocol + "://" + request_host + "/",
            "openid.mode": "checkid_setup",
        }
        if ax_attrs:
            args.update({
                "openid.ns.ax": self.SPEC_AX_NS,
                "openid.ax.mode": "fetch_request",
            })
            ax_attrs = set(ax_attrs)
            required = []
            if "name" in ax_attrs:
                ax_attrs -= set(["name", "firstname", "fullname", "lastname"])
                required += ["firstname", "fullname", "lastname"]
                args.update({
                    "openid.ax.type.firstname": self.ATTRIB_FIRST_NAME,
                    "openid.ax.type.fullname": self.ATTRIB_FULL_NAME,
                    "openid.ax.type.lastname": self.ATTRIB_LAST_NAME,
                    })
            known_attrs = {
                "email": self.ATTRIB_EMAIL,
                "country": self.ATTRIB_COUNTRY,
                "language": self.ATTRIB_LANGUAGE,
                "username": self.ATTRIB_USERNAME,
                }
            for name in ax_attrs:
                args["openid.ax.type." + name] = known_attrs[name]
                required.append(name)
            args["openid.ax.required"] = ",".join(required)
        if oauth_scope:
            args.update({
                "openid.ns.oauth": self.SPEC_OAUTH_NS,
                "openid.oauth.consumer": request_host.split(":")[0],
                "openid.oauth.scope": oauth_scope,
                })
        return args

    def _on_authentication_verified(self, callback, response):
        """
        Called after the authentication attempt. It calls the callback function
        set when the authentication process started, passing a dictionary of
        user data if the authentication was successful or None if it failed.

        :param callback:
            A function that is called after the authentication attempt
        """
        if not response:
            logging.warning("Missing OpenID response.")
            callback(None)
            return
        elif response.error or "is_value:true" not in response.body:
            logging.warning("Invalid OpenID response (%s): %r",
                            str(response.status) + response.reason,
                            response.body)
            callback(None)
            return

        request_arguments = self.adapter_request_params

        # Make sure we got back at least an email from Attribute Exchange.
        ax_ns = None
        for name, values in request_arguments.items():
            if name.startswith("openid.ns.") and values[-1] == SPEC_AX_NS:
                ax_ns = name[10:]
                break

        ax_args = self._get_ax_args(request_arguments, ax_ns)
        def get_ax_arg(uri, ax_args=ax_args, ax_ns=ax_ns):
            ax_name = self._get_ax_name(ax_args, uri, ax_ns)
            return self.adapter_request_get(ax_name, u"")

        claimed_id = self.adapter_request_get("openid.claimed_id", "")
        name = get_ax_arg(self.ATTRIB_FULL_NAME)
        first_name = get_ax_arg(self.ATTRIB_FIRST_NAME)
        last_name = get_ax_arg(self.ATTRIB_LAST_NAME)
        username = get_ax_arg(self.ATTRIB_USERNAME)
        email = get_ax_arg(self.ATTRIB_EMAIL)
        locale = get_ax_arg(self.ATTRIB_LANGUAGE).lower()
        country = get_ax_arg(self.ATTRIB_COUNTRY)

        user = self._get_user_dict(name, first_name, last_name, username,
                                   email, locale, country, claimed_id)
        callback(user)

    @classmethod
    def _get_user_dict(cls, name, first_name, last_name, username, email,
                       locale, country, claimed_id):
        user = dict()

        name_parts = []
        # First name and last name.
        if first_name:
            user["first_name"] = first_name
            name_parts.append(first_name)
        if last_name:
            user["last_name"] = last_name
            name_parts.append(last_name)

        # Full name.
        if name:
            user["name"] = name
        elif name_parts:
            user["name"] = u" ".join(name_parts)
        elif email:
            user["name"] = email.split("@")[0]

        # Other properties.
        if email:
            user["email"] = email
        if locale:
            user["locale"] = locale
        if username:
            user["username"] = username
        if country:
            user["country"] = country
        if claimed_id:
            user["claimed_id"] = claimed_id
        return user

    @classmethod
    def _get_ax_args(cls, request_arguments, ax_ns):
        if not ax_ns:
            return {}
        prefix = "openid." + ax_ns + ".type."
        return select_dict(lambda k, v: k.startswith(prefix), request_arguments)

    @classmethod
    def _get_ax_name(cls, ax_args, uri, ax_ns):
        """
        Returns an Attribute Exchange value from the request.

        :param ax_args:
            Attribute Exchange-specific request arguments.
        :param uri:
            Attribute Exchange URI.
        :param ax_ns:
            Attribute Exchange namespace.
        :returns:
            The Attribute Exchange value, if found in the request.
        """
        if not ax_ns:
            return ""
        ax_name = ""
        prefix = "openid." + ax_ns + ".type."
        for name, values in ax_args.items():
            if values[-1] == uri:
                part = name[len(prefix):]
                ax_name = "openid." + ax_ns + ".value." + part
                break
        return ax_name


class OAuthMixin(object):
    """
    Framework-agnostic OAuth 1.0 handler mixin implementation.
    """
    @property
    def oauth_client(self):
        raise NotImplementedError(
            "This property must be overridden by a derivative "
            "mixin to return an OAuth client instance."
        )

    def authorize_redirect(self, callback_uri="oob", realm=None,
                           *args, **kwargs):
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
        self._auth_redirect(callback_uri=callback_uri,
                            realm=realm, authenticate=False)

    def authenticate_redirect(self, callback_uri="oob", realm=None,
                              *args, **kwargs):
        """
        Just like authorize_redirect(), but auto-redirects if authorized.

        This is generally the right interface to use if you are using
        single sign-on.

        Override this method in subclasses if authentication URLs are not
        supported.
        """
        # Ask for temporary credentials, and when we get them, redirect
        # to authentication URL.
        self._auth_redirect(callback_uri=callback_uri,
                            realm=realm, authenticate=True)

    def _auth_redirect(self, callback_uri, realm, authenticate):
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
            callback_uri = urljoin(self.adapter_request_full_url, callback_uri)

        # Ask for temporary credentials, and when we get them, redirect
        # to either the authentication or authorization URL.
        #async_callback = partial(self._on_temporary_credentials,
        #                         authenticate=authenticate)
        temp, _ = self.oauth_client.fetch_temporary_credentials(
            realm=realm,
            oauth_callback=callback_uri
        #    async_callback=async_callback
        )
        self._on_temporary_credentials(authenticate, temp)

    def _on_temporary_credentials(self, authenticate, credentials):
        # Obtain the temporary credentials from the response
        # and save them temporarily in a session cookie.
        self._set_temporary_credentials_cookie(credentials)
        if authenticate:
            # Redirects to the authentication URL.
            url = self.oauth_client.get_authentication_url(credentials)
        else:
            # Redirects to the authorization URL.
            url = self.oauth_client.get_authorization_url(credentials)
        self.adapter_redirect(url)

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
        oauth_token = self.adapter_request_get("oauth_token")
        oauth_verifier = self.adapter_request_get("oauth_verifier")

        # Obtain the temporary credentials saved in the browser cookie.
        temp = self._get_temporary_credentials_from_cookie()

        # Verify that the oauth_token matches the one sent by the server
        # in the query string.
        self.oauth_client.check_verification_code(
            temp, oauth_token, oauth_verifier
        )

        # Ask for token credentials.
        token, _ = self.oauth_client.fetch_token_credentials(
            temp, oauth_verifier=oauth_verifier, realm=realm
        )
        #self._oauth_get_user(token, callback)

    def _get_temporary_credentials_from_cookie(self, name="_oauth_temporary_credentials"):
        # Get the temporary credentials stored in the secure cookie and clear
        # the cookie.
        cookie = self.adapter_get_secure_cookie(name)
        if cookie:
            self.adapter_delete_cookie(name)
            return Credentials(**cookie)
        else:
            logging.warning("Missing OAuth temporary credentials cookie.")
            return None

    def _set_temporary_credentials_cookie(self, credentials, cookie_name="_oauth_temporary_credentials"):
        self.adapter_set_secure_cookie(cookie_name, credentials.to_dict())

    def _oauth_get_user(self, token_credentials, callback):
        raise NotImplementedError("OAuth mixin subclass authors must implement this.")

    def _on_oauth_get_user(self, token_credentials, callback, user):
        if not user:
            callback(None)
        else:
            user["oauth_token_credentials"] = token_credentials.to_dict()
            callback(user)
