#!/usr/bin/env python
# -*- coding: utf-8 -*-
# OAuth 1.0 Client.
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
:module: pyoauth.oauth1.client
:synopsis: Implements an OAuth 1.0 client.

Classes
-------
.. autoclass:: Client
   :members:
   :show-inheritance:
"""

import logging

from pyoauth.http import RequestProxy, ResponseProxy, CONTENT_TYPE_FORM_URLENCODED
from pyoauth.oauth1 import \
    Credentials, \
    SIGNATURE_METHOD_HMAC_SHA1, \
    SIGNATURE_METHOD_RSA_SHA1, \
    SIGNATURE_METHOD_PLAINTEXT
from pyoauth.url import \
    oauth_url_sanitize, \
    oauth_protocol_params_sanitize, \
    oauth_url_query_params_sanitize, \
    oauth_url_query_params_add, \
    oauth_urlencode_s, \
    oauth_url_append_query_params, \
    oauth_parse_qs
from pyoauth.utils import oauth_generate_nonce, \
    oauth_generate_timestamp, \
    oauth_get_hmac_sha1_signature, \
    oauth_get_rsa_sha1_signature, \
    oauth_get_plaintext_signature, \
    oauth_get_normalized_authorization_header_value


SIGNATURE_METHOD_MAP = {
    SIGNATURE_METHOD_HMAC_SHA1: oauth_get_hmac_sha1_signature,
    SIGNATURE_METHOD_RSA_SHA1: oauth_get_rsa_sha1_signature,
    SIGNATURE_METHOD_PLAINTEXT: oauth_get_plaintext_signature,
}


class Client(object):
    """
    OAuth 1.0 Client.

    Authorization in simple words:
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    1. Construct a client with its client credentials.

    2. Send an HTTP request for temporary credentials with a callback URL
       which the server will call with an OAuth verification code after
       authorizing the resource owner (end-user).

    3. Obtain temporary credentials from a successful server response.

    4. Use the temporary credentials to build an authorization URL and
       redirect the resource owner (end-user) to the generated URL.

    5. If a callback URL is not provided when requesting temporary credentials,
       the server displays the OAuth verification code to the resource owner
       (end-user), which she then types into your application.

       OR

       If a callback URL is provided, the server redirects the resource owner
       (end-user) after authorization to your callback URL attaching the
       OAuth verification code as a query parameter.

    6. Using the obtained OAuth verification code from step 5 and the
       temporary credentials obtained in step 3, send an HTTP request for
       token credentials.

    7. Obtain token credentials from a successful server response.

    8. Save the token credentials for future use (say, in a database).

    Accessing a resource:
    ~~~~~~~~~~~~~~~~~~~~~
    1. Construct a client with its client credentials.

    2. Using the token credentials that you have saved (say, in a database),
       send an HTTP request to a resource URL.

    3. Obtain the response and deal with it.
    """
    def __init__(self,
                 client_credentials,
                 temporary_credentials_request_uri,
                 resource_owner_authorization_uri,
                 token_request_uri,
                 use_authorization_header=True):
        """
        Creates an instance of an OAuth 1.0 client.

        :param client_credentials:
            Client (consumer) credentials.
        :param temporary_credentials_request_uri:
            OAuth request token URI.

            Any query parameters starting with "oauth_" will be excluded from
            the URL. All OAuth parameters must be specified in their respective
            requests.
        :param resource_owner_authorization_uri:
            OAuth authorization URI.

            Any query parameters starting with "oauth_" will be excluded from
            the URL. All OAuth parameters must be specified in their respective
            requests.
        :param token_request_uri:
            OAuth access token request URI.

            Any query parameters starting with "oauth_" will be excluded from
            the URL. All OAuth parameters must be specified in their respective
            requests.
        :param use_authorization_header:
            ``True`` to use the HTTP Authorization header to pass OAuth
            parameters; ``False`` will force using the URL query string or
            the entity-body of a request.

            Using the HTTP Authorization header is preferable for many reasons
            including:

            1. Keeps your server request logs clean and readable.

            2. Separates any protocol-specific parameters from server or
               application-specific parameters.

            3. Debugging OAuth problems is easier.

            However, not all OAuth servers may support this feature. Therefore,
            you can set this to ``False`` for use with such services.
        """
        self._client_credentials = client_credentials
        self._temporary_credentials_request_uri = oauth_url_sanitize(temporary_credentials_request_uri)
        self._resource_owner_authorization_uri = oauth_url_sanitize(resource_owner_authorization_uri)
        self._token_request_uri = oauth_url_sanitize(token_request_uri)
        self._use_authorization_header = use_authorization_header

    @property
    def oauth_version(self):
        """Must return ``"1.0"`` (unless for compatibility, in which case,
        you are all by yourself.)"""
        return "1.0"

    def build_temporary_credentials_request(self,
                                            method,
                                            query_params=None,
                                            headers=None,
                                            realm=None,
                                            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                                            oauth_callback=None,
                                            **extra_oauth_params):
        """
        Builds an OAuth request for temporary credentials.

        :param method:
            HTTP request method.
        :param query_params:
            A dictionary of payload parameters. These will be serialized
            into the URL or the entity-body depending on the HTTP request method.
            These must not include any parameters starting with "oauth_". Any
            of these parameters with names starting with the "oauth_" prefix
            will be ignored.
        :param headers:
            A dictionary of headers that will be passed along with the request.

            Including a "Authorization" header is equivalent to instantiating
            this class with ``use_authorization_header=True``, but the scope
            is limited to only the current request.

            If the "Authorization" header is included, its value will be
            replaced with a system-generated value, and OAuth parameters
            will not be included in either the query string or the request
            entity body.
        :param realm:
            The value to use for the realm parameter in the Authorization HTTP
            header. It will be excluded from the base string, however.
        :param oauth_signature_method:
            One of ``SIGNATURE_METHOD_HMAC_SHA1``,
            ``SIGNATURE_METHOD_RSA_SHA1``, or ``SIGNATURE_METHOD_PLAINTEXT``.
        :param oauth_callback:
            A callback URL that you want the server to call when done
            with your requests.
        :param extra_oauth_params:
            Any additional oauth parameters you would like to include.
            The parameter names must begin with "oauth_". Any other parameters
            with names that do not begin with this prefix will be ignored.
        :returns:
            An instance of :class:`pyoauth.http.Request`.
        """
        return self._build_request(method=method,
                                   url=self._temporary_credentials_request_uri,
                                   query_params=query_params,
                                   headers=headers,
                                   realm=realm,
                                   oauth_signature_method=oauth_signature_method,
                                   oauth_callback=oauth_callback,
                                   **extra_oauth_params)

    def get_authorization_url(self, temporary_credentials, **query_params):
        """
        Calculates the authorization URL to which the user will be (re)directed.

        :param temporary_credentials:
            Temporary credentials obtained after parsing the response to
            the temporary credentials request.
        :param query_params:
            Additional query parameters that you would like to include
            into the authorization URL. Parameters beginning with the "oauth_"
            prefix will be ignored.
        """
        url = self._resource_owner_authorization_uri
        if query_params:
            query_params = oauth_url_query_params_sanitize(query_params)
            url = oauth_url_append_query_params(url, query_params)
        return oauth_url_append_query_params(url, {
            "oauth_token": temporary_credentials.identifier,
        })

    def build_token_credentials_request(self,
                                        temporary_credentials,
                                        oauth_verifier,
                                        method,
                                        query_params=None,
                                        headers=None,
                                        realm=None,
                                        oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                                        **extra_oauth_params):
        """
        Builds an OAuth request instance for token credentials from the OAuth
        server.

        :param temporary_credentials:
            Temporary credentials obtained from the response to the
            request built by
            :method:`Client.build_temporary_credentials_request`.
        :param oauth_verifier:
            OAuth verification string sent by the server to your callback URI
            or input by the user into your application.
        :param query_params:
            A dictionary of payload parameters. These will be serialized
            into the URL or the entity-body depending on the HTTP request method.
            These must not include any parameters starting with "oauth_". Any
            of these parameters with names starting with the "oauth_" prefix
            will be ignored.
        :param headers:
            A dictionary of headers that will be passed along with the request.

            Including a "Authorization" header is equivalent to instantiating
            this class with ``use_authorization_header=True``, but the scope
            is limited to only the current request.

            If the "Authorization" header is included, its value will be
            replaced with a system-generated value, and OAuth parameters
            will not be included in either the query string or the request
            entity body.
        :param realm:
            The value to use for the realm parameter in the Authorization HTTP
            header. It will be excluded from the base string, however.
        :param oauth_signature_method:
            One of ``SIGNATURE_METHOD_HMAC_SHA1``,
            ``SIGNATURE_METHOD_RSA_SHA1``, or ``SIGNATURE_METHOD_PLAINTEXT``.
        :param extra_oauth_params:
            Any additional oauth parameters you would like to include.
            The parameter names must begin with "oauth_". Any other parameters
            with names that do not begin with this prefix will be ignored.
        :returns:
            An instance of :class:`pyoauth.http.Request`.
        """
        return self._build_request(method=method,
                                   url=self._token_request_uri,
                                   query_params=query_params,
                                   headers=headers,
                                   realm=realm,
                                   oauth_signature_method=oauth_signature_method,
                                   oauth_verifier=oauth_verifier,
                                   oauth_token=temporary_credentials.identifier,
                                   **extra_oauth_params)

    def build_resource_request(self,
                               token_credentials,
                               method,
                               url,
                               query_params=None,
                               headers=None,
                               realm=None,
                               oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                               **extra_oauth_params):
        """
        Builds an OAuth request instance for token credentials from the OAuth
        server.

        :param token_credentials:
            Temporary credentials obtained from the response to the
            request built by
            :method:`Client.build_temporary_credentials_request`.
        :param method:
            The HTTP method to use.
        :param url:
            The HTTP URL to which the resource request must be sent.
        :param query_params:
            A dictionary of payload parameters. These will be serialized
            into the URL or the entity-body depending on the HTTP request method.
            These must not include any parameters starting with "oauth_". Any
            of these parameters with names starting with the "oauth_" prefix
            will be ignored.
        :param headers:
            A dictionary of headers that will be passed along with the request.

            Including a "Authorization" header is equivalent to instantiating
            this class with ``use_authorization_header=True``, but the scope
            is limited to only the current request.

            If the "Authorization" header is included, its value will be
            replaced with a system-generated value, and OAuth parameters
            will not be included in either the query string or the request
            entity body.
        :param realm:
            The value to use for the realm parameter in the Authorization HTTP
            header. It will be excluded from the base string, however.
        :param oauth_signature_method:
            One of ``SIGNATURE_METHOD_HMAC_SHA1``,
            ``SIGNATURE_METHOD_RSA_SHA1``, or ``SIGNATURE_METHOD_PLAINTEXT``.
        :param extra_oauth_params:
            Any additional oauth parameters you would like to include.
            The parameter names must begin with "oauth_". Any other parameters
            with names that do not begin with this prefix will be ignored.
        :returns:
            An instance of :class:`pyoauth.http.Request`.
        """
        return self._build_request(method=method,
                                   url=url,
                                   query_params=query_params,
                                   headers=headers,
                                   realm=realm,
                                   oauth_signature_method=oauth_signature_method,
                                   oauth_token=token_credentials.identifier
                                   **extra_oauth_params)

    def parse_credentials_response(self, status_code, body, headers):
        """
        Parses the entity-body of the OAuth server response to an OAuth
        credential request.

        :param status_code:
            HTTP response status code.
        :param body:
            HTTP response body.
        :param headers:
            HTTP response headers.
        :returns:
            A tuple of the form::

                (parameter dictionary, pyoauth.oauth1.Credentials instance)
        """
        if not (status_code and body and headers):
            raise ValueError("You must specify the HTTP status code, the response body, and the response headers.")

        response = ResponseProxy(status_code=status_code, body=body, headers=headers)
        self._validate_oauth_response(response)
        params = oauth_parse_qs(response.body)
        return params, Credentials(identifier=params["oauth_token"][0],
                                   shared_secret=params["oauth_token_secret"][0])

    def _validate_oauth_response(self, response):
        """
        Validates an OAuth server response.

        :param response:
            The response of the OAuth server wrapped into a
            :class:`pyoauth.http.Response` object.
        """
        #if not isinstance(response, Response):
        #    raise ValueError("``response`` must be of type pyoauth.http.Response")
        if response.error:
            raise ValueError("Could not fetch temporary credentials -- HTTP status code: %d" % response.status_code)
        if not response.body:
            # For empty bodies.
            raise ValueError("OAuth server did not return a valid response")
        # The response body must be URL encoded.
        if not response.is_body_form_urlencoded():
            raise ValueError("OAuth server response must have Content-Type: `%s`" % CONTENT_TYPE_FORM_URLENCODED)

    def _build_request(self,
                      method,
                      url,
                      query_params=None,
                      headers=None,
                      realm=None,
                      oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                      **extra_oauth_params):
        """
        Builds an OAuth request.

        :param method:
            HTTP request method.
        :param url:
            The OAuth request URI.
        :param query_params:
            A dictionary of payload parameters. These will be serialized
            into the URL or the entity-body depending on the HTTP request method.
            These must not include any parameters starting with "oauth_". Any
            of these parameters with names starting with the "oauth_" prefix
            will be ignored.
        :param headers:
            A dictionary of headers that will be passed along with the request.

            Including a "Authorization" header is equivalent to instantiating
            this class with ``use_authorization_header=True``, but the scope
            is limited to only the current request.

            If the "Authorization" header is included, its value will be
            replaced with a system-generated value, and OAuth parameters
            will not be included in either the query string or the request
            entity body.
        :param realm:
            The value to use for the realm parameter in the Authorization HTTP
            header. It will be excluded from the base string, however.
        :param oauth_signature_method:
            One of ``SIGNATURE_METHOD_HMAC_SHA1``,
            ``SIGNATURE_METHOD_RSA_SHA1``, or ``SIGNATURE_METHOD_PLAINTEXT``.
        :param extra_oauth_params:
            Any additional oauth parameters you would like to include.
            The parameter names must begin with "oauth_". Any other parameters
            with names that do not begin with this prefix will be ignored.
        :returns:
            An instance of :class:`pyoauth.http.Request`.
        """
        method = method.upper()
        headers = headers or {}
        realm = realm or ""

        if oauth_signature_method not in SIGNATURE_METHOD_MAP:
            raise ValueError("Invalid signature method specified -- `%r`" % (oauth_signature_method,))

        # Required OAuth protocol parameters.
        # See Making Requests (http://tools.ietf.org/html/rfc5849#section-3.1)
        oauth_params = dict(
            oauth_consumer_key=self._client_credentials.identifier,
            oauth_signature_method=oauth_signature_method,
            oauth_timestamp=oauth_generate_timestamp(),
            oauth_nonce=oauth_generate_nonce(),
            oauth_version=self.oauth_version,
        )

        # Filter and add additional OAuth parameters.
        extra_oauth_params = oauth_protocol_params_sanitize(extra_oauth_params)
        preserved_oauth_params = (
            "oauth_signature",     # Calculated from given parameters.
            "oauth_nonce",         # System-generated.
            "oauth_timestamp",     # System-generated.
            "oauth_consumer_key",  # Provided when creating the client instance.
            "oauth_version",       # Optional but MUST be set to "1.0" according to spec.
        )
        for k, v in extra_oauth_params.items():
            if k in preserved_oauth_params:
                # Don't override these required system-generated protocol parameters.
                raise ValueError("Cannot override system-generated protocol parameter `%r`." % k)
            elif k == "oauth_callback":
                if v:
                    # Set a callback URL only if it is available.
                    oauth_params["oauth_callback"] = v
                else:
                    raise ValueError("oauth_callback parameter value is undefined.")
            else:
                if k in oauth_params:
                    # Warn when an existing protocol parameter is being
                    # overridden.
                    logging.warning("Overriding existing protocol parameter `%r`=`%r` with `%r`=`%r`",
                                    k, oauth_params[k], k, v)
                oauth_params[k] = v

        # Filter payload parameters for the request.
        query_params = oauth_url_query_params_sanitize(query_params)

        # Determine the request's OAuth signature.
        url_with_query_params = oauth_url_query_params_add(url, query_params)
        oauth_params["oauth_signature"] = self._sign_request_data(oauth_signature_method,
                                                                  method, url_with_query_params, oauth_params)

        # Build request data now.
        # OAuth parameters and any parameters starting with the "oauth_"
        # must be included only in ONE of these three locations:
        #
        # 1. Authorization header.
        # 2. Request URI query string.
        # 3. Request entity body.
        #
        # See Parameter Transmission (http://tools.ietf.org/html/rfc5849#section-3.6)
        if self._use_authorization_header or headers.has_key("Authorization"):
            auth_header_value = oauth_get_normalized_authorization_header_value(oauth_params, realm=realm)
            headers["Authorization"] = auth_header_value
            # Empty the params if using authorization so that they are not
            # included multiple times in a request below.
            oauth_params = None

        if method == "GET":
            request_url = oauth_url_append_query_params(url_with_query_params, oauth_params)
            payload = ""
        elif method == "POST":
            # The query params are not appended to the OAuth request URL in this
            # case but added to the payload instead. Keeps stuff clean.
            request_url = url
            headers["Content-Type"] = CONTENT_TYPE_FORM_URLENCODED
            payload = oauth_urlencode_s(query_params)
        else:
            raise NotImplementedError("Not implemented any other HTTP methods yet.")

        return RequestProxy(method, url=request_url, payload=payload, headers=headers)

    def _sign_request_data(self, signature_method,
                           method, url, oauth_params,
                           credentials=None):
        """
        Generates a signature for the given OAuth request using the credentials
        and the signature method specified.
        """
        sign_func = SIGNATURE_METHOD_MAP[signature_method]
        credentials_shared_secret = credentials.shared_secret if credentials else None
        return sign_func(self._client_credentials.shared_secret,
                         method, url, oauth_params,
                         credentials_shared_secret)
