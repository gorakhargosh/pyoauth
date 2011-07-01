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
from pyoauth.unicode import is_bytes_or_unicode
from pyoauth.url import \
    url_sanitize, \
    protocol_params_sanitize, \
    query_params_sanitize, \
    url_add_query, \
    urlencode_s, \
    url_append_query, \
    parse_qs, query_params_append, is_valid_callback_url
from pyoauth.utils import generate_nonce, \
    generate_timestamp, \
    get_hmac_sha1_signature, \
    get_rsa_sha1_signature, \
    get_plaintext_signature, \
    get_normalized_authorization_header_value


SIGNATURE_METHOD_MAP = {
    SIGNATURE_METHOD_HMAC_SHA1: get_hmac_sha1_signature,
    SIGNATURE_METHOD_RSA_SHA1: get_rsa_sha1_signature,
    SIGNATURE_METHOD_PLAINTEXT: get_plaintext_signature,
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
                 use_authorization_header=True,
                 authorization_header_param_delimiter=","):
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
        :param authorization_header_param_delimiter:
            The delimiter used to separate header value parameters.
            According to the Specification, this must be a comma ",". However,
            certain services like Yahoo! use "&" instead. Comma is default.

            See https://github.com/oauth/oauth-ruby/pull/12
        """
        self._client_credentials = client_credentials
        self._temporary_credentials_request_uri = url_sanitize(temporary_credentials_request_uri)
        self._resource_owner_authorization_uri = url_sanitize(resource_owner_authorization_uri)
        self._token_request_uri = url_sanitize(token_request_uri)
        self._use_authorization_header = use_authorization_header
        self._authorization_header_param_delimiter = authorization_header_param_delimiter

    @property
    def oauth_version(self):
        """Must return ``"1.0"`` (unless for compatibility, in which case,
        you are all by yourself.)"""
        return "1.0"

    def build_temporary_credentials_request(self,
                                            method,
                                            payload_params=None,
                                            headers=None,
                                            realm=None,
                                            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                                            oauth_callback="oob",
                                            **extra_oauth_params):
        """
        Builds an OAuth request for temporary credentials.

        :param method:
            HTTP request method.
        :param payload_params:
            A dictionary of payload parameters. These will be serialized
            into the URL or the entity-body depending on the HTTP request method.
            These must not include any parameters starting with "oauth_". Any
            of these parameters with names starting with the "oauth_" prefix
            will be ignored.
        :param headers:
            A dictionary of headers that will be passed along with the request.
            Must not include the "Authorization" header.
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
            An instance of :class:`pyoauth.http.RequestProxy`.
        """
        if not is_valid_callback_url(oauth_callback):
            raise ValueError("`oauth_callback` parameter value is invalid: `%r`" % (oauth_callback, ))

        return self._build_request(method=method,
                                   url=self._temporary_credentials_request_uri,
                                   payload_pparams=payload_params,
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
            query_params = query_params_sanitize(query_params)
            url = url_append_query(url, query_params)
        return url_append_query(url, {
            "oauth_token": temporary_credentials.identifier,
        })

    def build_token_credentials_request(self,
                                        temporary_credentials,
                                        oauth_verifier,
                                        method,
                                        payload_params=None,
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
        :param payload_params:
            A dictionary of payload parameters. These will be serialized
            into the URL or the entity-body depending on the HTTP request method.
            These must not include any parameters starting with "oauth_". Any
            of these parameters with names starting with the "oauth_" prefix
            will be ignored.
        :param headers:
            A dictionary of headers that will be passed along with the request.
            Must not include the "Authorization" header.
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
            An instance of :class:`pyoauth.http.RequestProxy`.
        """
        if "oauth_callback" in extra_oauth_params:
            raise ValueError("`oauth_callback` is reserved for use with temporary credentials request only.")

        return self._build_request(method=method,
                                   url=self._token_request_uri,
                                   payload_params=payload_params,
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
                               payload_params=None,
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
        :param payload_params:
            A dictionary of payload parameters. These will be serialized
            into the URL or the entity-body depending on the HTTP request method.
            These must not include any parameters starting with "oauth_". Any
            of these parameters with names starting with the "oauth_" prefix
            will be ignored.
        :param headers:
            A dictionary of headers that will be passed along with the request.
            Must not include the "Authorization" header.
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
            An instance of :class:`pyoauth.http.RequestProxy`.
        """
        if "oauth_callback" in extra_oauth_params:
            raise ValueError("`oauth_callback` is reserved for use with temporary credentials request only.")

        return self._build_request(method=method,
                                   url=url,
                                   payload_params=payload_params,
                                   headers=headers,
                                   realm=realm,
                                   oauth_signature_method=oauth_signature_method,
                                   oauth_token=token_credentials.identifier
                                   **extra_oauth_params)

    def parse_temporary_credentials_response(self, status_code, body, headers):
        """
        Parses the entity-body of the OAuth server response to an OAuth
        temporary credentials request.

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
        params, credentials = self._parse_credentials_response(status_code, body, headers)
        callback_confirmed = params.get("oauth_callback_confirmed", "").lower()
        if callback_confirmed != "true":
            raise ValueError("Invalid OAuth server response -- `oauth_callback_confirmed` MUST be set to `true`.")
        return params, credentials



    def _parse_credentials_response(self, status_code, body, headers):
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
        if not status_code:
            raise ValueError("Invalid status code: `%r`" % (status_code, ))
        if not body:
            raise ValueError("Body is invalid or empty: `%r`" % (body, ))
        if not headers:
            raise ValueError("Headers are invalid or not specified: `%r`" % (headers, ))

        response = ResponseProxy(status_code=status_code, body=body, headers=headers)
        self._validate_oauth_response(response)
        params = parse_qs(response.body)
        return params, Credentials(identifier=params["oauth_token"][0],
                                   shared_secret=params["oauth_token_secret"][0])

    def _validate_oauth_response(self, response):
        """
        Validates an OAuth server response.

        :param response:
            The response of the OAuth server wrapped into a
            :class:`pyoauth.http.ResponseProxy` object.
        """
        #if not isinstance(response, ResponseProxy):
        #    raise ValueError("``response`` must be of type pyoauth.http.ResponseProxy")
        if response.error:
            raise ValueError("Could not fetch credentials -- HTTP status code: %d" % (response.status_code, ))
        if not response.body:
            # For empty bodies.
            raise ValueError("OAuth server did not return a valid response: `%r`" % (response.body, ))
        # The response body must be URL encoded.
        if not response.is_body_form_urlencoded():
            raise ValueError("OAuth server response must have Content-Type: `%s`" % (CONTENT_TYPE_FORM_URLENCODED, ))

    def _build_request(self,
                      method,
                      url,
                      payload_params=None,
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
        :param payload_params:
            A dictionary of payload parameters. These will be serialized
            into the URL or the entity-body depending on the HTTP request method.
            These must not include any parameters starting with "oauth_". Any
            of these parameters with names starting with the "oauth_" prefix
            will be ignored.
        :param headers:
            A dictionary of headers that will be passed along with the request.
            Must not include the "Authorization" header.
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
            raise ValueError("Invalid signature method specified: `%r`" % (oauth_signature_method,))

        # Required OAuth protocol parameters.
        # See Making Requests (http://tools.ietf.org/html/rfc5849#section-3.1)
        oauth_params = dict(
            oauth_consumer_key=self._client_credentials.identifier,
            oauth_signature_method=oauth_signature_method,
            oauth_timestamp=generate_timestamp(),
            oauth_nonce=generate_nonce(),
            oauth_version=self.oauth_version,
        )

        # Filter and add additional OAuth parameters.
        extra_oauth_params = protocol_params_sanitize(extra_oauth_params)
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
            else:
                if k in oauth_params:
                    # Warn when an existing protocol parameter is being
                    # overridden.
                    logging.warning("Overriding existing protocol parameter `%r`=`%r` with `%r`=`%r`",
                                    k, oauth_params[k], k, v)
                oauth_params[k] = v

        # Filter payload parameters for the request.
        payload_params = query_params_sanitize(payload_params)

        # TODO: I'm not entirely certain yet about whether PUT payload
        #    params should be included in the signature or not.
        #    Here is why:
        #    http://groups.google.com/group/oauth/browse_thread/thread/fdc0b11f2c4a8dc3/
        #
        #    However, until I'm certain that PUT parameters encoded with
        #    application/x-www-form-urlencoded must not be signed,
        #    I'm not handling PUT explicitly in this method.
        #if not method == "PUT":
        url_with_payload_params_added = url_add_query(url, payload_params)

        # Determine the request's OAuth signature.
        oauth_params["oauth_signature"] = self._sign_request_data(oauth_signature_method,
                                                                  method, url_with_payload_params_added, oauth_params)

        # Build request data now.
        # OAuth parameters and any parameters starting with the "oauth_"
        # must be included only in ONE of these three locations:
        #
        # 1. Authorization header.
        # 2. Request URI query string.
        # 3. Request entity body.
        #
        # See Parameter Transmission (http://tools.ietf.org/html/rfc5849#section-3.6)
        if "Authorization" in headers:
            raise ValueError("Authorization field is already present in headers: %r" % (headers, ))
        if self._use_authorization_header:
            auth_header_value = get_normalized_authorization_header_value(oauth_params, realm=realm, param_delimiter=self._authorization_header_param_delimiter)
            headers["Authorization"] = auth_header_value
            # Empty the params if using authorization so that they are not
            # included multiple times in a request below.
            oauth_params = None

        if method in ("POST", "PUT"):
            # The payload params are not appended to the OAuth request URL
            # in this case but added to the payload instead.
            request_url = url
            headers["Content-Type"] = CONTENT_TYPE_FORM_URLENCODED
            payload = query_params_append(payload_params, oauth_params)
        else: #if method == "GET":
            request_url = url_append_query(url_with_payload_params_added, oauth_params)
            payload = ""
        #else:
        #    raise NotImplementedError("Not implemented any other HTTP methods yet.")

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
