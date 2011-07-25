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

from __future__ import absolute_import

from pyoauth.http import CONTENT_TYPE_FORM_URLENCODED, RequestAdapter
from pyoauth.error import \
    InvalidAuthorizationHeaderError, InvalidSignatureMethodError, \
    IllegalArgumentError, InvalidHttpRequestError, \
    InvalidContentTypeError, HttpError, InvalidHttpResponseError
from pyoauth.oauth1 import \
    SIGNATURE_METHOD_HMAC_SHA1, \
    SIGNATURE_METHOD_RSA_SHA1, \
    SIGNATURE_METHOD_PLAINTEXT, Credentials
from pyoauth.protocol import \
    generate_authorization_header, \
    generate_base_string, \
    generate_nonce, \
    generate_timestamp
from pyoauth.url import \
    url_append_query, url_add_query, \
    query_append, request_query_remove_non_oauth, \
    oauth_url_sanitize, is_valid_callback_url, query_remove_oauth, parse_qs
from pyoauth.protocol import \
    generate_hmac_sha1_signature, \
    generate_rsa_sha1_signature, \
    generate_plaintext_signature


SIGNATURE_METHOD_MAP = {
    SIGNATURE_METHOD_HMAC_SHA1: generate_hmac_sha1_signature,
    SIGNATURE_METHOD_RSA_SHA1: generate_rsa_sha1_signature,
    SIGNATURE_METHOD_PLAINTEXT: generate_plaintext_signature,
}


class _OAuthClient(object):
    def __init__(self, client_credentials, http_client,
                 use_authorization_header=True):
        self._client_credentials = client_credentials
        self._http_client = http_client
        self._use_authorization_header = use_authorization_header

    @property
    def oauth_version(self):
        return "1.0"

    @classmethod
    def generate_nonce(cls):
        """
        Generates a nonce value.
        Override if you need a different method.
        """
        return generate_nonce()

    @classmethod
    def generate_timestamp(cls):
        """
        Generates a timestamp.
        Override if you need a different method.
        """
        return generate_timestamp()

    @classmethod
    def _generate_oauth_params(cls,
                               oauth_consumer_key,
                               oauth_signature_method,
                               oauth_version,
                               oauth_nonce,
                               oauth_timestamp,
                               oauth_token,
                               **extra_oauth_params):
        """
        Generates property formatted oauth_params dictionary for use with an
        OAuth request.

        :param oauth_consumer_key:
            Your OAuth consumer key (client identifier).
        :param oauth_signature_method:
            The signature method to use.
        :param oauth_version:
            The version of OAuth to be used. "1.0" for standards-compliant.
        :param oauth_nonce:
            A unique randomly generated nonce value.
        :param oauth_timestamp:
            A unique timestamp since epoch.
        :param oauth_token:
            A response oauth_token if obtained from the OAuth server.
        :returns:
            A dictionary of protocol parameters.
        """
        if oauth_signature_method not in SIGNATURE_METHOD_MAP:
            raise InvalidSignatureMethodError(
                "Invalid signature method specified: %r" % \
                oauth_signature_method
            )

        # Reserved OAuth parameters.
        oauth_params = dict(
            oauth_consumer_key=oauth_consumer_key,
            oauth_signature_method=oauth_signature_method,
            oauth_timestamp=oauth_timestamp,
            oauth_nonce=oauth_nonce,
            oauth_version=oauth_version,
            )
        # If we have an oauth token.
        if oauth_token:
            oauth_params["oauth_token"] = oauth_token

        # Clean up oauth parameters in the arguments.
        extra_oauth_params = request_query_remove_non_oauth(extra_oauth_params)
        for k, v in extra_oauth_params.items():
            if k == "oauth_signature":
                raise IllegalArgumentError("Cannot override system-generated "\
                                           "protocol parameter: %r" % k)
            else:
                oauth_params[k] = v[0]
        return oauth_params

    @classmethod
    def _generate_signature(cls, method, url, params,
                            oauth_consumer_secret,
                            oauth_token_secret,
                            oauth_params):
        """
        Given the base string parameters, secrets, and protocol parameters,
        calculates a signature for the request.

        :param method:
            HTTP method.
        :param url:
            Request URL.
        :param params:
            Additional query/payload parameters.
        :param oauth_consumer_secret:
            OAuth client shared secret (consumer secret).
        :param oauth_token_secret:
            OAuth token/temporary shared secret if obtained from the OAuth
            server.
        :param oauth_params:
            OAuth parameters generated by
            :func:`OAuthClient._generate_oauth_params`.
        :returns:
            Request signature.
        """
        # Make oauth params and sign the request.
        signature_url = url_add_query(url, params)
        base_string = generate_base_string(method, signature_url, oauth_params)

        signature_method = oauth_params["oauth_signature_method"]
        try:
            sign_func = SIGNATURE_METHOD_MAP[signature_method]
            return sign_func(base_string,
                             oauth_consumer_secret,
                             oauth_token_secret)
        except KeyError:
            raise InvalidSignatureMethodError(
                "unsupported signature method: %r" % signature_method
            )

    @classmethod
    def _build_request(cls, method, url, params, body, headers,
                       oauth_params, realm, use_authorization_header):
        """
        Builds a request based on the HTTP arguments and OAuth protocol
        parameters.

        :param method:
            HTTP method.
        :param url:
            Request URL
        :param params:
            Additional query/payload parameters.
            If a `body` argument to this function is specified,
            the parameters are appended to the URL query string.
            If a `body` is not specified and a method other than GET is used
            the parameters will be added to the entity body.
        :param body:
            Entity body.
        :param oauth_params:
            Protocol-specific parameters.
        :param realm:
            OAuth authorization realm.
        :param use_authorization_header:
            ``True`` if the Authorization HTTP header should be used;
            ``False`` otherwise.
        :returns:
            An instance of :class:`pyoauth.http.RequestAdapter`.
        """
        # http://tools.ietf.org/html/rfc5849#section-3.6
        if "Authorization" in headers:
            raise InvalidAuthorizationHeaderError(
                "Authorization field is already present in headers: %r" % \
                headers
            )
        if use_authorization_header:
            headers["Authorization"] = \
                generate_authorization_header(oauth_params, realm)
            # Empty oauth params so that they are not included again below.
            oauth_params = None

        # OAuth requests can contain payloads.
        if body or method == "GET":
            # Append params to query string.
            url = url_append_query(url_add_query(url, params), oauth_params)
            if body and method == "GET":
                raise InvalidHttpRequestError(
                    "HTTP method GET does not take an entity body: got %r" % \
                    body
                )
        else:
            # Append to payload and set content type.
            headers["Content-Type"] = CONTENT_TYPE_FORM_URLENCODED
            body = query_append(params, oauth_params)
        return RequestAdapter(method, url, body, headers)

    def _request(self,
                method, url, params=None, body=None, headers=None,
                realm=None,
                auth_credentials=None,
                oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                **extra_oauth_params):
        """
        Makes an OAuth request.

        :param method:
            HTTP method.
        :param url:
            Request URL
        :param params:
            Additional query/payload parameters.
            If a `body` argument to this function is specified,
            the parameters are appended to the URL query string.
            If a `body` is not specified and a method other than GET is used
            the parameters will be added to the entity body.
        :param body:
            Entity body string.
        :param headers:
            Request headers dictionary.
        :param realm:
            Authorization realm.
        :param auth_credentials:
            OAuth token/temporary credentials (if available).
        :param oauth_signature_method:
            Signature method.
        :param extra_oauth_params:
            Additional OAuth parameters.
        :returns:
            HTTP response (:class:`pyoauth.http.ResponseAdapter`) if
            ``async_callback`` is not specified;
            otherwise, ``async_callback`` is called with the response as its
            argument.
        """
        method = method.upper()
        params = query_remove_oauth(params) if params else {}
        body = body or ""
        headers = headers or {}
        url = oauth_url_sanitize(url, force_secure=False)

        client_credentials = self._client_credentials
        if auth_credentials:
            oauth_token = auth_credentials.identifier
            oauth_token_secret = auth_credentials.shared_secret
        else:
            oauth_token = oauth_token_secret = None

        # Build oauth parameters.
        oauth_params = self._generate_oauth_params(
            oauth_consumer_key=client_credentials.identifier,
            oauth_signature_method=oauth_signature_method,
            oauth_version=self.oauth_version,
            oauth_timestamp=self.generate_timestamp(),
            oauth_nonce=self.generate_nonce(),
            oauth_token=oauth_token,
            **extra_oauth_params
        )

        # Sign the request.
        signature = self._generate_signature(method, url, params,
                                            client_credentials.shared_secret,
                                            oauth_token_secret,
                                            oauth_params)
        oauth_params["oauth_signature"] = signature

        # Now build the request.
        return self._build_request(
            method, url, params, body, headers,
            oauth_params, realm, self._use_authorization_header
        )

    def _fetch(self,
              method, url, params=None, body=None, headers=None,
              async_callback=None,
              realm=None,
              auth_credentials=None,
              oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
              **extra_oauth_params):
        """
        Makes an OAuth request.

        :param method:
            HTTP method.
        :param url:
            Request URL
        :param params:
            Additional query/payload parameters.
            If a `body` argument to this function is specified,
            the parameters are appended to the URL query string.
            If a `body` is not specified and a method other than GET is used
            the parameters will be added to the entity body.
        :param body:
            Entity body string.
        :param headers:
            Request headers dictionary.
        :param async_callback:
            If the HTTP client used is asynchronous, then this parameter
            will be used as a callback function with the response as its
            argument.
        :param realm:
            Authorization realm.
        :param auth_credentials:
            OAuth token/temporary credentials (if available).
        :param oauth_signature_method:
            Signature method.
        :param extra_oauth_params:
            Additional OAuth parameters.
        :returns:
            HTTP response (:class:`pyoauth.http.ResponseAdapter`) if
            ``async_callback`` is not specified;
            otherwise, ``async_callback`` is called with the response as its
            argument.
        """
        request = self._request(
            method, url, params,
            body, headers, realm, auth_credentials,
            oauth_signature_method, **extra_oauth_params
        )
        return self._http_client.fetch(request, async_callback)

    @classmethod
    def _parse_credentials_response(cls, response):
        """
        Parses the entity-body of the OAuth server response to an OAuth
        credential request.

        :param response:
            An instance of :class:`pyoauth.http.ResponseAdapter`.
        :returns:
            A tuple of the form::

                (pyoauth.oauth1.Credentials instance, other parameters)
        """
        if not response.status_code:
            raise InvalidHttpResponseError(
                "Invalid status code: `%r`" % response.status_code)
        if not response.status:
            raise InvalidHttpResponseError(
                "Invalid status message: `%r`" % response.status)
        if not response.body:
            raise InvalidHttpResponseError(
                "Body is invalid or empty: `%r`" % response.body)
        if not response.headers:
            raise InvalidHttpResponseError(
                "Headers are invalid or not specified: `%r`" % \
                response.headers)

        if response.error:
            raise HttpError("Could not fetch credentials: HTTP %d - %s" \
            % (response.status_code, response.status,))
            # The response body must be URL encoded.
        if not response.is_body_form_urlencoded():
            raise InvalidContentTypeError(
                "OAuth credentials server response must " \
                "have Content-Type: `%s`" % CONTENT_TYPE_FORM_URLENCODED)

        params = parse_qs(response.body)
        credentials = Credentials(identifier=params["oauth_token"][0],
                                  shared_secret=params["oauth_token_secret"][0])
        return credentials, params


class Client(_OAuthClient):
    def __init__(self,
                 http_client,
                 client_credentials,
                 temporary_credentials_uri,
                 token_credentials_uri,
                 authorization_uri,
                 authentication_uri=None,
                 use_authorization_header=True):
        super(Client, self).__init__(client_credentials,
                                     http_client,
                                     use_authorization_header)
        self._temporary_credentials_uri = \
            oauth_url_sanitize(temporary_credentials_uri)
        self._token_credentials_uri = \
            oauth_url_sanitize(token_credentials_uri)
        self._authorization_uri = \
            oauth_url_sanitize(authorization_uri, False)
        if authentication_uri:
            self._authentication_uri = \
                oauth_url_sanitize(authentication_uri, False)
        else:
            self._authentication_uri = None

    def fetch_temporary_credentials(self,
                                    method, url, params=None,
                                    body=None, headers=None,
                                    realm=None,
                                    async_callback=None,
                                    oauth_signature_method=\
                                        SIGNATURE_METHOD_HMAC_SHA1,
                                    oauth_callback="oob",
                                    **extra_oauth_params):
        """
        Fetches temporary credentials.

        :param method:
            HTTP method.
        :param url:
            Request URL
        :param params:
            Additional query/payload parameters.
            If a `body` argument to this function is specified,
            the parameters are appended to the URL query string.
            If a `body` is not specified and a method other than GET is used
            the parameters will be added to the entity body.
        :param body:
            Entity body string.
        :param headers:
            Request headers dictionary.
        :param async_callback:
            If the HTTP client used is asynchronous, then this parameter
            will be used as a callback function with the response as its
            argument.
        :param realm:
            Authorization realm.
        :param oauth_signature_method:
            Signature method.
        :param oauth_callback:
            OAuth callback URL; default case-sensitive "oob" (out-of-band).
        :param extra_oauth_params:
            Additional OAuth parameters.
        :returns:
            HTTP response (:class:`pyoauth.http.ResponseAdapter`) if
            ``async_callback`` is not specified;
            otherwise, ``async_callback`` is called with the response as its
            argument.
        """
        if not is_valid_callback_url(oauth_callback):
            raise ValueError(
                "`oauth_callback` parameter value is invalid URL: %r" % \
                oauth_callback
            )

        return self._fetch(method, url, params,
                           body, headers,
                           async_callback=async_callback,
                           realm=realm,
                           oauth_signature_method=oauth_signature_method,
                           oauth_callback=oauth_callback,
                           **extra_oauth_params)

    def fetch_token_credentials(self,
                                temporary_credentials,
                                method, url, params=None,
                                body=None, headers=None,
                                realm=None, async_callback=None,
                                oauth_signature_method=\
                                    SIGNATURE_METHOD_HMAC_SHA1,
                                **extra_oauth_params):
        """
        Fetches token credentials using the temporary credentials.

        :param temporary_credentials:
            Temporary credentials obtained in a previous step.
        :param method:
            HTTP method.
        :param url:
            Request URL
        :param params:
            Additional query/payload parameters.
            If a `body` argument to this function is specified,
            the parameters are appended to the URL query string.
            If a `body` is not specified and a method other than GET is used
            the parameters will be added to the entity body.
        :param body:
            Entity body string.
        :param headers:
            Request headers dictionary.
        :param async_callback:
            If the HTTP client used is asynchronous, then this parameter
            will be used as a callback function with the response as its
            argument.
        :param realm:
            Authorization realm.
        :param oauth_signature_method:
            Signature method.
        :param extra_oauth_params:
            Additional OAuth parameters.
        :returns:
            HTTP response (:class:`pyoauth.http.ResponseAdapter`) if
            ``async_callback`` is not specified;
            otherwise, ``async_callback`` is called with the response as its
            argument.
        """
        if "oauth_callback" in extra_oauth_params:
            raise IllegalArgumentError(
                '`oauth_callback` is reserved for requesting temporary '\
                'credentials only: got %r' % \
                extra_oauth_params["oauth_callback"]
            )

        response = self._fetch(method, url, params,
                               body, headers,
                               async_callback=async_callback,
                               realm=realm,
                               auth_credentials=temporary_credentials,
                               oauth_signature_method=oauth_signature_method,
                               **extra_oauth_params)
        return response

    def fetch_resource(self,
                       token_credentials,
                       method, url, params=None,
                       body=None, headers=None,
                       realm=None, async_callback=None,
                       oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                       **extra_oauth_params):
        """
        Fetches a resource using the token credentials.

        :param token_credentials:
            Token credentials obtained in a previous step.
        :param method:
            HTTP method.
        :param url:
            Request URL
        :param params:
            Additional query/payload parameters.
            If a `body` argument to this function is specified,
            the parameters are appended to the URL query string.
            If a `body` is not specified and a method other than GET is used
            the parameters will be added to the entity body.
        :param body:
            Entity body string.
        :param headers:
            Request headers dictionary.
        :param async_callback:
            If the HTTP client used is asynchronous, then this parameter
            will be used as a callback function with the response as its
            argument.
        :param realm:
            Authorization realm.
        :param oauth_signature_method:
            Signature method.
        :param extra_oauth_params:
            Additional OAuth parameters.
        :returns:
            HTTP response (:class:`pyoauth.http.ResponseAdapter`) if
            ``async_callback`` is not specified;
            otherwise, ``async_callback`` is called with the response as its
            argument.
        """
        response = self._fetch(method, url, params,
                               body, headers,
                               async_callback=async_callback,
                               realm=realm,
                               auth_credentials=token_credentials,
                               oauth_signature_method=oauth_signature_method,
                               **extra_oauth_params)
        return response

    def get_authorization_url(self, temporary_credentials, **query_params):
        """
        Calculates the authorization URL to which the user will be (re)directed.

        :param temporary_credentials:
            Temporary credentials obtained after parsing the response to
            the temporary credentials request.
        :param query_params:
            Additional query parameters that you would like to include
            into the authorization URL. Parameters beginning with the ``oauth_``
            prefix will be ignored.
        """
        url = self._authorization_uri
        if query_params:
            query_params = query_remove_oauth(query_params)
            url = url_append_query(url, query_params)

        # `oauth_token` must appear last.
        return url_append_query(url, {
            "oauth_token": temporary_credentials.identifier,
        })

    def get_authentication_url(self, temporary_credentials, **query_params):
        """
        Calculates the automatic authentication redirect URL to which the
        user will be (re)directed. Some providers support automatic
        authorization URLs if the user is already signed in. You can use
        this method with such URLs.

        :param temporary_credentials:
            Temporary credentials obtained after parsing the response to
            the temporary credentials request.
        :param query_params:
            Additional query parameters that you would like to include
            into the authorization URL. Parameters beginning with the ``oauth_``
            prefix will be ignored.
        """
        url = self._authentication_uri
        if not url:
            raise NotImplementedError(
                "Service does not support automatic authentication redirects.")
        if query_params:
            query_params = query_remove_oauth(query_params)
            url = url_append_query(url, query_params)

        # So that the "oauth_token" appears LAST.
        return url_append_query(url, {
            "oauth_token": temporary_credentials.identifier,
            })

    def check_verification_code(self,
                                temporary_credentials,
                                oauth_token, oauth_verifier):
        """
        When an OAuth 1.0 server redirects the resource owner to your
        callback URL after authorization, it will attach two parameters to
        the query string.

        1. ``oauth_token``: Must match your temporary credentials identifier.
        2. ``oauth_verifier``: Server-generated verification code that you will
           use in the next step--that is requesting token credentials.

        :param temporary_credentials:
            Temporary credentials
        :param oauth_token:
            The value of the ``oauth_token`` parameter as obtained
            from the server redirect.
        :param oauth_verifier:
            The value of the ``oauth_verifier`` parameter as obtained
            from the server redirect.
        """
        if temporary_credentials.identifier != oauth_token:
            raise InvalidHttpRequestError(
                "OAuth token returned in callback query `%r` " \
                "does not match temporary credentials: `%r`" % \
                (oauth_token, temporary_credentials.identifier)
            )
        return oauth_verifier

    def parse_temporary_credentials_response(self, response):
        """
        Parses the entity-body of the OAuth server response to an OAuth
        temporary credentials request.

        :param response:
            An instance of :class:`pyoauth.http.ResponseAdapter`.
        :returns:
            A tuple of the form::

                (pyoauth.oauth1.Credentials instance, other parameters)
        """
        credentials, params = self._parse_credentials_response(response)
        if params.get("oauth_callback_confirmed", [""])[0].lower() != "true":
            raise ValueError(
                "Invalid OAuth server response -- " \
                "`oauth_callback_confirmed` MUST be set to `true`.")
        return credentials, params

    def parse_token_credentials_response(self, response):
        """
        Parses the entity-body of the OAuth server response to an OAuth
        token credentials request.

        :param response:
            An instance of :class:`pyoauth.http.ResponseAdapter`.
        :returns:
            A tuple of the form::

                (pyoauth.oauth1.Credentials instance, other parameters)
        """
        return self._parse_credentials_response(response)
