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

import logging

from pyoauth.http import Request, Response
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
CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded"


class Client(object):
    """
    OAuth 1.0 Client.
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
        oauth_request_url = self._temporary_credentials_request_uri
        return self._build_request(method=method,
                                   oauth_request_url=oauth_request_url,
                                   query_params=query_params,
                                   headers=headers,
                                   realm=realm,
                                   oauth_signature_method=oauth_signature_method,
                                   oauth_callback=oauth_callback,
                                   **extra_oauth_params)

    def parse_temporary_credentials_response(self, response):
        self._validate_oauth_response(response)
        params = oauth_parse_qs(response.body)
        return params, Credentials(identifier=params["oauth_token"],
                                   shared_secret=params["oauth_token_secret"])

    def parse_token_credentials_response(self, response):
        self._validate_oauth_response(response)
        params = oauth_parse_qs(response.body)
        return params, Credentials(identifier=params["oauth_token"],
                                   shared_secret=params["oauth_token_secret"])



    def get_authorization_url(self, temporary_credentials, **query_params):
        url = self._resource_owner_authorization_uri
        if query_params:
            query_params = oauth_url_query_params_sanitize(query_params)
            url = oauth_url_append_query_params(url, query_params)
        return oauth_url_append_query_params(url, dict(oauth_token=temporary_credentials.identifier))

    def _validate_oauth_response(self, response):
        if not isinstance(response, Response):
            raise ValueError("``response`` must be of type pyoauth.http.Response")
        if response.error:
            raise ValueError("Could not fetch temporary credentials -- HTTP status code: %d" % response.status_code)
        if not response.body:
            raise ValueError("OAuth server did not return a valid response")
        # The response body must be URL encoded.
        if response.get_content_type() != CONTENT_TYPE_FORM_URLENCODED:
            raise ValueError("OAuth server must return Content-Type: `%s`" % CONTENT_TYPE_FORM_URLENCODED)


    def _build_request(self,
                      method,
                      oauth_request_url,
                      query_params=None,
                      headers=None,
                      realm=None,
                      oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                      **extra_oauth_params):
        """
        Builds an OAuth request.

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
        :param oauth_callback:
            A callback URL that you want the server to call when done
            with your requests.
        :param oauth_signature_method:
            One of ``SIGNATURE_METHOD_HMAC_SHA1``,
            ``SIGNATURE_METHOD_RSA_SHA1``, or ``SIGNATURE_METHOD_PLAINTEXT``.
        :param extra_oauth_params:
            Any additional oauth parameters you would like to include.
            The parameter names must begin with "oauth_". Any other parameters
            with names that do not begin with this prefix will be ignored.
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
        for k, v in extra_oauth_params.items():
            if k in ("oauth_signature",     # Calculated from given parameters.
                     "oauth_nonce",         # System-generated.
                     "oauth_timestamp",     # System-generated.
                     "oauth_consumer_key",  # Provided when creating the client instance.
                     "oauth_version",       # Optional, but MUST be set to "1.0" according to spec.
                    ):
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
        signature_url = oauth_url_query_params_add(oauth_request_url, query_params)
        oauth_params["oauth_signature"] = self._sign_request_data(oauth_signature_method,
                                                                  method, signature_url, oauth_params)

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
            # Empty the params so that they are not used below.
            oauth_params = None

        if method == "GET":
            request_url = oauth_url_append_query_params(signature_url, oauth_params)
            payload = ""
        elif method == "POST":
            request_url = oauth_request_url
            headers["Content-Type"] = CONTENT_TYPE_FORM_URLENCODED
            payload = oauth_urlencode_s(query_params)
        else:
            raise NotImplementedError("Not implemented any other HTTP methods yet.")

        return Request(method, url=request_url, payload=payload, headers=headers)

    def _sign_request_data(self, signature_method,
             method, url, oauth_params,
             credentials=None):
        sign_func = SIGNATURE_METHOD_MAP[signature_method]
        credentials_shared_secret = credentials.shared_secret if credentials else None
        return sign_func(self._client_credentials.shared_secret,
                         method, url, oauth_params,
                         credentials_shared_secret)



"""
def request_temporary_credentials(http_client,
                                  client_credentials,
                                  method,
                                  temporary_credentials_request_uri,
                                  oauth_params,
                                  realm=None,
                                  use_authorization_header=True):


# Response contains temporary credentials

def get_authorization_url(temporary_credentials,
                          resource_owner_authorization_uri):
    pass

# Send the user to the authorization URL.

# User signs in at that URL.

# Got verifier from server redirect if callback set when
# requesting temporary credentials or user is shown the verifier which
# is input into the client.

def request_token_credentials(http_client,
                              client_credentials,
                              temporary_credentials,
                              method,
                              token_request_uri,
                              realm=None,
                              use_authorization_header=True):
    pass

# Response contains token credentials
# Save these credentials.

def request_api(http_client,
                client_credentials,
                token_credentials,
                method,
                api_uri,
                realm=None,
                use_authorization_header=True):
    pass
"""
