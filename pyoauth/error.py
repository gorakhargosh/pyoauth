#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
# Copyright (C) 2012 Google, Inc.
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
:module: pyoauth.error
:synopsis: Contains errors and exception classes raised by the library.

.. autoclass:: OAuthError
.. autoclass:: InvalidQueryParametersError
.. autoclass:: InsecureOAuthParametersError
.. autoclass:: InvalidOAuthParametersError
.. autoclass:: InsecureOAuthUrlError
.. autoclass:: InvalidUrlError
.. autoclass:: InvalidHttpMethodError
.. autoclass:: InvalidAuthorizationHeaderError
.. autoclass:: IllegalArgumentError
.. autoclass:: InvalidHttpRequestError
.. autoclass:: InvalidHttpResponseError
.. autoclass:: HttpError
.. autoclass:: InvalidContentTypeError
.. autoclass:: InvalidSignatureMethod
.. autoclass:: SignatureMethodNotSupportedError
"""

class OAuthError(RuntimeError):
    """
    Base exception class.
    """
    def __init__(self, message="OAuth error occurred"):
        self._message = message
        super(OAuthError, self).__init__()

    @property
    def message(self):
        """A hack to get around the deprecation errors in Python 2.6"""
        return self._message

    def __str__(self):
        return self._message


class InvalidQueryParametersError(OAuthError):
    """
    Raised when a query parameter is invalid.
    """
    pass

class InsecureOAuthParametersError(OAuthError):
    """
    Raised when an OAuth confidential parameter is passed into protocol
    parameters.
    """
    pass

class InvalidOAuthParametersError(OAuthError):
    """
    Raised when invalid protocol parameters are detected.
    """
    pass

class InsecureOAuthUrlError(OAuthError):
    """
    Raised when an insecure (non-HTTPS) URL is detected for requesting OAuth
    credentials.
    """
    pass

class InvalidUrlError(OAuthError):
    """
    Raised when a specified URL is invalid for consumption by a routine.
    """
    pass

class InvalidHttpMethodError(OAuthError):
    """
    Raised when an invalid HTTP method is used.
    """
    pass

class InvalidAuthorizationHeaderError(OAuthError):
    """
    Raised when an invalid Authorization header is detected.
    """
    pass

class IllegalArgumentError(OAuthError):
    """
    Raised when an illegal argument is passed to a function.
    """
    pass

class InvalidHttpRequestError(OAuthError):
    """
    Raised when an invalid HTTP request is detected.
    """
    pass

class InvalidHttpResponseError(OAuthError):
    """
    Raised when an invalid HTTP response is detected.
    """
    pass

class HttpError(OAuthError):
    """
    General HTTP error.
    """
    pass

class InvalidContentTypeError(OAuthError):
    """
    Raised when an invalid content type header value is detected.
    """
    pass

class InvalidSignatureMethodError(OAuthError):
    """
    Raised when the signature method specified is invalid.
    """
    pass

class SignatureMethodNotSupportedError(OAuthError):
    """
    Raised when the signature method specified is not supported.
    """
    pass
