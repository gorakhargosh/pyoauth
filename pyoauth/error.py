#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Exceptions.
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
:module: pyoauth.error
:synopsis: Contains errors and exception classes raised by the library.

.. autoclass:: Error
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

class Error(RuntimeError):
    """
    Base exception class.
    """
    def __init__(self, message="OAuth error occurred"):
        self._message = message
        super(Error, self).__init__()

#    @property
#    def message(self):
#        """A hack to get around the deprecation errors in Python 2.6"""
#        return self._message
#
#    def __str__(self):
#        return self._message


class InvalidQueryParametersError(Error):
    """
    Raised when a query parameter is invalid.
    """
    pass

class InsecureOAuthParametersError(Error):
    """
    Raised when an OAuth confidential parameter is passed into protocol
    parameters.
    """
    pass

class InvalidOAuthParametersError(Error):
    """
    Raised when invalid protocol parameters are detected.
    """
    pass

class InsecureOAuthUrlError(Error):
    """
    Raised when an insecure (non-HTTPS) URL is detected for requesting OAuth
    credentials.
    """
    pass

class InvalidUrlError(Error):
    """
    Raised when a specified URL is invalid for consumption by a routine.
    """
    pass

class InvalidHttpMethodError(Error):
    """
    Raised when an invalid HTTP method is used.
    """
    pass

class InvalidAuthorizationHeaderError(Error):
    """
    Raised when an invalid Authorization header is detected.
    """
    pass

class IllegalArgumentError(Error):
    """
    Raised when an illegal argument is passed to a function.
    """
    pass

class InvalidHttpRequestError(Error):
    """
    Raised when an invalid HTTP request is detected.
    """
    pass

class InvalidHttpResponseError(Error):
    """
    Raised when an invalid HTTP response is detected.
    """
    pass

class HttpError(Error):
    """
    General HTTP error.
    """
    pass

class InvalidContentTypeError(Error):
    """
    Raised when an invalid content type header value is detected.
    """
    pass

class InvalidSignatureMethodError(Error):
    """
    Raised when the signature method specified is invalid.
    """
    pass

class SignatureMethodNotSupportedError(Error):
    """
    Raised when the signature method specified is not supported.
    """
    pass
