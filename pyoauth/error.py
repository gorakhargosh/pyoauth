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


class Error(RuntimeError):
    """
    Base exception class.
    """
    def __init__(self, message="OAuth error occurred"):
        self._message = message
        super(Error, self).__init__()

    @property
    def message(self):
        """A hack to get around the deprecation errors in Python 2.6"""
        return self._message

    def __str__(self):
        return self._message


class InvalidQueryParametersError(Error):
    pass

class InsecureOAuthParametersError(Error):
    pass

class InvalidOAuthParametersError(Error):
    pass

class InsecureOAuthUrlError(Error):
    pass

class InvalidUrlError(Error):
    pass

class InvalidHttpMethodError(Error):
    pass

class InvalidAuthorizationHeaderError(Error):
    pass

class IllegalArgumentError(Error):
    pass

class InvalidHttpRequestError(Error):
    pass

class InvalidHttpResponseError(Error):
    pass

class HttpError(Error):
    pass

class InvalidContentTypeError(Error):
    pass

class InvalidSignatureMethodError(Error):
    pass

class SignatureMethodNotSupportedError(Error):
    pass
