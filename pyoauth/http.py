#!/usr/bin/env python
# -*- coding: utf-8 -*-
# HTTP utility functions.
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
:module: pyoauth.http
:synopsis: Adaptor functionality for HTTP.

Request and Response Proxies
----------------------------
.. autoclass:: RequestProxy
.. autoclass:: ResponseProxy

"""


CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded"

class RequestProxy(object):
    """Adaptor HTTP Request class.

    Framework implementers can subclass this class and must use it with
    the client methods for them to work.
    """
    def __init__(self, method, url, body=None, headers=None):
        self._method = method.upper()
        self._url = url
        self._body = body
        self._headers = headers

    @property
    def method(self):
        """
        Determines the HTTP request method.
        """
        return self._method

    @property
    def url(self):
        """
        Determines the URL.
        """
        return self._url

    @property
    def payload(self):
        """
        Payload for the request.
        """
        return self._body

    @property
    def body(self):
        """Payload for the request."""
        return self._body

    @property
    def content(self):
        """Payload for the request."""
        return self._body

    @property
    def headers(self):
        """Dictionary of headers."""
        return self._headers


class ResponseProxy(object):
    """Adaptor HTTP Response class.

    Framework implementers can subclass this class and must use it with
    the client methods for them to work.
    """
    def __init__(self, status_code, status, body, headers=None):
        self._body = body
        self._status_message = status
        self._status_code = status_code
        self._headers = headers or {}

    @property
    def body(self):
        """Payload from the response."""
        return self._body

    @property
    def payload(self):
        """Payload from the response."""
        return self._body

    @property
    def content(self):
        """Payload from the response."""
        return self._body

    @property
    def error(self):
        """
        Determines whether an error occurred. ``True`` or ``False``.
        """
        return self.status_code < 200 or self.status_code >= 300

    @property
    def status_code(self):
        """The HTTP response status code."""
        return self._status_code

    @property
    def status(self):
        """The HTTP response status message."""
        return self._status_message

    @property
    def headers(self):
        """HTTP response headers."""
        return self._headers

    def get_header(self, name):
        """
        Fetches the value of a header with the given name.

        :param name:
            The name of the header.
        :returns:
            Value of the header.
        """
        if name in self.headers:
            return self.headers[name]
        elif name.lower() in self.headers:
            return self.headers[name.lower()]
        else:
            header_lowercased = name.lower()
            for k, v in self.headers.items():
                if k.lower() == header_lowercased:
                    return v
            return None

    @property
    def content_type(self):
        """Determines the content type of the response."""
        return self.get_header("Content-Type")

    def is_body_form_urlencoded(self):
        """Determines whether the response has content type form urlencoded."""
        return self.content_type == CONTENT_TYPE_FORM_URLENCODED
