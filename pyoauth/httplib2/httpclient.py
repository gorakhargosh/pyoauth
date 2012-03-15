#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
# Copyright 2012 Google, Inc.
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
:module: pyoauth.httplib2.httpclient
:synopsis: httplib2-based adapter HTTP client implementation.

.. autoclass: HttpClient
"""

from __future__ import absolute_import

from httplib2 import Http
from pyoauth.http import ResponseAdapter


class HttpClient(object):
    def __init__(self):
        self._http_client = Http()

    def fetch(self, request, async_callback=None, *args, **kwargs):
        """
        Fetches a response from the OAuth server for a given OAuth request.

        Self-contained HTTP request method can be replaced with
        one for your Web framework.

        :param request:
            An instance of type :class:`pyoauth.http.RequestProxy`.
        :param async_callback:
            ``None`` by default. Unused on App Engine. Useful when your request
            fetching method is asynchronous. Set to a callback function which
            has the following signature::

                def handle_response(response):
                    pass

            If callback is not set, the response is returned by the method.
        :param args:
            Any additional positional arguments to be passed to the
            ``async_callback``.
        :param kwargs:
            Any additional arguments to be passed to the ``async_callback``.
        """
        if async_callback:
            raise NotImplementedError(
                "Asynchronous httplib2 usage is currently not implemented."
            )
        else:
            response, content = self._http_client.request(
                request.url,
                request.method,
                request.body,
                request.headers
            )
            return ResponseAdapter(response.status, response.reason,
                                   content, response)
