#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Protocol-specific utility functions.
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


class HttpClient(object):
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
            pass
#            http = _AsyncHttpClient()
#
#            if args or kwargs:
#                async_callback = partial(async_callback, *args, **kwargs)
#
#            def adapt_response(response):
#                async_callback(ResponseAdapter(response.status_code,
#                                               response.status,
#                                               response.content,
#                                               response.headers))
#            http.fetch(
#                url=request.url,
#                body=request.body,
#                method=request.method,
#                headers=request.headers,
#                callback=adapt_response,
#                deadline=10
#            )
        else:
            try:
                response = urlfetch.fetch(
                    url=request.url,
                    payload=request.body,
                    method=request.method,
                    headers=request.headers,
                    deadline=10)
            except urlfetch.DownloadError, e:
                logging.exception(e)
                response = None
            return ResponseAdapter(response.status_code, response.status,
                                   response.content, response.headers)

