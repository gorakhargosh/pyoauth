#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Rodrigo Moraes <rodrigo.moraes@gmail.com>
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

import logging

from functools import partial
from google.appengine.api import urlfetch

from pyoauth.http import ResponseAdapter
from vendor.mom.mom.builtins import b


class HttpResponseError(object):
    """A dummy response used when urlfetch raises an exception."""
    status_code = 404
    content = '404 Not Found'
    status = 'Error 404'
    headers = None

class _AsyncHttpClient(object):
    """An non-blocking HTTP client that uses `google.appengine.api.urlfetch`."""
    def fetch(self, url, callback, **kwargs):
        # Replace kwarg keys.
        kwargs['payload'] = kwargs.pop('body', None)

        rpc = urlfetch.create_rpc()
        rpc.callback = create_rpc_callback(rpc, callback)
        urlfetch.make_fetch_call(rpc, url, **kwargs)
        rpc.wait()


def create_rpc_callback(rpc, callback, *args, **kwargs):
    """Returns a wrapped callback for an async request."""
    if callback is None:
        return None

    if args or kwargs:
        callback = partial(callback, *args, **kwargs)

    def wrapper(*args, **kwargs):
        try:
            result = rpc.get_result()
            code = result.status_code
            # Add 'body' and 'error' attributes expected by tornado.
            setattr(result, 'body', result.content)
            if code < 200 or code >= 300:
                setattr(result, 'error', 'Error %d' % code)
            else:
                setattr(result, 'error', None)

        except urlfetch.DownloadError, e:
            logging.exception(e)
            result = HttpResponseError()

        try:
            args += (result,)
            return callback(*args, **kwargs)
        except Exception:
            logging.error("Exception during callback", exc_info=True)

    return wrapper


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
            http = _AsyncHttpClient()

            if args or kwargs:
                async_callback = partial(async_callback, *args, **kwargs)

            def adapt_response(response):
                async_callback(ResponseAdapter(response.status_code,
                                               response.status,
                                               response.content,
                                               response.headers))
            http.fetch(
                url=request.url,
                body=request.body,
                method=request.method,
                headers=request.headers,
                callback=adapt_response,
                deadline=10
            )
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

