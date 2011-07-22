#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Tornado-compliant asynchronous HTTP client interface.


import logging

from functools import partial
from google.appengine.api import urlfetch
from pyoauth.http import ResponseAdapter


class HttpResponseError(object):
    """A dummy response used when urlfetch raises an exception."""
    code = 404
    body = '404 Not Found'
    error = 'Error 404'

class AsyncHTTPClient(object):
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
        except Exception, e:
            logging.error("Exception during callback", exc_info=True)

    return wrapper


class HttpAdapterMixin(object):
    # Framework-specific adaptor.
    # This one is for webapp2.
    @property
    def _oauth_request_full_url(self):
        return self.request.url

    @property
    def _oauth_request_path(self):
        return self.request.path

    def _oauth_request_get(self, argument):
        return self.request.get(argument)

    def _oauth_redirect(self, url):
        self.redirect(url)

    def _oauth_abort(self, status_code):
        self.abort(status_code)

    def _oauth_set_secure_cookie(self, cookie, value):
        self.session_store.set_secure_cookie(cookie, value)

    def _oauth_get_secure_cookie(self, cookie):
        return self.session_store.get_secure_cookie(cookie)

    def _oauth_delete_cookie(self, cookie):
        self.response.delete_cookie(cookie)

    def _oauth_fetch(self, request, async_callback=None, *args, **kwargs):
        """
        Fetches a response from the OAuth server for a given OAuth request.

        Self contained HTTP request method can be replaced with
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
            http = AsyncHTTPClient()

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

