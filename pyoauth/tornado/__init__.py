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


from __future__ import absolute_import
import logging

from mom.builtins import b
from mom.codec import base64_urlsafe_encode, base64_urlsafe_decode
from pyoauth.constants import SYMBOL_PIPE, OAUTH_TEMP_COOKIE_NAME
from pyoauth.httplib2.httpclient import HttpClient
from pyoauth.http import HttpAdapterMixin as _HttpAdapterMixin
from pyoauth.oauth1 import Credentials


class HttpAdapterMixin(_HttpAdapterMixin):
    # Framework-specific adaptor.
    # This one is for tornado.
    @property
    def adapter_request_full_url(self):
        return self.request.full_url()

    @property
    def adapter_request_path(self):
        return self.request.uri

    @property
    def adapter_request_params(self):
        return self.request.arguments

    def adapter_request_get(self, *args, **kwargs):
        return self.get_argument(*args, **kwargs)

    @property
    def adapter_request_host(self):
        return self.request.host

    @property
    def adapter_request_scheme(self):
        return self.request.protocol

    def adapter_redirect(self, url):
        self.redirect(url)

    def adapter_abort(self, status_code):
        from tornado.web import HTTPError
        raise HTTPError(status_code, "Error")

    def adapter_set_secure_cookie(self, cookie, value):
        self.set_cookie(cookie, value)

    def adapter_get_secure_cookie(self, cookie):
        return self.get_cookie(cookie)

    def adapter_delete_cookie(self, cookie):
        self.clear_cookie(cookie)

    def adapter_read_credentials_cookie(self, name=OAUTH_TEMP_COOKIE_NAME):
        # Get the temporary credentials stored in the secure cookie and clear
        # the cookie.
        cookie = self.adapter_get_secure_cookie(name)
        if cookie:
            self.adapter_delete_cookie(name)
            id, secret = map(base64_urlsafe_decode, cookie.split(SYMBOL_PIPE))
            return Credentials(id, secret)
        else:
            logging.warning("Missing OAuth temporary credentials cookie.")
            return None

    def adapter_set_credentials_cookie(self, credentials,
                                       cookie_name=OAUTH_TEMP_COOKIE_NAME):
        value = SYMBOL_PIPE.join(map(base64_urlsafe_encode,
                                     [credentials.identifier,
                                     credentials.shared_secret]))
        self.adapter_set_secure_cookie(cookie_name, value)

    @property
    def adapter_http_client(self):
        return HttpClient()
