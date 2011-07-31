#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
import logging

from pyoauth.appengine.httpclient import HttpClient
from pyoauth.http import HttpAdapterMixin as _HttpAdapterMixin
from pyoauth.oauth1 import Credentials


class HttpAdapterMixin(_HttpAdapterMixin):
    # Framework-specific adaptor.
    # This one is for webapp2.
    @property
    def adapter_request_full_url(self):
        return self.request.url

    @property
    def adapter_request_path(self):
        return self.request.path

    @property
    def adapter_request_params(self):
        return self.request.params

    def adapter_request_get(self, *args, **kwargs):
        return self.request.get(*args, **kwargs)

    @property
    def adapter_request_host(self):
        return self.request.host

    @property
    def adapter_request_scheme(self):
        return self.request.scheme

    def adapter_redirect(self, url):
        self.redirect(url)

    def adapter_abort(self, status_code):
        self.abort(status_code)

    def adapter_set_secure_cookie(self, cookie, value):
        self.session_store.set_secure_cookie(cookie, value)

    def adapter_get_secure_cookie(self, cookie):
        return self.session_store.get_secure_cookie(cookie)

    def adapter_delete_cookie(self, cookie):
        self.response.delete_cookie(cookie)

    def adapter_read_credentials_cookie(self, name="_oauth_temporary_credentials"):
        # Get the temporary credentials stored in the secure cookie and clear
        # the cookie.
        cookie = self.adapter_get_secure_cookie(name)
        if cookie:
            self.adapter_delete_cookie(name)
            return Credentials(**cookie)
        else:
            logging.warning("Missing OAuth temporary credentials cookie.")
            return None

    def adapter_set_credentials_cookie(self, credentials, cookie_name="_oauth_temporary_credentials"):
        self.adapter_set_secure_cookie(cookie_name, credentials.to_dict())

    @property
    def adapter_http_client(self):
        return HttpClient()
