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

from pyoauth.appengine.httpclient import HttpClient
from pyoauth.http import HttpAdapterMixin


class Webapp2HttpAdapterMixin(HttpAdapterMixin):
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

    @property
    def adapter_http_client(self):
        return HttpClient()
