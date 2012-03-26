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


from __future__ import absolute_import

from mom.builtins import b
from pyoauth.oauth1.client import Client
from pyoauth.oauth1.client.mixins import OAuthMixin


class TwitterClient(Client):
    """
    Creates an instance of a Twitter OAuth 1.0 client.
    """
    _TEMP_URI = b("https://api.twitter.com/oauth/request_token")
    _TOKEN_URI = b("https://api.twitter.com/oauth/access_token")
    _AUTHORIZATION_URI = b("https://api.twitter.com/oauth/authorize")
    _AUTHENTICATION_URI = b("https://api.twitter.com/oauth/authenticate")

    def __init__(self,
                 http_client,
                 client_credentials,
                 use_authorization_header=True,
                 strict=False):
        super(TwitterClient, self).__init__(
            http_client,
            client_credentials,
            self._TEMP_URI,
            self._TOKEN_URI,
            self._AUTHORIZATION_URI,
            self._AUTHENTICATION_URI,
            use_authorization_header=use_authorization_header,
            strict=strict
        )


class TwitterMixin(OAuthMixin):
    """
    OAuth handler mixin. Use with an HttpAdapterMixin for your framework.
    """
    pass

