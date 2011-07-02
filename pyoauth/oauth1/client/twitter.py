#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Twitter OAuth 1.0 Client.
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


from pyoauth.oauth1.client import Client

class TwitterClient(Client):
    """
    Creates an instance of a Twitter OAuth 1.0 client.
    """
    _OAUTH_TEMPORARY_CREDENTIALS_REQUEST_URI = "https://api.twitter.com/oauth/request_token"
    _OAUTH_RESOURCE_OWNER_AUTHORIZATION_URI = "https://api.twitter.com/oauth/authorize"
    _OAUTH_TOKEN_CREDENTIALS_REQUEST_URI = "https://api.twitter.com/oauth/access_token"

    def __init__(self,
                 client_credentials,
                 use_authorization_header=True):
        super(TwitterClient, self).__init__(
            client_credentials=client_credentials,
            temporary_credentials_request_uri=self._OAUTH_TEMPORARY_CREDENTIALS_REQUEST_URI,
            resource_owner_authorization_uri=self._OAUTH_RESOURCE_OWNER_AUTHORIZATION_URI,
            token_credentials_request_uri=self._OAUTH_TEMPORARY_CREDENTIALS_REQUEST_URI,
            use_authorization_header=use_authorization_header
        )

