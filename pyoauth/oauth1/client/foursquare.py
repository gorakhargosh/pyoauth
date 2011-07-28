#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Foursquare OAuth 1.0 Client.
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

# TODO: Largely untested because I don't have an OAuth 1.0 consumer.

"""
:module: pyoauth.oauth1.client.foursquare
:synopsis: Foursquare OAuth 1.0 client implementation.

.. autoclass:: FoursquareClient
   :members:
   :show-inheritance:
"""

from mom.builtins import is_bytes_or_unicode
from pyoauth.oauth1.client import Client


class FoursquareClient(Client):
    """
    """
    _TEMP_URI = "https://www.foursquare.com/oauth/request_token"
    _TOKEN_URI = "https://www.foursquare.com/oauth/access_token"
    _AUTHORIZATION_URI = "https://www.foursquare.com/oauth/authorize"
    # Automatically redirects if user has already authorized.
    _AUTHENTICATION_URI = "https://www.foursquare.com/oauth/authenticate"
    _MOBILE_AUTHORIZATION_URI = "https://www.foursquare.com/mobile/oauth/authorize"
    # Automatically redirects if the user has already authorized.
    _MOBILE_AUTHENTICATION_URI = "https://www.foursquare.com/mobile/oauth/authenticate"

    def __init__(self,
                 http_client,
                 client_credentials,
                 use_authorization_header=True,
                 strict=False):

        super(FoursquareClient, self).__init__(
            http_client,
            client_credentials=client_credentials,
            temporary_credentials_uri=self._TEMP_URI,
            token_credentials_uri=self._TOKEN_URI,
            authorization_uri=self._AUTHORIZATION_URI,
            authentication_uri=self._AUTHENTICATION_URI,
            use_authorization_header=use_authorization_header,
            strict=strict,
        )
