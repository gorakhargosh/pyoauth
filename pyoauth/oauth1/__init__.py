# -*- coding: utf-8 -*-
# OAuth 1.0 implementation.
#
# Copyright (C) 2007-2010 Leah Culver, Joe Stump, Mark Paschal, Vic Fryzel
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
#
# MIT License
# -----------
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import httplib2
from pyoauth import OAuthToken, \
    SIGNATURE_METHODS, \
    SIGNATURE_METHOD_PLAINTEXT, \
    SIGNATURE_METHOD_RSA_SHA1, \
    SIGNATURE_METHOD_HMAC_SHA1
from pyoauth.utils import \
    oauth_get_rsa_sha1_signature, \
    oauth_get_hmac_sha1_signature, \
    oauth_get_plaintext_signature, \
    oauth_generate_nonce, \
    oauth_generate_verification_code, \
    oauth_generate_timestamp

signature_method_map = {
    SIGNATURE_METHOD_HMAC_SHA1: oauth_get_hmac_sha1_signature,
    SIGNATURE_METHOD_RSA_SHA1: oauth_get_rsa_sha1_signature,
    SIGNATURE_METHOD_PLAINTEXT: oauth_get_plaintext_signature,
}


class Consumer(object):

    _OAUTH_VERSION = "1.0"

    def __init__(self,
                 oauth_consumer_key,
                 oauth_consumer_secret,
                 oauth_request_token_url,
                 oauth_access_token_url,
                 oauth_authorize_url,
                 signature_method=SIGNATURE_METHOD_HMAC_SHA1):

        if signature_method not in SIGNATURE_METHODS:
            raise ValueError("Expected one of %s for signature method: got `%s` instead" % (SIGNATURE_METHODS, signature_method))

        self._consumer_token = OAuthToken(oauth_consumer_key,
                                          oauth_consumer_secret)
        self._request_token_url = oauth_request_token_url
        self._access_token_url = oauth_access_token_url
        self._authorize_url = oauth_authorize_url
        self._signature_method = signature_method
        self._httpClient = httplib2.Http()

    def get_request_token(self, callback_uri=None):
        query_params = dict(
            oauth_consumer_key=self._consumer_token.key,
            oauth_signature_method=self._signature_method,
            oauth_timestamp=oauth_generate_timestamp(),
            oauth_nonce=oauth_generate_nonce(),
            oauth_version=self._OAUTH_VERSION,
        )

    def get_access_token(self, request_token, callback_uri=None):
        pass

    def service_request(self, access_token, method, url, **query_params):
        pass
