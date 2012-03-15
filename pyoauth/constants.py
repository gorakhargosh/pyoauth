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

# -----------------------------------------------------------------------------
# All the byte literals used throughout the codebase.
#
# The major reason why we're doing this is to avoid the call overhead to
# b() repeatedly. The second reason is when we drop support for Python 2.5.
# there's only one place to edit and get rid of b() (well, almost).
#
# We need b() because we're supporting Python 2.5 as well
# which does not have byte literal syntax sugar. b fakes it for all versions
# of Python 2.5+.

from __future__ import absolute_import

import re
from mom.builtins import b

SYMBOL_AMPERSAND = b("&")
SYMBOL_EMPTY_BYTES = b("")
SYMBOL_COMMA = b(",")
SYMBOL_EQUAL = b("=")
SYMBOL_INVERTED_DOUBLE_QUOTE = b('"')
SYMBOL_NEWLINE = b("\n")
SYMBOL_SEMICOLON = b(";")
SYMBOL_PIPE = b("|")
SYMBOL_ZERO = b("0")
SYMBOL_SPACE = b(" ")
SYMBOL_QUESTION_MARK = b("?")

# Used in construction.
OAUTH_VERSION_1 = b("1.0")
OAUTH_REALM = b("realm")
OAUTH_AUTH_SCHEME_PATTERN = re.compile(r"(^OAuth[\s]+)", re.IGNORECASE)

OAUTH_PARAM_REALM = "realm"
OAUTH_PARAM_PREFIX = "oauth_"
OAUTH_PARAM_SIGNATURE = "oauth_signature"
OAUTH_PARAM_CONSUMER_KEY = "oauth_consumer_key"
OAUTH_PARAM_CONSUMER_SECRET = "oauth_consumer_secret"
OAUTH_PARAM_TOKEN_SECRET = "oauth_token_secret"
OAUTH_PARAM_TOKEN = "oauth_token"
OAUTH_PARAM_NONCE = "oauth_nonce"
OAUTH_PARAM_TIMESTAMP = "oauth_timestamp"
OAUTH_PARAM_VERSION = "oauth_version"
OAUTH_PARAM_VERIFIER = "oauth_verifier"
OAUTH_PARAM_SIGNATURE_METHOD = "oauth_signature_method"
OAUTH_PARAM_CALLBACK = "oauth_callback"
OAUTH_PARAM_CALLBACK_CONFIRMED = "oauth_callback_confirmed"

OAUTH_VALUE_CALLBACK_CONFIRMED = b("true")
OAUTH_VALUE_CALLBACK_OOB = b("oob")

OAUTH_TEMP_COOKIE_NAME = b("_oauthtempcred")

HMAC_SHA1 = b("HMAC-SHA1")
RSA_SHA1 = b("RSA-SHA1")
PLAINTEXT = b("PLAINTEXT")

HTTP_GET = b("GET")
HTTP_POST = b("POST")
HTTP_REASON_OK = b("OK")
HTTP_REASON_MULTIPLE_CHOICES = b("Multiple choices")
HTTP_REASON_CONTINUE = b("continue")

HEADER_CONTENT_TYPE = "content-type"
HEADER_CONTENT_TYPE_CAPS = "Content-Type"
HEADER_AUTHORIZATION = "authorization"
HEADER_AUTHORIZATION_CAPS = "Authorization"
HEADER_CONTENT_LENGTH = "content-length"
HEADER_CONTENT_LENGTH_CAPS = "Content-Length"

OPENID_MODE_CHECK_AUTHENTICATION = "check_authentication"
                                   # u"check_authentication"
OPENID_MODE_CHECKID_SETUP = "checkid_setup"
OPENID_AX_MODE_FETCH_REQUEST = "fetch_request"
