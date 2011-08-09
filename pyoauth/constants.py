#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# All the byte literals used throughout the codebase.
#
# The major reason why we're doing this is to avoid the call overhead to
# b() repeatedly. We need b() because we're supporting Python 2.5 as well
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

OAUTH_VERSION_1 = b("1.0")
OAUTH_REALM = b("realm")
OAUTH_AUTH_SCHEME = b('OAuth ')
OAUTH_AUTH_SCHEME_LOWERCASE = b("oauth ")
OAUTH_AUTH_SCHEME_PATTERN = re.compile(b(r"(^OAuth[\s]+)"), re.IGNORECASE)
OAUTH_AUTH_HEADER_PREFIX = b('OAuth realm="')

OAUTH_PARAM_PREFIX = b("oauth_")
OAUTH_PARAM_SIGNATURE = b("oauth_signature")
OAUTH_PARAM_CONSUMER_SECRET = b("oauth_consumer_secret")
OAUTH_PARAM_TOKEN_SECRET = b("oauth_token_secret")
OAUTH_PARAM_TOKEN = b("oauth_token")
OAUTH_PARAM_VERSION = b("oauth_version")
OAUTH_PARAM_SIGNATURE_METHOD = b("oauth_signature_method")
OAUTH_PARAM_CALLBACK = b("oauth_callback")
OAUTH_PARAM_CALLBACK_CONFIRMED = b("oauth_callback_confirmed")
OAUTH_VALUE_CALLBACK_CONFIRMED = b("true")
OAUTH_VALUE_CALLBACK_OOB = b("oob")


HTTP_GET = b("GET")
HTTP_POST = b("POST")

HEADER_CONTENT_TYPE = b("content-type")
HEADER_CONTENT_TYPE_CAPS = b("Content-Type")
HEADER_AUTHORIZATION = b("authorization")
HEADER_AUTHORIZATION_CAPS = b("Authorization")
HEADER_CONTENT_LENGTH = b("content-length")
HEADER_CONTENT_LENGTH_CAPS = b("Content-Length")
