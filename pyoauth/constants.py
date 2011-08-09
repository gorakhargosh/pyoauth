#!/usr/bin/env python
# -*- coding: utf-8 -*-
# All the constants used throughout the codebase.
#

from __future__ import absolute_import

import re
from mom.builtins import b

SYMBOL_AMPERSAND = b("&")
SYMBOL_EMPTY_BYTES = b("")
SYMBOL_COMMA = b(",")
SYMBOL_EQUAL = b("=")
SYMBOL_INVERTED_DOUBLE_QUOTE = b('"')
SYMBOL_NEWLINE = b("\n")

OAUTH_REALM = b("realm")
OAUTH_AUTH_SCHEME = b('OAuth ')
OAUTH_AUTH_SCHEME_LOWERCASE = b("oauth ")
OAUTH_AUTH_SCHEME_PATTERN = re.compile(b(r"(^OAuth[\s]+)"), re.IGNORECASE)
OAUTH_AUTH_HEADER_PREFIX = b('OAuth realm="')

OAUTH_PARAM_SIGNATURE = b("oauth_signature")
OAUTH_PARAM_CONSUMER_SECRET = b("oauth_consumer_secret")
OAUTH_PARAM_TOKEN_SECRET = b("oauth_token_secret")

