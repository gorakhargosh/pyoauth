#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

from mom._compat import have_python3
from mom.builtins import b

if have_python3:
    from tests import py3kconstants
    constants = py3kconstants
else:
    from tests import py2kconstants
    constants = py2kconstants

    
__all__ = [
    "constants"
]


TEST_CONSUMER_KEY = b("consumer-key")
TEST_NONCE = b("nonce")
TEST_TIMESTAMP = b("timestamp")
TEST_IGNORE_THIS_TEXT = b("ignore-this")
TEST_TOKEN = b("token")
TEST_EXTRA_PARAM_VALUE = b("extra-parameter")

RFC_CLIENT_IDENTIFIER = b("dpf43f3p2l4k3l03")
RFC_CLIENT_SECRET = b("kd94hf93k423kf44")
RFC_TEMPORARY_IDENTIFIER = b("hh5s93j4hdidpola")
RFC_TEMPORARY_SECRET = b("hdhd0244k9j7ao03")
RFC_TOKEN_IDENTIFIER = b("nnch734d00sl2jdk")
RFC_TOKEN_SECRET = b("pfkkdhi9sl3r4s00")
RFC_OAUTH_VERIFIER = b("hfdp7dh39dks9884")

BAD_RFC_TEMP_CREDENTIALS_RESPONSE = b("oauth_token=hh5s93j4hdidpola\
&oauth_token_secret=hdhd0244k9j7ao03")
RFC_TEMP_CREDENTIALS_RESPONSE = b("oauth_token=hh5s93j4hdidpola\
&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true")
RFC_TOKEN_CREDENTIALS_RESPONSE = b("oauth_token=nnch734d00sl2jdk\
&oauth_token_secret=pfkkdhi9sl3r4s00")

RFC_TEMP_URI = b("https://photos.example.net/initiate")
RFC_TOKEN_URI = b("https://photos.example.net/token")
RFC_AUTHORIZATION_URI = b("https://photos.example.net/authorize")
RFC_AUTHENTICATION_URI = b("https://photos.example.net/authenticate")
RFC_OAUTH_CALLBACK_URI = b("http://printer.example.com/ready")
RFC_RESOURCE_URI = b("http://photos.example.net/photos")
RFC_RESOURCE_FULL_URL = \
    b("http://photos.example.net/photos?file=vacation.jpg&size=original")
FOO_URI = b("http://example.com/foo")

BAD_SIGNATURE_METHOD = b("HMAC-SHOOOOOO1")
BAD_SIGNATURE = b("BOOM!")
BAD_OAUTH_CALLBACK = b("foobar")
BAD_CREDENTIALS_CONTENT_TYPE = b('INVALID-CONTENT-TYPE')

RFC_TIMESTAMP_1 = b("137131200")
RFC_TIMESTAMP_2 = b("137131201")
RFC_TIMESTAMP_3 = b("137131202")

RFC_NONCE_1 = b("wIjqoS")
RFC_NONCE_2 = b("walatlh")
RFC_NONCE_3 = b("chapoH")

RFC_REALM = b("Photos")
RFC_TEMP_REQUEST_SIGNATURE = b("74KNZJeDHnMBp0EMJ9ZHt/XKycU=")
RFC_TOKEN_REQUEST_SIGNATURE = b("gKgrFCywp7rO0OXSjdot/IHF7IU=")
RFC_RESOURCE_REQUEST_SIGNATURE = b("MdpQcU8iPSUjWoN/UDMsK2sui9I=")
RFC_RESOURCE_REQUEST_SIGNATURE_ENCODED = b("MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D")

CONTENT_TYPE_TEXT_CSS = b("text/css")
