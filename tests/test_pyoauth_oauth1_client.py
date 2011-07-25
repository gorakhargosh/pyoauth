#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest2
from pyoauth.error import InvalidSignatureMethodError
from pyoauth.oauth1.client import _OAuthClient

class Test__OAuthClient_oauth_version(unittest2.TestCase):
    def test_default_is_1_0(self):
        self.assertEqual(_OAuthClient(None, None).oauth_version, "1.0")

class Test__OAuthClient__generate_signature(unittest2.TestCase):
    def test_generates_signature(self):
        params = {
            "method": "POST",
            "realm": "Photos",
            "url": "https://photos.example.net/initiate",
            "oauth_consumer_secret": "kd94hf93k423kf44",
            "oauth_token_secret": None,
            "oauth_signature": "74KNZJeDHnMBp0EMJ9ZHt/XKycU=",
            "oauth_params": dict(
                oauth_consumer_key="dpf43f3p2l4k3l03",
                oauth_signature_method="HMAC-SHA1",
                oauth_timestamp="137131200",
                oauth_nonce="wIjqoS",
                oauth_callback="http://printer.example.com/ready",
            )
        }
        self.assertEqual(_OAuthClient._generate_signature(
            params["method"],
            params["url"],
            None,
            params["oauth_consumer_secret"],
            params["oauth_token_secret"],
            params["oauth_params"],
        ), params["oauth_signature"])

    def test_raises_InvalidSignatureMethodError_when_invalid_signature_method(self):
        params = {
            "method": "POST",
            "url": "https://photos.example.net/initiate",
            "oauth_consumer_secret": "kd94hf93k423kf44",
            "oauth_token_secret": None,
            "oauth_params": dict(
                oauth_consumer_key="dpf43f3p2l4k3l03",
                oauth_signature_method="HMAC-SHOOOOOOOOOOOOOOO1",
                oauth_timestamp="137131200",
                oauth_nonce="wIjqoS",
                oauth_callback="http://printer.example.com/ready",
            )
        }
        self.assertRaises(InvalidSignatureMethodError,
              _OAuthClient._generate_signature,
              params["method"],
              params["url"],
              None,
              params["oauth_consumer_secret"],
              params["oauth_token_secret"],
              params["oauth_params"],
        )

    def test_raises_KeyError_when_missing_signature_method(self):
        params = {
            "method": "POST",
            "url": "https://photos.example.net/initiate",
            "oauth_consumer_secret": "kd94hf93k423kf44",
            "oauth_token_secret": None,
            "oauth_params": dict(
                oauth_consumer_key="dpf43f3p2l4k3l03",
                oauth_timestamp="137131200",
                # oauth_signature_method="HMAC-SHOOOOOOOOOOOOOOO1",
                oauth_nonce="wIjqoS",
                oauth_callback="http://printer.example.com/ready",
            )
        }
        self.assertRaises(KeyError, _OAuthClient._generate_signature,
              params["method"],
              params["url"],
              None,
              params["oauth_consumer_secret"],
              params["oauth_token_secret"],
              params["oauth_params"],
        )

