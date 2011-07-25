#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest2
from pyoauth.error import InvalidSignatureMethodError, IllegalArgumentError, InvalidHttpResponseError, HttpError, InvalidContentTypeError
from pyoauth.http import ResponseAdapter
from pyoauth.oauth1 import Credentials
from pyoauth.oauth1.client import _OAuthClient
from mom.builtins import is_bytes, is_bytes_or_unicode

class Test__OAuthClient_oauth_version(unittest2.TestCase):
    def test_default_is_1_0(self):
        self.assertEqual(_OAuthClient(None, None).oauth_version, "1.0")

class Test__OAuthClient_generate_nonce(unittest2.TestCase):
    def test_uniqueness(self):
        self.assertNotEqual(_OAuthClient.generate_nonce(), _OAuthClient.generate_nonce())

    def test_unsigned_integer(self):
        self.assertTrue(int(_OAuthClient.generate_nonce()) >= 0)

    def test_result_is_string(self):
        self.assertTrue(is_bytes(_OAuthClient.generate_nonce()))

class Test__OAuthClient_generate_timestamp(unittest2.TestCase):
    def test_is_positive_integer_string(self):
        self.assertTrue(int(_OAuthClient.generate_timestamp()) > 0,
                    "Timestamp is not positive integer string.")

    def test_is_string(self):
        self.assertTrue(is_bytes_or_unicode(_OAuthClient.generate_timestamp()),
                    "Timestamp is not a string.")

    def test_is_not_empty_string(self):
        self.assertTrue(len(_OAuthClient.generate_timestamp()) > 0,
                    "Timestamp is an empty string.")

class Test__OAuthClient__generate_oauth_params(unittest2.TestCase):
    def test_generates_oauth_params(self):
        args_no_token = dict(
            oauth_consumer_key="consumer-key",
            oauth_signature_method="HMAC-SHA1",
            oauth_version="1.0",
            oauth_nonce="nonce",
            oauth_timestamp="timestamp",
            oauth_token=None,
            oauth_extra="extra-parameter",
        )
        args_with_token = dict(
            oauth_consumer_key="consumer-key",
            oauth_signature_method="HMAC-SHA1",
            oauth_version="1.0",
            oauth_nonce="nonce",
            oauth_timestamp="timestamp",
            oauth_token="token",
            oauth_extra="extra-parameter",
        )

        args1 = dict(
            non_oauth_param="ignore-this",
        )
        args1.update(args_no_token)
        del args_no_token["oauth_token"]
        self.assertDictEqual(_OAuthClient._generate_oauth_params(**args1),
                             args_no_token)

        args2 = dict(
            non_oauth_param="ignore-this",
        )
        args2.update(args_with_token)
        self.assertDictEqual(_OAuthClient._generate_oauth_params(**args2),
                             args_with_token)

    def test_InvalidSignatureMethodError_when_invalid_signature_method(self):
        args_no_token = dict(
            oauth_consumer_key="consumer-key",
            oauth_signature_method="HMAC-SHOOOOOO1",
            oauth_version="1.0",
            oauth_nonce="nonce",
            oauth_timestamp="timestamp",
            oauth_token=None,
            oauth_extra="extra-parameter",
        )
        self.assertRaises(InvalidSignatureMethodError,
                          _OAuthClient._generate_oauth_params, **args_no_token)

    def test_IllegalArgumentError_when_signature_specified(self):
        args_no_token = dict(
            oauth_consumer_key="consumer-key",
            oauth_signature_method="HMAC-SHA1",
            oauth_version="1.0",
            oauth_nonce="nonce",
            oauth_timestamp="timestamp",
            oauth_token=None,
            oauth_extra="extra-parameter",
            oauth_signature="BOOM!"
        )
        self.assertRaises(IllegalArgumentError,
                          _OAuthClient._generate_oauth_params, **args_no_token)

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

class Test__OAuthClient_misc(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(identifier="dpf43f3p2l4k3l03", shared_secret="kd94hf93k423kf44")
        self.temporary_credentials = Credentials(identifier="hh5s93j4hdidpola", shared_secret="hdhd0244k9j7ao03")
        self.token_credentials = Credentials(identifier="nnch734d00sl2jdk", shared_secret="pfkkdhi9sl3r4s00")

    def test_parse_temporary_credentials_response(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.assertRaises(ValueError, _OAuthClient.parse_temporary_credentials_response, ResponseAdapter(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=", headers))
        self.assertRaises(ValueError, _OAuthClient.parse_temporary_credentials_response, ResponseAdapter(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=false", headers))

        credentials, params = _OAuthClient.parse_temporary_credentials_response(ResponseAdapter(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true", headers=headers))
        self.assertDictEqual(params, {
            "oauth_token": ["hh5s93j4hdidpola"],
            "oauth_token_secret": ["hdhd0244k9j7ao03"],
            "oauth_callback_confirmed": ["true"],
        })
        self.assertEqual(credentials, self.temporary_credentials)

    def test_parse_token_credentials_response(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        credentials, params = _OAuthClient.parse_token_credentials_response(ResponseAdapter(200, "OK", "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00", headers=headers))
        self.assertDictEqual(params, {
            "oauth_token": ["nnch734d00sl2jdk"],
            "oauth_token_secret": ["pfkkdhi9sl3r4s00"],
        })
        self.assertEqual(credentials, self.token_credentials)

    def test__parse_credentials_response(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        credentials, params = _OAuthClient._parse_credentials_response(ResponseAdapter(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true", headers=headers))
        self.assertDictEqual(params, {
            "oauth_token": ["hh5s93j4hdidpola"],
            "oauth_token_secret": ["hdhd0244k9j7ao03"],
            "oauth_callback_confirmed": ["true"],
        })
        self.assertEqual(credentials, self.temporary_credentials)

        credentials, params = _OAuthClient._parse_credentials_response(ResponseAdapter(200, "OK", "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00", headers=headers))
        self.assertDictEqual(params, {
            "oauth_token": ["nnch734d00sl2jdk"],
            "oauth_token_secret": ["pfkkdhi9sl3r4s00"],
        })
        self.assertEqual(credentials, self.token_credentials)

    def test_parse_credentials_response_validation(self):
        status_code = 200
        status = "OK"
        body = "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.assertRaises(InvalidHttpResponseError, _OAuthClient._parse_credentials_response, ResponseAdapter(status_code, None, body, headers))
        self.assertRaises(InvalidHttpResponseError, _OAuthClient._parse_credentials_response, ResponseAdapter(None, status, body, headers))
        self.assertRaises(InvalidHttpResponseError, _OAuthClient._parse_credentials_response, ResponseAdapter(status_code, status, None, headers))
        self.assertRaises(InvalidHttpResponseError, _OAuthClient._parse_credentials_response, ResponseAdapter(status_code, status, body, None))

        self.assertRaises(HttpError, _OAuthClient._parse_credentials_response, ResponseAdapter(300, "Multiple choices", body, headers))
        self.assertRaises(HttpError, _OAuthClient._parse_credentials_response, ResponseAdapter(199, "continue", body, headers))

        self.assertRaises(InvalidHttpResponseError, _OAuthClient._parse_credentials_response, ResponseAdapter(200, "OK" , "", headers))
        self.assertRaises(InvalidContentTypeError, _OAuthClient._parse_credentials_response, ResponseAdapter(200, "OK", body, {"Content-Type": "invalid"}))
