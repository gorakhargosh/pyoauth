#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest2
from pyoauth.error import InvalidSignatureMethodError, IllegalArgumentError, InvalidHttpResponseError, HttpError, InvalidContentTypeError, InvalidHttpRequestError, InvalidAuthorizationHeaderError
from pyoauth.http import ResponseAdapter, RequestAdapter
from pyoauth.oauth1 import Credentials
from pyoauth.oauth1.client import _OAuthClient, Client
from mom.builtins import is_bytes, is_bytes_or_unicode
from pyoauth.protocol import parse_authorization_header

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


class Test__OAuthClient_check_verification_code(unittest2.TestCase):
    def test_raises_InvalidHttpRequestError_when_identifier_invalid(self):
        temporary_credentials = Credentials(identifier="hh5s93j4hdidpola",
                                            shared_secret="hdhd0244k9j7ao03")

        self.assertRaises(InvalidHttpRequestError,
                          _OAuthClient.check_verification_code,
                          temporary_credentials, "non-matching-token",
                          "verification-code")

    def test_returns_verification_code(self):
        temporary_credentials = Credentials(identifier="hh5s93j4hdidpola",
                                            shared_secret="hdhd0244k9j7ao03")
        self.assertEqual(
            _OAuthClient.check_verification_code(
                temporary_credentials,
                temporary_credentials.identifier,
                "verification-code"
            ), "verification-code")


class Test__OAuthClient_urls(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(identifier="dpf43f3p2l4k3l03",
                                              shared_secret="kd94hf93k423kf44")
        self.temporary_credentials = Credentials(identifier="hh5s93j4hdidpola",
                                                 shared_secret="hdhd0244k9j7ao03")
        self.token_credentials = Credentials(identifier="nnch734d00sl2jdk",
                                             shared_secret="pfkkdhi9sl3r4s00")
        args = dict(
            temporary_credentials_uri="https://photos.example.net/initiate",
            token_credentials_uri="https://photos.example.net/token",
            authorization_uri="https://photos.example.net/authorize",
            authentication_uri="https://photos.example.net/authenticate",
            use_authorization_header=True
        )
        self.client = Client(None, self.client_credentials, **args)

    def test___init__(self):
        c = self.client
        self.assertEqual(c._temporary_credentials_uri,
                         "https://photos.example.net/initiate")
        self.assertEqual(c._token_credentials_uri,
                         "https://photos.example.net/token")
        self.assertEqual(c._authorization_uri,
                         "https://photos.example.net/authorize")
        self.assertEqual(c._authentication_uri,
                         "https://photos.example.net/authenticate")
        self.assertEqual(c._use_authorization_header, True)
        self.assertEqual(c._client_credentials.identifier, "dpf43f3p2l4k3l03")
        self.assertEqual(c._client_credentials.shared_secret, "kd94hf93k423kf44")

    def test_get_authorization_url(self):
        url = self.client.get_authorization_url(self.temporary_credentials,
                                                a="something here",
                                                b=["another thing", 5],
                                                oauth_ignored="ignored")
        self.assertEqual(url,
                         "https://photos.example.net/authorize?" \
                         "a=something%20here" \
                         "&b=5" \
                         "&b=another%20thing&oauth_token=" +
                         self.temporary_credentials.identifier)

    def test_get_authentication_url(self):
        url = self.client.get_authentication_url(self.temporary_credentials,
                                                a="something here",
                                                b=["another thing", 5],
                                                oauth_ignored="ignored")
        self.assertEqual(url,
                         "https://photos.example.net/authenticate?" \
                         "a=something%20here" \
                         "&b=5" \
                         "&b=another%20thing&oauth_token=" +
                         self.temporary_credentials.identifier)

    def test_no_authentication_url(self):
        args = dict(
            temporary_credentials_uri="https://photos.example.net/initiate",
            token_credentials_uri="https://photos.example.net/token",
            authorization_uri="https://photos.example.net/authorize",
            authentication_uri=None,
            use_authorization_header=True
        )
        client = Client(None, self.client_credentials, **args)
        self.assertRaises(NotImplementedError,
                          client.get_authentication_url,
                          self.temporary_credentials,
                          a="something here",
                          b=["another thing", 5],
                          oauth_ignored="ignored")


class Test__OAuthClient__build_request(unittest2.TestCase):
    def test_auth_header(self):
        oauth_params = dict(
            oauth_blah="blah",
        )
        headers = {
            "something": "blah",
        }
        params = dict(a="b")
        expected = RequestAdapter("GET",
                                 "http://example.com/foo?a=b",
                                 None,
                                 {
                "Authorization": 'OAuth realm="realm",oauth_blah="blah"',
                "something": "blah",
            })
        got = _OAuthClient._build_request("GET",
                                          "http://example.com/foo",
                                          params, None, headers,
                                          oauth_params, "realm", True)
        self.assertEqual(expected.method, got.method)
        self.assertEqual(expected.url, got.url)
        self.assertEqual(expected.body, got.body)
        self.assertDictEqual(expected.headers, got.headers)

    def test_get_query_string(self):
        oauth_params = dict(
            oauth_blah="blah",
        )
        headers = {
            "something": "blah",
        }
        params = dict(a="b")
        expected = RequestAdapter("GET",
                                 "http://example.com/foo?a=b&oauth_blah=blah",
                                 None,
                                 {"something": "blah"})
        got = _OAuthClient._build_request("GET",
                                          "http://example.com/foo",
                                          params, None, headers,
                                          oauth_params, "realm", False)
        self.assertEqual(expected.method, got.method)
        self.assertEqual(expected.url, got.url)
        self.assertEqual(expected.body, got.body)
        self.assertDictEqual(expected.headers, got.headers)

    def test_payload(self):
        oauth_params = dict(
            oauth_blah="blah",
        )
        headers = {
            "something": "blah",
        }
        params = dict(a="b")
        expected = RequestAdapter("POST",
                                 "http://example.com/foo",
                                 "a=b&oauth_blah=blah",
                                 {
            "something": "blah",
            "Content-Type": "application/x-www-form-urlencoded"
        })
        got = _OAuthClient._build_request("POST",
                                          "http://example.com/foo",
                                          params, "", headers,
                                          oauth_params, "realm", False)
        self.assertEqual(expected.method, got.method)
        self.assertEqual(expected.url, got.url)
        self.assertEqual(expected.body, got.body)
        self.assertDictEqual(expected.headers, got.headers)

    def test_raises_InvalidHttpRequestError_when_body_and_GET(self):
        oauth_params = dict(
            oauth_blah="blah",
        )
        self.assertRaises(InvalidHttpRequestError,
                          _OAuthClient._build_request,
                          "GET",
                          "http://example.com/foo",
                          None, "a=b", {}, oauth_params,
                          "realm", False)

    def test_raises_InvalidAuthorizationHeaderError_when_auth_present(self):
        oauth_params = dict(
            oauth_blah="blah",
        )
        self.assertRaises(InvalidAuthorizationHeaderError,
                          _OAuthClient._build_request,
                          "POST",
                          "http://example.com/foo",
                          None, "a=b", {"Authorization": ""}, oauth_params,
                          "realm", False)

class Test__OAuthClient__request(unittest2.TestCase):
    def test__request_data(self):
        expected = RequestAdapter(
            'POST',
            'https://photos.example.net/initiate',
            '',
            headers = {
                "Authorization": '''\
OAuth realm="Photos",\
oauth_consumer_key="dpf43f3p2l4k3l03",\
oauth_signature_method="HMAC-SHA1",\
oauth_timestamp="137131200",\
oauth_nonce="wIjqoS",\
oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready",\
oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"''',
            }
        )
        client_credentials = Credentials('dpf43f3p2l4k3l03', 'kd94hf93k423kf44')

        class MockClient(_OAuthClient):
            @classmethod
            def generate_timestamp(cls):
                return "137131200"

            @classmethod
            def generate_nonce(cls):
                return "wIjqoS"

        got = MockClient._request(
            client_credentials,
            'POST',
            'https://photos.example.net/initiate',
            realm='Photos',
            oauth_version=None,
            oauth_callback='http://printer.example.com/ready'
        )
        self.assertEqual(got.method, expected.method)
        self.assertEqual(got.url, expected.url)
        self.assertEqual(got.body, expected.body)
        expected_headers, expected_realm = parse_authorization_header(
            expected.headers["Authorization"],
        )
        got_headers, got_realm = parse_authorization_header(
            got.headers["Authorization"],
        )
        self.assertDictEqual(got_headers, expected_headers)
        self.assertEqual(got_realm, expected_realm)

    def test__resource_request_data(self):
        expected = RequestAdapter(
            'GET',
            'http://photos.example.net/photos?file=vacation.jpg&size=original',
            '',
            headers = {
                "Authorization": '''\
OAuth realm="Photos",\
oauth_consumer_key="dpf43f3p2l4k3l03",\
oauth_token="nnch734d00sl2jdk",\
oauth_signature_method="HMAC-SHA1",\
oauth_timestamp="137131202",\
oauth_nonce="chapoH",\
oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"''',
            }
        )
        auth_credentials = Credentials('nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00')
        client_credentials = Credentials('dpf43f3p2l4k3l03', 'kd94hf93k423kf44')

        class MockClient(_OAuthClient):
            @classmethod
            def generate_timestamp(cls):
                return "137131202"

            @classmethod
            def generate_nonce(cls):
                return "chapoH"

        got = MockClient._request(
            client_credentials,
            'GET',
            'http://photos.example.net/photos',
            params={
                "file": "vacation.jpg",
                "size": "original",
            },
            realm='Photos',
            auth_credentials=auth_credentials,
            oauth_version=None
        )
        self.assertEqual(got.method, expected.method)
        self.assertEqual(got.url, expected.url)
        self.assertEqual(got.body, expected.body)
        expected_headers, expected_realm = parse_authorization_header(
            expected.headers["Authorization"],
        )
        got_headers, got_realm = parse_authorization_header(
            got.headers["Authorization"],
        )
        self.assertDictEqual(got_headers, expected_headers)
        self.assertEqual(got_realm, expected_realm)
