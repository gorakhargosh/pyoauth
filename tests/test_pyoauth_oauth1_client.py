#!/usr/bin/env python
# -*- coding: utf-8 -*-


import unittest2
from pyoauth.error import InvalidOAuthParametersError, \
    InvalidAuthorizationHeaderError, \
    InvalidSignatureMethodError, \
    InvalidHttpResponseError, HttpError, InvalidContentTypeError, IllegalArgumentError
from pyoauth.http import RequestAdapter, ResponseAdapter
from pyoauth.protocol import parse_authorization_header
from pyoauth.oauth1 import Credentials
from pyoauth.oauth1.client import Client


class TestClient_OAuth_1_0_Example(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(identifier="dpf43f3p2l4k3l03", shared_secret="kd94hf93k423kf44")
        self.client = Client(self.client_credentials,
                             temporary_credentials_request_uri="https://photos.example.net/initiate",
                             resource_owner_authorization_uri="https://photos.example.net/authorize",
                             token_credentials_request_uri="https://photos.example.net/token",
                             use_authorization_header=True)
        self.temporary_credentials = Credentials(identifier="hh5s93j4hdidpola", shared_secret="hdhd0244k9j7ao03")
        self.token_credentials = Credentials(identifier="nnch734d00sl2jdk", shared_secret="pfkkdhi9sl3r4s00")

    def test___init__(self):
        c = self.client
        self.assertEqual(c._temporary_credentials_request_uri, "https://photos.example.net/initiate")
        self.assertEqual(c._resource_owner_authorization_uri, "https://photos.example.net/authorize")
        self.assertEqual(c._token_credentials_request_uri, "https://photos.example.net/token")
        self.assertEqual(c._use_authorization_header, True)
        self.assertEqual(c._client_credentials.identifier, "dpf43f3p2l4k3l03")
        self.assertEqual(c._client_credentials.shared_secret, "kd94hf93k423kf44")

    def test_oauth_version(self):
        # OAuth version MUST be set to "1.0". Anything else is the responsibility of the API user.
        self.assertEqual(self.client.oauth_version, "1.0")

    def test_get_authorization_url(self):
        url = self.client.get_authorization_url(self.temporary_credentials, a="something here", b=["another thing", 5], oauth_ignored="ignored")
        self.assertEqual(url, "https://photos.example.net/authorize?a=something%20here&b=5&b=another%20thing&oauth_token=" + self.temporary_credentials.identifier)

    def test_parse_temporary_credentials_response(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.assertRaises(ValueError, self.client.parse_temporary_credentials_response, ResponseAdapter(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=", headers))
        self.assertRaises(ValueError, self.client.parse_temporary_credentials_response, ResponseAdapter(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=false", headers))

        credentials, params = self.client.parse_temporary_credentials_response(ResponseAdapter(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true", headers=headers))
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
        credentials, params = self.client.parse_token_credentials_response(ResponseAdapter(200, "OK", "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00", headers=headers))
        self.assertDictEqual(params, {
            "oauth_token": ["nnch734d00sl2jdk"],
            "oauth_token_secret": ["pfkkdhi9sl3r4s00"],
        })
        self.assertEqual(credentials, self.token_credentials)

    def test__parse_credentials_response(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        credentials, params = self.client._parse_credentials_response(ResponseAdapter(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true", headers=headers))
        self.assertDictEqual(params, {
            "oauth_token": ["hh5s93j4hdidpola"],
            "oauth_token_secret": ["hdhd0244k9j7ao03"],
            "oauth_callback_confirmed": ["true"],
        })
        self.assertEqual(credentials, self.temporary_credentials)

        credentials, params = self.client._parse_credentials_response(ResponseAdapter(200, "OK", "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00", headers=headers))
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

        self.assertRaises(InvalidHttpResponseError, self.client._parse_credentials_response, ResponseAdapter(status_code, None, body, headers))
        self.assertRaises(InvalidHttpResponseError, self.client._parse_credentials_response, ResponseAdapter(None, status, body, headers))
        self.assertRaises(InvalidHttpResponseError, self.client._parse_credentials_response, ResponseAdapter(status_code, status, None, headers))
        self.assertRaises(InvalidHttpResponseError, self.client._parse_credentials_response, ResponseAdapter(status_code, status, body, None))

        self.assertRaises(HttpError, self.client._parse_credentials_response, ResponseAdapter(300, "Multiple choices", body, headers))
        self.assertRaises(HttpError, self.client._parse_credentials_response, ResponseAdapter(199, "continue", body, headers))

        self.assertRaises(InvalidHttpResponseError, self.client._parse_credentials_response, ResponseAdapter(200, "OK" , "", headers))
        self.assertRaises(InvalidContentTypeError, self.client._parse_credentials_response, ResponseAdapter(200, "OK", body, {"Content-Type": "invalid"}))


class Test_Client_build_temporary_credentials_request(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(identifier="dpf43f3p2l4k3l03", shared_secret="kd94hf93k423kf44")
        self.client = Client(self.client_credentials,
                             temporary_credentials_request_uri="https://photos.example.net/initiate",
                             resource_owner_authorization_uri="https://photos.example.net/authorize",
                             token_credentials_request_uri="https://photos.example.net/token",
                             use_authorization_header=True)
        self.temporary_credentials = Credentials(identifier="hh5s93j4hdidpola", shared_secret="hdhd0244k9j7ao03")
        self.token_credentials = Credentials(identifier="nnch734d00sl2jdk", shared_secret="pfkkdhi9sl3r4s00")

    def test_raises_ValueError_when_oauth_callback_is_invalid(self):
        self.assertRaises(ValueError, self.client.build_temporary_credentials_request, oauth_callback="foobar")

class Test_Client_build_token_credentials_request(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(identifier="dpf43f3p2l4k3l03", shared_secret="kd94hf93k423kf44")
        self.client = Client(self.client_credentials,
                             temporary_credentials_request_uri="https://photos.example.net/initiate",
                             resource_owner_authorization_uri="https://photos.example.net/authorize",
                             token_credentials_request_uri="https://photos.example.net/token",
                             use_authorization_header=True)
        self.temporary_credentials = Credentials(identifier="hh5s93j4hdidpola", shared_secret="hdhd0244k9j7ao03")
        self.token_credentials = Credentials(identifier="nnch734d00sl2jdk", shared_secret="pfkkdhi9sl3r4s00")

    def test_raises_IllegalArgumentError_when_oauth_callback_specified(self):
        self.assertRaises(IllegalArgumentError,
                      self.client.build_token_credentials_request,
                      temporary_credentials=self.temporary_credentials,
                      oauth_verifier="something",
                      oauth_callback="oob")

class Test_Client_build_resource_request(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(identifier="dpf43f3p2l4k3l03", shared_secret="kd94hf93k423kf44")
        self.client = Client(self.client_credentials,
                             temporary_credentials_request_uri="https://photos.example.net/initiate",
                             resource_owner_authorization_uri="https://photos.example.net/authorize",
                             token_credentials_request_uri="https://photos.example.net/token",
                             use_authorization_header=True)
        self.temporary_credentials = Credentials(identifier="hh5s93j4hdidpola", shared_secret="hdhd0244k9j7ao03")
        self.token_credentials = Credentials(identifier="nnch734d00sl2jdk", shared_secret="pfkkdhi9sl3r4s00")

    def test_raises_IllegalArgumentError_when_oauth_callback_specified(self):
        self.assertRaises(IllegalArgumentError,
                      self.client.build_resource_request,
                      token_credentials=self.token_credentials,
                      method="POST",
                      url="http://photos.example.net/request",
                      oauth_callback="oob")

class Test_Client_build_request(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(identifier="dpf43f3p2l4k3l03", shared_secret="kd94hf93k423kf44")
        self.client = Client(self.client_credentials,
                             temporary_credentials_request_uri="https://photos.example.net/initiate",
                             resource_owner_authorization_uri="https://photos.example.net/authorize",
                             token_credentials_request_uri="https://photos.example.net/token",
                             use_authorization_header=True)
        self.temporary_credentials = Credentials(identifier="hh5s93j4hdidpola", shared_secret="hdhd0244k9j7ao03")
        self.token_credentials = Credentials(identifier="nnch734d00sl2jdk", shared_secret="pfkkdhi9sl3r4s00")

    def test_raises_InvalidSignatureMethodError_when_signature_method_invalid(self):
        self.assertRaises(InvalidSignatureMethodError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      oauth_signature_method="BLAH")

    def test_raises_ValueError_when_multiple_oauth_param_values(self):
        self.assertRaises(InvalidOAuthParametersError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      oauth_something=[1, 2, 3])

    def test_raises_IllegalArgumentError_when_overriding_reserved_oauth_params(self):
        self.assertRaises(IllegalArgumentError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      oauth_signature="dummy-signature")

    def tests_raises_InvalidAuthorizationHeaderError_when_Authorization_header_is_already_present(self):
        self.assertRaises(InvalidAuthorizationHeaderError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      headers={"Authorization": "blah blah."})

    def test_valid_request_generated(self):
        valid_request = RequestAdapter("GET",
                                     "http://photos.example.net/photos?file=vacation.jpg&size=original",
                                     body="",
                                     headers={
                                         "Authorization": '''\
OAuth realm="Photos",\
    oauth_consumer_key="dpf43f3p2l4k3l03",\
    oauth_nonce="chapoH",\
    oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D",\
    oauth_signature_method="HMAC-SHA1",\
    oauth_timestamp="137131202",\
    oauth_token="nnch734d00sl2jdk"'''})

        method = "GET"
        url = "http://photos.example.net/photos"
        params = dict(file="vacation.jpg", size="original")
        request = self.client._build_request(method,
                                             url,
                                             params,
                                             auth_credentials=self.token_credentials,
                                             realm="Photos",
                                             oauth_signature_method="HMAC-SHA1",
                                             oauth_timestamp="137131202",
                                             oauth_consumer_key="dpf43f3p2l4k3l03",
                                             oauth_token="nnch734d00sl2jdk",
                                             oauth_nonce="chapoH",
                                             _test_force_override_reserved_oauth_params=True,
                                             _test_force_exclude_oauth_version=True)
        self.assertEqual(request.method, valid_request.method)
        self.assertEqual(request.payload, valid_request.payload)
        self.assertEqual(request.url, valid_request.url)

        expected_authorization_header, expected_realm = parse_authorization_header(valid_request.headers["Authorization"])
        got_authorization_header, got_realm = parse_authorization_header(request.headers["Authorization"])
        self.assertEqual(got_realm, expected_realm)
        self.assertDictEqual(got_authorization_header, expected_authorization_header)

    def test_example_post_request(self):
        valid_request = RequestAdapter("POST",
                                     "https://photos.example.net/initiate",
                                     body="",
                                     headers={
                                         "Authorization": '''\
OAuth realm="Photos",\
    oauth_callback="http://printer.example.com/ready",\
    oauth_consumer_key="dpf43f3p2l4k3l03",\
    oauth_nonce="wIjqoS",\
    oauth_signature="74KNZJeDHnMBp0EMJ9ZHt/XKycU=",\
    oauth_signature_method="HMAC-SHA1",\
    oauth_timestamp="137131200"'''})

        method = "POST"
        url = "https://photos.example.net/initiate"
        params = None
        request = self.client._build_request(method,
                                             url,
                                             params,
                                             auth_credentials=None,
                                             realm="Photos",
                                             oauth_signature_method="HMAC-SHA1",
                                             oauth_timestamp="137131200",
                                             oauth_consumer_key="dpf43f3p2l4k3l03",
                                             oauth_nonce="wIjqoS",
                                             oauth_callback="http://printer.example.com/ready",
                                             _test_force_override_reserved_oauth_params=True,
                                             _test_force_exclude_oauth_version=True)
        self.assertEqual(request.method, valid_request.method)
        self.assertEqual(request.payload, valid_request.payload)
        self.assertEqual(request.url, valid_request.url)

        expected_authorization_header, expected_realm = parse_authorization_header(valid_request.headers["Authorization"])
        got_authorization_header, got_realm = parse_authorization_header(request.headers["Authorization"])
        self.assertEqual(got_realm, expected_realm)
        self.assertDictEqual(got_authorization_header, expected_authorization_header)


if __name__ == "__main__":
    unittest2.main()
