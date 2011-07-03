#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nose import SkipTest
from nose.tools import assert_equal, assert_raises
from pyoauth.error import InvalidOAuthParametersError, \
    InvalidAuthorizationHeaderError, \
    InvalidSignatureMethodError, \
    OverridingReservedOAuthParameterError, \
    InvalidHttpResponseError, HttpError, InvalidContentTypeError, IllegalArgumentError
from pyoauth.http import RequestProxy
from pyoauth.utils import parse_authorization_header_value

try:
    from nose.tools import assert_dict_equal
except ImportError:
    assert_dict_equal = assert_equal

from pyoauth.oauth1 import Credentials
from pyoauth.oauth1.client import Client

class TestClient_OAuth_1_0_Example:
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
        assert_equal(c._temporary_credentials_request_uri, "https://photos.example.net/initiate")
        assert_equal(c._resource_owner_authorization_uri, "https://photos.example.net/authorize")
        assert_equal(c._token_credentials_request_uri, "https://photos.example.net/token")
        assert_equal(c._use_authorization_header, True)
        assert_equal(c._client_credentials.identifier, "dpf43f3p2l4k3l03")
        assert_equal(c._client_credentials.shared_secret, "kd94hf93k423kf44")

    def test_oauth_version(self):
        # OAuth version MUST be set to "1.0". Anything else is the responsibility of the API user.
        assert_equal(self.client.oauth_version, "1.0")

    def test_get_authorization_url(self):
        url = self.client.get_authorization_url(self.temporary_credentials, a="something here", b=["another thing", 5], oauth_ignored="ignored")
        assert_equal(url, "https://photos.example.net/authorize?a=something%20here&b=5&b=another%20thing&oauth_token=" + self.temporary_credentials.identifier)

    def test_parse_temporary_credentials_response(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        assert_raises(ValueError, self.client.parse_temporary_credentials_response, 200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=", headers)
        assert_raises(ValueError, self.client.parse_temporary_credentials_response, 200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=false", headers)

        params, credentials = self.client.parse_temporary_credentials_response(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true", headers=headers)
        assert_dict_equal(params, {
            "oauth_token": ["hh5s93j4hdidpola"],
            "oauth_token_secret": ["hdhd0244k9j7ao03"],
            "oauth_callback_confirmed": ["true"],
        })
        assert_equal(credentials, self.temporary_credentials)

    def test_parse_token_credentials_response(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        params, credentials = self.client.parse_token_credentials_response(200, "OK", "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00", headers=headers)
        assert_dict_equal(params, {
            "oauth_token": ["nnch734d00sl2jdk"],
            "oauth_token_secret": ["pfkkdhi9sl3r4s00"],
        })
        assert_equal(credentials, self.token_credentials)

    def test__parse_credentials_response(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        params, credentials = self.client._parse_credentials_response(200, "OK", "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true", headers=headers)
        assert_dict_equal(params, {
            "oauth_token": ["hh5s93j4hdidpola"],
            "oauth_token_secret": ["hdhd0244k9j7ao03"],
            "oauth_callback_confirmed": ["true"],
        })
        assert_equal(credentials, self.temporary_credentials)

        params, credentials = self.client._parse_credentials_response(200, "OK", "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00", headers=headers)
        assert_dict_equal(params, {
            "oauth_token": ["nnch734d00sl2jdk"],
            "oauth_token_secret": ["pfkkdhi9sl3r4s00"],
        })
        assert_equal(credentials, self.token_credentials)


    def test_parse_credentials_response_validation(self):
        status_code = 200
        status = "OK"
        body = "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        assert_raises(InvalidHttpResponseError, self.client._parse_credentials_response, status_code, None, body, headers)
        assert_raises(InvalidHttpResponseError, self.client._parse_credentials_response, None, status, body, headers)
        assert_raises(InvalidHttpResponseError, self.client._parse_credentials_response, status_code, status, None, headers)
        assert_raises(InvalidHttpResponseError, self.client._parse_credentials_response, status_code, status, body, None)

        assert_raises(HttpError, self.client._parse_credentials_response, 300, "Multiple choices", body, headers)
        assert_raises(HttpError, self.client._parse_credentials_response, 199, "continue", body, headers)

        assert_raises(InvalidHttpResponseError, self.client._parse_credentials_response, 200, "OK" , "", headers)
        assert_raises(InvalidContentTypeError, self.client._parse_credentials_response, 200, "OK", body, {"Content-Type": "invalid"})


class Test_Client_build_temporary_credentials_request(object):
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
        assert_raises(ValueError, self.client.build_temporary_credentials_request, oauth_callback="foobar")

class Test_Client_build_token_credentials_request(object):
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
        assert_raises(IllegalArgumentError,
                      self.client.build_token_credentials_request,
                      temporary_credentials=self.temporary_credentials,
                      oauth_verifier="something",
                      oauth_callback="oob")

class Test_Client_build_resource_request(object):
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
        assert_raises(IllegalArgumentError,
                      self.client.build_resource_request,
                      token_credentials=self.token_credentials,
                      method="POST",
                      url="http://photos.example.net/request",
                      oauth_callback="oob")

class Test_Client_build_request(object):
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
        assert_raises(InvalidSignatureMethodError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      oauth_signature_method="BLAH")

    def test_raises_ValueError_when_multiple_oauth_param_values(self):
        assert_raises(InvalidOAuthParametersError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      oauth_something=[1, 2, 3])

    def test_raises_IllegalArgumentError_when_overriding_reserved_oauth_params(self):
        assert_raises(IllegalArgumentError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      oauth_signature="dummy-signature")

    def tests_raises_InvalidAuthorizationHeaderError_when_Authorization_header_is_already_present(self):
        assert_raises(InvalidAuthorizationHeaderError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      headers={"Authorization", "blah blah."})

    def test_valid_request_generated(self):
        valid_request = RequestProxy("GET",
                                     "http://photos.example.net/photos?file=vacation.jpg&size=original",
                                     payload="",
                                     headers={
                                         "Authorization": '''\
OAuth realm="Photos",
    oauth_consumer_key="dpf43f3p2l4k3l03",
    oauth_nonce="chapoH",
    oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D",
    oauth_signature_method="HMAC-SHA1",
    oauth_timestamp="137131202",
    oauth_token="nnch734d00sl2jdk"
    '''})

        method = "GET"
        url = "http://photos.example.net/photos"
        params = dict(file="vacation.jpg", size="original")
        request = self.client._build_request(method,
                                             url,
                                             params,
                                             token_or_temporary_credentials=self.token_credentials,
                                             realm="Photos",
                                             oauth_signature_method="HMAC-SHA1",
                                             oauth_timestamp="137131202",
                                             oauth_consumer_key="dpf43f3p2l4k3l03",
                                             oauth_token="nnch734d00sl2jdk",
                                             oauth_nonce="chapoH",
                                             _test_force_override_reserved_oauth_params=True,
                                             _test_force_exclude_oauth_version=True)
        assert_equal(request.method, valid_request.method)
        assert_equal(request.payload, valid_request.payload)
        assert_equal(request.url, valid_request.url)

        expected_authorization_header, expected_realm = parse_authorization_header_value(valid_request.headers["Authorization"])
        got_authorization_header, got_realm = parse_authorization_header_value(request.headers["Authorization"])
        assert_equal(got_realm, expected_realm)
        assert_dict_equal(got_authorization_header, expected_authorization_header)

    def test_example_post_request(self):
        valid_request = RequestProxy("POST",
                                     "https://photos.example.net/initiate",
                                     payload="",
                                     headers={
                                         "Authorization": '''\
OAuth realm="Photos",
    oauth_callback="http://printer.example.com/ready",
    oauth_consumer_key="dpf43f3p2l4k3l03",
    oauth_nonce="wIjqoS",
    oauth_signature="74KNZJeDHnMBp0EMJ9ZHt/XKycU=",
    oauth_signature_method="HMAC-SHA1",
    oauth_timestamp="137131200"
    '''})

        method = "POST"
        url = "https://photos.example.net/initiate"
        params = None
        request = self.client._build_request(method,
                                             url,
                                             params,
                                             token_or_temporary_credentials=None,
                                             realm="Photos",
                                             oauth_signature_method="HMAC-SHA1",
                                             oauth_timestamp="137131200",
                                             oauth_consumer_key="dpf43f3p2l4k3l03",
                                             oauth_nonce="wIjqoS",
                                             oauth_callback="http://printer.example.com/ready",
                                             _test_force_override_reserved_oauth_params=True,
                                             _test_force_exclude_oauth_version=True)
        assert_equal(request.method, valid_request.method)
        assert_equal(request.payload, valid_request.payload)
        assert_equal(request.url, valid_request.url)

        expected_authorization_header, expected_realm = parse_authorization_header_value(valid_request.headers["Authorization"])
        got_authorization_header, got_realm = parse_authorization_header_value(request.headers["Authorization"])
        assert_equal(got_realm, expected_realm)
        assert_dict_equal(got_authorization_header, expected_authorization_header)
