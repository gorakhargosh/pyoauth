#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nose import SkipTest
from nose.tools import assert_equal, assert_raises
from pyoauth.http import RequestProxy

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
                             token_request_uri="https://photos.example.net/token",
                             use_authorization_header=True)
        self.temporary_credentials = Credentials(identifier="hh5s93j4hdidpola", shared_secret="hdhd0244k9j7ao03")
        self.token_credentials = Credentials(identifier="nnch734d00sl2jdk", shared_secret="pfkkdhi9sl3r4s00")

    def test___init__(self):
        c = self.client
        assert_equal(c._temporary_credentials_request_uri, "https://photos.example.net/initiate")
        assert_equal(c._resource_owner_authorization_uri, "https://photos.example.net/authorize")
        assert_equal(c._token_request_uri, "https://photos.example.net/token")
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
        assert_raises(ValueError, self.client.parse_temporary_credentials_response, 200, "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=", headers)
        assert_raises(ValueError, self.client.parse_temporary_credentials_response, 200, "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=false", headers)

        params, credentials = self.client.parse_temporary_credentials_response(200, "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true", headers=headers)
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
        params, credentials = self.client.parse_token_credentials_response(200, "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00", headers=headers)
        assert_dict_equal(params, {
            "oauth_token": ["nnch734d00sl2jdk"],
            "oauth_token_secret": ["pfkkdhi9sl3r4s00"],
        })
        assert_equal(credentials, self.token_credentials)

    def test__parse_credentials_response(self):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        params, credentials = self.client._parse_credentials_response(200, "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true", headers=headers)
        assert_dict_equal(params, {
            "oauth_token": ["hh5s93j4hdidpola"],
            "oauth_token_secret": ["hdhd0244k9j7ao03"],
            "oauth_callback_confirmed": ["true"],
        })
        assert_equal(credentials, self.temporary_credentials)

        params, credentials = self.client._parse_credentials_response(200, "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00", headers=headers)
        assert_dict_equal(params, {
            "oauth_token": ["nnch734d00sl2jdk"],
            "oauth_token_secret": ["pfkkdhi9sl3r4s00"],
        })
        assert_equal(credentials, self.token_credentials)


    def test_parse_credentials_response_validation(self):
        status_code = 200
        body = "oauth_token=nnch734d00sl2jdk&oauth_token_secret=pfkkdhi9sl3r4s00"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }

        assert_raises(ValueError, self.client._parse_credentials_response, None, body, headers)
        assert_raises(ValueError, self.client._parse_credentials_response, status_code, None, headers)
        assert_raises(ValueError, self.client._parse_credentials_response, status_code, body, None)

        assert_raises(ValueError, self.client._parse_credentials_response, 300, body, headers)
        assert_raises(ValueError, self.client._parse_credentials_response, 199, body, headers)

        assert_raises(ValueError, self.client._parse_credentials_response, 200, "", headers)
        assert_raises(ValueError, self.client._parse_credentials_response, 200, body, {"Content-Type": "invalid"})


class Test_Client_build_request(object):
    def setUp(self):
        self.client_credentials = Credentials(identifier="dpf43f3p2l4k3l03", shared_secret="kd94hf93k423kf44")
        self.client = Client(self.client_credentials,
                             temporary_credentials_request_uri="https://photos.example.net/initiate",
                             resource_owner_authorization_uri="https://photos.example.net/authorize",
                             token_request_uri="https://photos.example.net/token",
                             use_authorization_header=True)
        self.temporary_credentials = Credentials(identifier="hh5s93j4hdidpola", shared_secret="hdhd0244k9j7ao03")
        self.token_credentials = Credentials(identifier="nnch734d00sl2jdk", shared_secret="pfkkdhi9sl3r4s00")

    def test_raises_ValueError_when_signature_method_invalid(self):
        assert_raises(ValueError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      oauth_signature_method="BLAH")

    def test_raises_ValueError_when_multiple_oauth_param_values(self):
        assert_raises(ValueError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      oauth_something=[1, 2, 3])

    def test_raises_ValueError_when_overriding_reserved_oauth_params(self):
        assert_raises(ValueError,
                      self.client._build_request,
                      "POST",
                      self.client._temporary_credentials_request_uri,
                      oauth_signature="dummy-signature")

    def test_valid_request_generated(self):
        valid_request = RequestProxy("GET",
                                     "https://photos.example.net/photos?file=vacation.jpg&size=original",
                                     payload="",
                                     headers={
                                         "Authorization": '''OAuth realm="Photos",
               oauth_consumer_key="dpf43f3p2l4k3l03",
               oauth_token="nnch734d00sl2jdk",
               oauth_signature_method="HMAC-SHA1",
               oauth_timestamp="137131202",
               oauth_nonce="chapoH",
               oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"'''
                                     })
