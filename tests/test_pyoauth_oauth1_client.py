#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nose import SkipTest
from nose.tools import assert_equal
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


    def test_build_resource_request(self):
        # client = Client(client_credentials, temporary_credentials_request_uri, resource_owner_authorization_uri, token_request_uri, use_authorization_header)
        # assert_equal(expected, client.build_resource_request(token_credentials, method, url, query_params, headers, realm, oauth_signature_method, **extra_oauth_params))
        raise SkipTest # TODO: implement your test here

    def test_build_temporary_credentials_request(self):
        # client = Client(client_credentials, temporary_credentials_request_uri, resource_owner_authorization_uri, token_request_uri, use_authorization_header)
        # assert_equal(expected, client.build_temporary_credentials_request(method, query_params, headers, realm, oauth_signature_method, oauth_callback, **extra_oauth_params))
        raise SkipTest # TODO: implement your test here

    def test_build_token_credentials_request(self):
        # client = Client(client_credentials, temporary_credentials_request_uri, resource_owner_authorization_uri, token_request_uri, use_authorization_header)
        # assert_equal(expected, client.build_token_credentials_request(temporary_credentials, oauth_verifier, method, query_params, headers, realm, oauth_signature_method, **extra_oauth_params))
        raise SkipTest # TODO: implement your test here


    def test_parse_credentials_response(self):
        # client = Client(client_credentials, temporary_credentials_request_uri, resource_owner_authorization_uri, token_request_uri, use_authorization_header)
        # assert_equal(expected, client.parse_credentials_response(status_code, body, headers))
        raise SkipTest # TODO: implement your test here

    def test__build_request(self):
        raise SkipTest
