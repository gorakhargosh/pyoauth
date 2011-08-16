#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest2

from mom.builtins import b
from mom.builtins import is_bytes, is_bytes_or_unicode
from mom.codec.text import utf8_encode
from pyoauth.constants import \
    OAUTH_VERSION_1, OAUTH_VALUE_CALLBACK_OOB, \
    HTTP_GET, HEADER_CONTENT_TYPE, HTTP_POST, \
    HEADER_AUTHORIZATION_CAPS, HEADER_CONTENT_LENGTH, \
    OAUTH_PARAM_TOKEN, OAUTH_PARAM_CONSUMER_SECRET, \
    OAUTH_PARAM_TOKEN_SECRET, OAUTH_PARAM_SIGNATURE, \
    OAUTH_REALM, OAUTH_PARAM_CALLBACK_CONFIRMED, \
    OAUTH_VALUE_CALLBACK_CONFIRMED, HTTP_REASON_OK, \
    HTTP_REASON_MULTIPLE_CHOICES, HTTP_REASON_CONTINUE, \
    OAUTH_PARAM_REALM

from pyoauth.error import InvalidSignatureMethodError, \
    IllegalArgumentError, InvalidHttpResponseError, HttpError, \
    InvalidContentTypeError, InvalidHttpRequestError, \
    InvalidAuthorizationHeaderError, InvalidOAuthParametersError, \
    SignatureMethodNotSupportedError
from pyoauth.http import ResponseAdapter, RequestAdapter, \
    CONTENT_TYPE_FORM_URLENCODED
from pyoauth.oauth1 import Credentials, SIGNATURE_METHOD_HMAC_SHA1
from pyoauth.oauth1.client import _OAuthClient, Client
from pyoauth.oauth1.protocol import parse_authorization_header
from pyoauth.url import percent_decode
from pyoauth.tests.constants import TEST_CONSUMER_KEY, TEST_NONCE, \
    TEST_TIMESTAMP, TEST_EXTRA_PARAM_VALUE, TEST_IGNORE_THIS_TEXT, \
    TEST_TOKEN, BAD_SIGNATURE_METHOD, BAD_SIGNATURE, \
    RFC_OAUTH_CALLBACK_URI, RFC_NONCE_1, RFC_TIMESTAMP_1, \
    RFC_CLIENT_IDENTIFIER, RFC_TEMP_REQUEST_SIGNATURE, \
    RFC_CLIENT_SECRET, RFC_TEMP_URI, RFC_REALM, \
    RFC_RESOURCE_REQUEST_SIGNATURE_ENCODED, RFC_TOKEN_SECRET, \
    RFC_RESOURCE_URI, RFC_NONCE_3, RFC_TIMESTAMP_3, \
    RFC_TOKEN_IDENTIFIER, RFC_RESOURCE_FULL_URL, \
    CONTENT_TYPE_TEXT_CSS, RFC_TEMPORARY_SECRET, \
    RFC_TEMPORARY_IDENTIFIER, RFC_TEMP_CREDENTIALS_RESPONSE, \
    BAD_CREDENTIALS_CONTENT_TYPE, RFC_TOKEN_CREDENTIALS_RESPONSE, \
    BAD_RFC_TEMP_CREDENTIALS_RESPONSE, RFC_AUTHENTICATION_URI, \
    RFC_AUTHORIZATION_URI, RFC_TOKEN_URI, FOO_URI, BAD_OAUTH_CALLBACK


class Test__OAuthClient_oauth_version(unittest2.TestCase):
    def test_default_is_1_0(self):
        self.assertEqual(_OAuthClient(None, None).oauth_version,
                         OAUTH_VERSION_1)

class Test__OAuthClient_generate_nonce(unittest2.TestCase):
    def test_uniqueness(self):
        self.assertNotEqual(_OAuthClient.generate_nonce(),
                            _OAuthClient.generate_nonce())

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
            oauth_consumer_key=TEST_CONSUMER_KEY,
            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
            oauth_version=OAUTH_VERSION_1,
            oauth_nonce=TEST_NONCE,
            oauth_timestamp=TEST_TIMESTAMP,
            oauth_token=None,
            oauth_extra=TEST_EXTRA_PARAM_VALUE,
        )
        args_with_token = dict(
            oauth_consumer_key=TEST_CONSUMER_KEY,
            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
            oauth_version=OAUTH_VERSION_1,
            oauth_nonce=TEST_NONCE,
            oauth_timestamp=TEST_TIMESTAMP,
            oauth_token=TEST_TOKEN,
            oauth_extra=TEST_EXTRA_PARAM_VALUE,
        )

        args1 = dict(
            non_oauth_param=TEST_IGNORE_THIS_TEXT,
        )
        args1.update(args_no_token)
        del args_no_token[OAUTH_PARAM_TOKEN]
        self.assertDictEqual(_OAuthClient._generate_oauth_params(**args1),
                             args_no_token)

        args2 = dict(
            non_oauth_param=TEST_IGNORE_THIS_TEXT,
        )
        args2.update(args_with_token)
        self.assertDictEqual(_OAuthClient._generate_oauth_params(**args2),
                             args_with_token)

    def test_InvalidSignatureMethodError_when_invalid_signature_method(self):
        args_no_token = dict(
            oauth_consumer_key=TEST_CONSUMER_KEY,
            oauth_signature_method=BAD_SIGNATURE_METHOD,
            oauth_version=OAUTH_VERSION_1,
            oauth_nonce=TEST_NONCE,
            oauth_timestamp=TEST_TIMESTAMP,
            oauth_token=None,
            oauth_extra=TEST_EXTRA_PARAM_VALUE,
        )
        self.assertRaises(InvalidSignatureMethodError,
                          _OAuthClient._generate_oauth_params, **args_no_token)

    def test_IllegalArgumentError_when_signature_specified(self):
        args_no_token = dict(
            oauth_consumer_key=TEST_CONSUMER_KEY,
            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
            oauth_version=OAUTH_VERSION_1,
            oauth_nonce=TEST_NONCE,
            oauth_timestamp=TEST_TIMESTAMP,
            oauth_token=None,
            oauth_extra=TEST_EXTRA_PARAM_VALUE,
            oauth_signature=BAD_SIGNATURE
        )
        self.assertRaises(IllegalArgumentError,
                          _OAuthClient._generate_oauth_params, **args_no_token)

class Test__OAuthClient__generate_signature(unittest2.TestCase):
    def test_generates_signature(self):
        params = {
            "method": HTTP_POST,
            OAUTH_PARAM_REALM: RFC_REALM,
            "url": RFC_TEMP_URI,
            OAUTH_PARAM_CONSUMER_SECRET: RFC_CLIENT_SECRET,
            OAUTH_PARAM_TOKEN_SECRET: None,
            OAUTH_PARAM_SIGNATURE: RFC_TEMP_REQUEST_SIGNATURE,
            "oauth_params": dict(
                oauth_consumer_key=RFC_CLIENT_IDENTIFIER,
                oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                oauth_timestamp=RFC_TIMESTAMP_1,
                oauth_nonce=RFC_NONCE_1,
                oauth_callback=RFC_OAUTH_CALLBACK_URI,
            )
        }
        self.assertEqual(_OAuthClient._generate_signature(
            params["method"],
            params["url"],
            None,
            None,
            None,
            params[OAUTH_PARAM_CONSUMER_SECRET],
            params[OAUTH_PARAM_TOKEN_SECRET],
            params["oauth_params"],
        ), params[OAUTH_PARAM_SIGNATURE])


    def test_generates_signature_including_urlencoded_body(self):
        oauth_params = dict(
            oauth_consumer_key=RFC_CLIENT_IDENTIFIER,
            oauth_token=RFC_TOKEN_IDENTIFIER,
            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
            oauth_timestamp=RFC_TIMESTAMP_3,
            oauth_nonce=RFC_NONCE_3,
        )
        self.assertEqual(_OAuthClient._generate_signature(
            HTTP_GET,
            # I Know ^ is a GET request and we're specifying a body in this
            # test. _generate_signature does not validate HTTP methods,
            # but only generates signatures. This example must produce
            # the same signature as in the RFC example, hence the test.
            RFC_RESOURCE_URI,
            params=None,
            body=b("file=vacation.jpg&size=original&oauth_ignored=IGNORED"),
            headers={
                HEADER_CONTENT_TYPE: CONTENT_TYPE_FORM_URLENCODED,
            },
            oauth_consumer_secret=RFC_CLIENT_SECRET,
            oauth_token_secret=RFC_TOKEN_SECRET,
            oauth_params=oauth_params,
        ), utf8_encode(percent_decode(RFC_RESOURCE_REQUEST_SIGNATURE_ENCODED)))


    def test_error_when_headers_or_content_type_missing_body_specified(self):
        oauth_params = dict(
            oauth_consumer_key=RFC_CLIENT_IDENTIFIER,
            oauth_token=RFC_TOKEN_IDENTIFIER,
            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
            oauth_timestamp=RFC_TIMESTAMP_3,
            oauth_nonce=RFC_NONCE_3,
        )
        self.assertRaises(TypeError,
            _OAuthClient._generate_signature,
            HTTP_GET,
            # I Know ^ is a GET request and we're specifying a body in this
            # test. _generate_signature does not validate HTTP methods,
            # but only generates signatures. This example must produce
            # the same signature as in the RFC example, hence the test.
            RFC_RESOURCE_URI,
            params=None,
            body=b("file=vacation.jpg&size=original"),
            headers=None,
            oauth_consumer_secret=RFC_CLIENT_SECRET,
            oauth_token_secret=RFC_TOKEN_SECRET,
            oauth_params=oauth_params,
        )
#        self.assertRaises(KeyError,
#            _OAuthClient._generate_signature,
#            HTTP_GET,
#            # I Know ^ is a GET request and we're specifying a body in this
#            # test. _generate_signature does not validate HTTP methods,
#            # but only generates signatures. This example must produce
#            # the same signature as in the RFC example, hence the test.
#            RFC_RESOURCE_URI,
#            params=None,
#            body="file=vacation.jpg&size=original",
#            headers={},
#            oauth_consumer_secret=RFC_CLIENT_SECRET,
#            oauth_token_secret=RFC_TOKEN_SECRET,
#            oauth_params=oauth_params,
#        )

    def test_ignores_body_params_if_content_type_is_not_urlencoded(self):
        oauth_params = dict(
            oauth_consumer_key=RFC_CLIENT_IDENTIFIER,
            oauth_token=RFC_TOKEN_IDENTIFIER,
            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
            oauth_timestamp=RFC_TIMESTAMP_3,
            oauth_nonce=RFC_NONCE_3,
        )
        self.assertEqual(_OAuthClient._generate_signature(
            HTTP_GET,
            # I Know ^ is a GET request and we're specifying a body in this
            # test. _generate_signature does not validate HTTP methods,
            # but only generates signatures. This example must produce
            # the same signature as in the RFC example, hence the test.
            RFC_RESOURCE_FULL_URL,
            params=None,
            body=b("""
body {
    font-family: "Lucida Grande", serif;
}
a:link {
    text-decoration: none;
}
"""),
            headers={
                HEADER_CONTENT_TYPE: CONTENT_TYPE_TEXT_CSS,
            },
            oauth_consumer_secret=RFC_CLIENT_SECRET,
            oauth_token_secret=RFC_TOKEN_SECRET,
            oauth_params=oauth_params,
        ), utf8_encode(percent_decode(RFC_RESOURCE_REQUEST_SIGNATURE_ENCODED)))


    def test_SignatureMethodNotSupportedError_when_invalid_sig_method(self):
        params = {
            "method": HTTP_POST,
            "url": RFC_TEMP_URI,
            OAUTH_PARAM_CONSUMER_SECRET: RFC_CLIENT_SECRET,
            OAUTH_PARAM_TOKEN_SECRET: None,
            "oauth_params": dict(
                oauth_consumer_key=RFC_CLIENT_IDENTIFIER,
                oauth_signature_method=BAD_SIGNATURE_METHOD,
                oauth_timestamp=RFC_TIMESTAMP_1,
                oauth_nonce=RFC_NONCE_1,
                oauth_callback=RFC_OAUTH_CALLBACK_URI,
            )
        }
        self.assertRaises(SignatureMethodNotSupportedError,
              _OAuthClient._generate_signature,
              params["method"],
              params["url"],
              None, None, None,
              params[OAUTH_PARAM_CONSUMER_SECRET],
              params[OAUTH_PARAM_TOKEN_SECRET],
              params["oauth_params"],
        )


    def test_raises_KeyError_when_missing_signature_method(self):
        params = {
            "method": HTTP_POST,
            "url": RFC_TEMP_URI,
            OAUTH_PARAM_CONSUMER_SECRET: RFC_CLIENT_SECRET,
            OAUTH_PARAM_TOKEN_SECRET: None,
            "oauth_params": dict(
                oauth_consumer_key=RFC_CLIENT_IDENTIFIER,
                oauth_timestamp=RFC_TIMESTAMP_1,
                # oauth_signature_method=BAD_SIGNATURE_METHOD,
                oauth_nonce=RFC_NONCE_1,
                oauth_callback=RFC_OAUTH_CALLBACK_URI,
            )
        }
        self.assertRaises(KeyError, _OAuthClient._generate_signature,
              params["method"],
              params["url"],
              None, None, None,
              params[OAUTH_PARAM_CONSUMER_SECRET],
              params[OAUTH_PARAM_TOKEN_SECRET],
              params["oauth_params"],
        )

class Test__OAuthClient_misc(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(
            identifier=RFC_CLIENT_IDENTIFIER, shared_secret=RFC_CLIENT_SECRET)
        self.temporary_credentials = Credentials(
            identifier=RFC_TEMPORARY_IDENTIFIER,
            shared_secret=RFC_TEMPORARY_SECRET)
        self.token_credentials = Credentials(
            identifier=RFC_TOKEN_IDENTIFIER, shared_secret=RFC_TOKEN_SECRET)

    def test_parse_temporary_credentials_response(self):
        headers = {
            HEADER_CONTENT_TYPE: CONTENT_TYPE_FORM_URLENCODED,
        }
        self.assertRaises(
            ValueError,
            _OAuthClient.parse_temporary_credentials_response,
            ResponseAdapter(200,
                            HTTP_REASON_OK,
                            "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=",
                            headers)
        )
        self.assertRaises(
            ValueError,
            _OAuthClient.parse_temporary_credentials_response,
            ResponseAdapter(200, HTTP_REASON_OK,
                            "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=false",
                            headers)
        )

        credentials, params = _OAuthClient.parse_temporary_credentials_response(
            ResponseAdapter(200, HTTP_REASON_OK,
                            RFC_TEMP_CREDENTIALS_RESPONSE, headers=headers))
        self.assertDictEqual(params, {
            OAUTH_PARAM_TOKEN: [RFC_TEMPORARY_IDENTIFIER],
            OAUTH_PARAM_TOKEN_SECRET: [RFC_TEMPORARY_SECRET],
            OAUTH_PARAM_CALLBACK_CONFIRMED: [OAUTH_VALUE_CALLBACK_CONFIRMED],
        })
        self.assertEqual(credentials, self.temporary_credentials)

        # Non-strict parsing.
        credentials, params = \
            _OAuthClient.parse_temporary_credentials_response(
                ResponseAdapter(200, HTTP_REASON_OK,
                                BAD_RFC_TEMP_CREDENTIALS_RESPONSE, headers={
                        HEADER_CONTENT_TYPE: BAD_CREDENTIALS_CONTENT_TYPE,
                    }), strict=False)
        self.assertDictEqual(params, {
            OAUTH_PARAM_TOKEN: [RFC_TEMPORARY_IDENTIFIER],
            OAUTH_PARAM_TOKEN_SECRET: [RFC_TEMPORARY_SECRET],
        })
        self.assertEqual(credentials, self.temporary_credentials)


    def test_parse_token_credentials_response(self):
        headers = {
            HEADER_CONTENT_TYPE: CONTENT_TYPE_FORM_URLENCODED,
        }
        credentials, params = _OAuthClient.parse_token_credentials_response(
            ResponseAdapter(200, HTTP_REASON_OK,
                            RFC_TOKEN_CREDENTIALS_RESPONSE, headers=headers))
        self.assertDictEqual(params, {
            OAUTH_PARAM_TOKEN: [RFC_TOKEN_IDENTIFIER],
            OAUTH_PARAM_TOKEN_SECRET: [RFC_TOKEN_SECRET],
        })
        self.assertEqual(credentials, self.token_credentials)

        # Non-strict.
        credentials, params = \
            _OAuthClient.parse_token_credentials_response(
                ResponseAdapter(200, HTTP_REASON_OK,
                                RFC_TOKEN_CREDENTIALS_RESPONSE, headers={
                        HEADER_CONTENT_TYPE: BAD_CREDENTIALS_CONTENT_TYPE,
                    }), strict=False)
        self.assertDictEqual(params, {
            OAUTH_PARAM_TOKEN: [RFC_TOKEN_IDENTIFIER],
            OAUTH_PARAM_TOKEN_SECRET: [RFC_TOKEN_SECRET],
        })
        self.assertEqual(credentials, self.token_credentials)


    def test__parse_credentials_response(self):
        headers = {
            HEADER_CONTENT_TYPE: CONTENT_TYPE_FORM_URLENCODED,
        }
        credentials, params = _OAuthClient._parse_credentials_response(
            ResponseAdapter(200, HTTP_REASON_OK,
                            RFC_TEMP_CREDENTIALS_RESPONSE, headers=headers))
        self.assertDictEqual(params, {
            OAUTH_PARAM_TOKEN: [RFC_TEMPORARY_IDENTIFIER],
            OAUTH_PARAM_TOKEN_SECRET: [RFC_TEMPORARY_SECRET],
            OAUTH_PARAM_CALLBACK_CONFIRMED: [OAUTH_VALUE_CALLBACK_CONFIRMED],
        })
        self.assertEqual(credentials, self.temporary_credentials)

        credentials, params = _OAuthClient._parse_credentials_response(
            ResponseAdapter(200, HTTP_REASON_OK,
                            RFC_TOKEN_CREDENTIALS_RESPONSE, headers=headers))
        self.assertDictEqual(params, {
            OAUTH_PARAM_TOKEN: [RFC_TOKEN_IDENTIFIER],
            OAUTH_PARAM_TOKEN_SECRET: [RFC_TOKEN_SECRET],
        })
        self.assertEqual(credentials, self.token_credentials)

    def test_parse_credentials_response_validation(self):
        status_code = 200
        status = HTTP_REASON_OK
        body = RFC_TOKEN_CREDENTIALS_RESPONSE
        headers = {
            HEADER_CONTENT_TYPE: CONTENT_TYPE_FORM_URLENCODED,
        }
        self.assertRaises(InvalidHttpResponseError,
                          _OAuthClient._parse_credentials_response,
                          ResponseAdapter(status_code, None, body, headers))
        self.assertRaises(InvalidHttpResponseError,
                          _OAuthClient._parse_credentials_response,
                          ResponseAdapter(None, status, body, headers))
        self.assertRaises(InvalidHttpResponseError,
                          _OAuthClient._parse_credentials_response,
                          ResponseAdapter(status_code, status, None, headers))
        self.assertRaises(InvalidHttpResponseError,
                          _OAuthClient._parse_credentials_response,
                          ResponseAdapter(status_code, status, body, None))

        self.assertRaises(HttpError,
                          _OAuthClient._parse_credentials_response,
                          ResponseAdapter(300, HTTP_REASON_MULTIPLE_CHOICES,
                                          body, headers))
        self.assertRaises(HttpError,
                          _OAuthClient._parse_credentials_response,
                          ResponseAdapter(199, HTTP_REASON_CONTINUE,
                                          body, headers))

        self.assertRaises(InvalidHttpResponseError,
                          _OAuthClient._parse_credentials_response,
                          ResponseAdapter(200, HTTP_REASON_OK , b(""), headers))
        self.assertRaises(InvalidContentTypeError,
                          _OAuthClient._parse_credentials_response,
                          ResponseAdapter(200, HTTP_REASON_OK, body,
                                  {HEADER_CONTENT_TYPE: b("invalid")}))


class Test__OAuthClient_check_verification_code(unittest2.TestCase):
    def test_raises_InvalidHttpRequestError_when_identifier_invalid(self):
        temporary_credentials = Credentials(identifier=RFC_TEMPORARY_IDENTIFIER,
                                            shared_secret=RFC_TEMPORARY_SECRET)

        self.assertRaises(InvalidHttpRequestError,
                          _OAuthClient.check_verification_code,
                          temporary_credentials, b("non-matching-token"),
                          b("verification-code"))

class Test__OAuthClient_urls(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = \
            Credentials(identifier=RFC_CLIENT_IDENTIFIER,
                        shared_secret=RFC_CLIENT_SECRET)
        self.temporary_credentials = \
            Credentials(identifier=RFC_TEMPORARY_IDENTIFIER,
                        shared_secret=RFC_TEMPORARY_SECRET)
        self.token_credentials = Credentials(identifier=RFC_TOKEN_IDENTIFIER,
                                             shared_secret=RFC_TOKEN_SECRET)
        args = dict(
            temporary_credentials_uri=RFC_TEMP_URI,
            token_credentials_uri=RFC_TOKEN_URI,
            authorization_uri=RFC_AUTHORIZATION_URI,
            authentication_uri=RFC_AUTHENTICATION_URI,
            use_authorization_header=True
        )
        self.client = Client(None, self.client_credentials, **args)

    def test___init__(self):
        c = self.client
        self.assertEqual(c._temporary_credentials_uri,
                         RFC_TEMP_URI)
        self.assertEqual(c._token_credentials_uri,
                         RFC_TOKEN_URI)
        self.assertEqual(c._authorization_uri,
                         RFC_AUTHORIZATION_URI)
        self.assertEqual(c._authentication_uri,
                         RFC_AUTHENTICATION_URI)
        self.assertEqual(c._use_authorization_header, True)
        self.assertEqual(c._client_credentials.identifier,
                         RFC_CLIENT_IDENTIFIER)
        self.assertEqual(c._client_credentials.shared_secret,
                         RFC_CLIENT_SECRET)

    def test_get_authorization_url(self):
        url = self.client.get_authorization_url(self.temporary_credentials,
                                                a="something here",
                                                b=["another thing", 5],
                                                oauth_ignored="ignored")
        self.assertEqual(url,
                         RFC_AUTHORIZATION_URI +
                         b("?a=something%20here"
                         "&b=5"
                         "&b=another%20thing&oauth_token=") +
                         self.temporary_credentials.identifier)

    def test_get_authentication_url(self):
        url = self.client.get_authentication_url(self.temporary_credentials,
                                                a="something here",
                                                b=["another thing", 5],
                                                oauth_ignored=b("ignored"))
        self.assertEqual(url,
                         RFC_AUTHENTICATION_URI +
                         b("?a=something%20here"
                         "&b=5"
                         "&b=another%20thing&oauth_token=") +
                         self.temporary_credentials.identifier)

    def test_no_authentication_url(self):
        args = dict(
            temporary_credentials_uri=RFC_TEMP_URI,
            token_credentials_uri=RFC_TOKEN_URI,
            authorization_uri=RFC_AUTHORIZATION_URI,
            authentication_uri=None,
            use_authorization_header=True
        )
        client = Client(None, self.client_credentials, **args)
        self.assertRaises(NotImplementedError,
                          client.get_authentication_url,
                          self.temporary_credentials,
                          a=b("something here"),
                          b=[b("another thing"), 5],
                          oauth_ignored=b("ignored"))


class Test__OAuthClient__build_request(unittest2.TestCase):
    def test_auth_header(self):
        oauth_params = dict(
            oauth_blah=b("blah"),
        )
        headers = {
            "something": b("blah"),
        }
        params = dict(a=b("b"))
        expected = RequestAdapter(HTTP_GET,
                                 FOO_URI + b("?a=b"),
                                 None,
                                 {
                HEADER_AUTHORIZATION_CAPS:
                    b('OAuth realm="realm",oauth_blah="blah"'),
                "something": b("blah"),
            })
        got = _OAuthClient._build_request(HTTP_GET,
                                          FOO_URI,
                                          params, None, headers,
                                          oauth_params, OAUTH_REALM, True)
        self.assertEqual(expected.method, got.method)
        self.assertEqual(expected.url, got.url)
        self.assertEqual(expected.body, got.body)
        self.assertDictEqual(expected.headers, got.headers)

    def test_get_query_string(self):
        oauth_params = dict(
            oauth_blah=b("blah"),
        )
        headers = {
            "something": b("blah"),
        }
        params = dict(a=b("b"))
        expected = RequestAdapter(HTTP_GET,
                                 FOO_URI + b("?a=b&oauth_blah=blah"),
                                 None,
                                 {"something": b("blah")})
        got = _OAuthClient._build_request(HTTP_GET,
                                          FOO_URI,
                                          params, None, headers,
                                          oauth_params, OAUTH_REALM, False)
        self.assertEqual(expected.method, got.method)
        self.assertEqual(expected.url, got.url)
        self.assertEqual(expected.body, got.body)
        self.assertDictEqual(expected.headers, got.headers)


    def test_payload(self):
        oauth_params = dict(
            oauth_blah=b("blah"),
        )
        headers = {
            "something": b("blah"),
        }
        params = dict(a=b("b"))
        expected = RequestAdapter(HTTP_POST,
                                 FOO_URI,
                                 b("a=b&oauth_blah=blah"),
                                 {
            "something": b("blah"),
            HEADER_CONTENT_TYPE: CONTENT_TYPE_FORM_URLENCODED,
            HEADER_CONTENT_LENGTH: b("19"),
        })
        got = _OAuthClient._build_request(HTTP_POST,
                                          FOO_URI,
                                          params, b(""), headers,
                                          oauth_params, OAUTH_REALM, False)
        self.assertEqual(expected.method, got.method)
        self.assertEqual(expected.url, got.url)
        self.assertEqual(expected.body, got.body)
        self.assertDictEqual(expected.headers, got.headers)

    def test_raises_InvalidHttpRequestError_when_body_and_GET(self):
        oauth_params = dict(
            oauth_blah=b("blah"),
        )
        self.assertRaises(InvalidHttpRequestError,
                          _OAuthClient._build_request,
                          HTTP_GET,
                          FOO_URI,
                          None, b("a=b"), {}, oauth_params,
                          OAUTH_REALM, False)

    def test_raises_InvalidAuthorizationHeaderError_when_auth_present(self):
        oauth_params = dict(
            oauth_blah=b("blah"),
        )
        self.assertRaises(InvalidAuthorizationHeaderError,
                          _OAuthClient._build_request,
                          HTTP_POST,
                          FOO_URI,
                          None, b("a=b"),
                {
                    HEADER_AUTHORIZATION_CAPS: b("")
            }, oauth_params,
                          OAUTH_REALM, False)

class Test__OAuthClient__request(unittest2.TestCase):
    def test__request_data(self):
        expected = RequestAdapter(
            HTTP_POST,
            RFC_TEMP_URI,
            b(''),
            headers = {
                HEADER_AUTHORIZATION_CAPS: b('''\
OAuth realm="Photos",\
oauth_consumer_key="dpf43f3p2l4k3l03",\
oauth_signature_method="HMAC-SHA1",\
oauth_timestamp="137131200",\
oauth_nonce="wIjqoS",\
oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready",\
oauth_signature="74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D"'''),
            }
        )
        client_credentials = Credentials(RFC_CLIENT_IDENTIFIER,
                                         RFC_CLIENT_SECRET)

        class MockClient(_OAuthClient):
            @classmethod
            def generate_timestamp(cls):
                return RFC_TIMESTAMP_1

            @classmethod
            def generate_nonce(cls):
                return RFC_NONCE_1

        got = MockClient._request(
            client_credentials,
            HTTP_POST,
            RFC_TEMP_URI,
            realm=RFC_REALM,
            oauth_version=None,
            oauth_callback=RFC_OAUTH_CALLBACK_URI
        )
        self.assertEqual(got.method, expected.method)
        self.assertEqual(got.url, expected.url)
        self.assertEqual(got.body, expected.body)
        expected_headers, expected_realm = parse_authorization_header(
            expected.headers[HEADER_AUTHORIZATION_CAPS],
        )
        got_headers, got_realm = parse_authorization_header(
            got.headers[HEADER_AUTHORIZATION_CAPS],
        )
        self.assertDictEqual(got_headers, expected_headers)
        self.assertEqual(got_realm, expected_realm)

    def test__resource_request_data(self):
        expected = RequestAdapter(
            HTTP_GET,
            RFC_RESOURCE_FULL_URL,
            b(''),
            headers = {
                HEADER_AUTHORIZATION_CAPS: b('''\
OAuth realm="Photos",\
oauth_consumer_key="dpf43f3p2l4k3l03",\
oauth_token="nnch734d00sl2jdk",\
oauth_signature_method="HMAC-SHA1",\
oauth_timestamp="137131202",\
oauth_nonce="chapoH",\
oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"'''),
            }
        )
        auth_credentials = Credentials(RFC_TOKEN_IDENTIFIER,
                                       RFC_TOKEN_SECRET)
        client_credentials = Credentials(RFC_CLIENT_IDENTIFIER,
                                         RFC_CLIENT_SECRET)

        class MockClient(_OAuthClient):
            @classmethod
            def generate_timestamp(cls):
                return RFC_TIMESTAMP_3

            @classmethod
            def generate_nonce(cls):
                return RFC_NONCE_3

        got = MockClient._request(
            client_credentials,
            HTTP_GET,
            RFC_RESOURCE_URI,
            params={
                "file": b("vacation.jpg"),
                "size": b("original"),
            },
            realm=RFC_REALM,
            auth_credentials=auth_credentials,
            oauth_version=None
        )
        self.assertEqual(got.method, expected.method)
        self.assertEqual(got.url, expected.url)
        self.assertEqual(got.body, expected.body)
        expected_headers, expected_realm = parse_authorization_header(
            expected.headers[HEADER_AUTHORIZATION_CAPS],
        )
        got_headers, got_realm = parse_authorization_header(
            got.headers[HEADER_AUTHORIZATION_CAPS],
        )
        self.assertDictEqual(got_headers, expected_headers)
        self.assertEqual(got_realm, expected_realm)

    def test_InvalidOAuthParametersError_multiple_oauth_param_values(self):
        creds = Credentials(
            identifier=RFC_CLIENT_IDENTIFIER, shared_secret=RFC_CLIENT_SECRET)
        self.assertRaises(InvalidOAuthParametersError,
                      _OAuthClient._request,
                      creds,
                      HTTP_POST,
                      b("http://photos.example.net/blah"),
                      oauth_something=[1, 2, 3])


class Test_Client_fetch_temporary_credentials(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(
            identifier=RFC_CLIENT_IDENTIFIER, shared_secret=RFC_CLIENT_SECRET)
        self.client = Client(
            None,
            self.client_credentials,
            temporary_credentials_uri=RFC_TEMP_URI,
            token_credentials_uri=RFC_TOKEN_URI,
            authorization_uri=RFC_AUTHORIZATION_URI)
        self.temporary_credentials = Credentials(
            identifier=RFC_TEMPORARY_IDENTIFIER,
            shared_secret=RFC_TEMPORARY_SECRET)
        self.token_credentials = Credentials(
            identifier=RFC_TOKEN_IDENTIFIER, shared_secret=RFC_TOKEN_SECRET)

    def test_raises_ValueError_when_oauth_callback_is_invalid(self):
        self.assertRaises(ValueError, self.client.fetch_temporary_credentials,
                          HTTP_POST,
                          oauth_callback=BAD_OAUTH_CALLBACK)



class Test_Client_fetch_token_credentials(unittest2.TestCase):
    def setUp(self):
        self.client_credentials = Credentials(
            identifier=RFC_CLIENT_IDENTIFIER, shared_secret=RFC_CLIENT_SECRET)
        self.client = Client(
            None,
            self.client_credentials,
            temporary_credentials_uri=RFC_TEMP_URI,
            token_credentials_uri=RFC_TOKEN_URI,
            authorization_uri=RFC_AUTHORIZATION_URI)
        self.temporary_credentials = Credentials(
            identifier=RFC_TEMPORARY_IDENTIFIER,
            shared_secret=RFC_TEMPORARY_SECRET)
        self.token_credentials = Credentials(
            identifier=RFC_TOKEN_IDENTIFIER, shared_secret=RFC_TOKEN_SECRET)

    def test_raises_IllegalArgumentError_when_oauth_callback_is_invalid(self):
        self.assertRaises(IllegalArgumentError,
                          self.client.fetch_token_credentials,
                          self.temporary_credentials,
                          HTTP_POST,
                          oauth_callback=OAUTH_VALUE_CALLBACK_OOB)

