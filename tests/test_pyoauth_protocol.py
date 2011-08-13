#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest2

from mom.builtins import is_bytes_or_unicode, is_bytes, b
from mom.codec import bytes_to_integer, base64_decode
from mom.codec.text import utf8_encode, utf8_decode

from pyoauth.constants import HTTP_POST, HTTP_GET, OAUTH_VERSION_1, \
    OAUTH_PARAM_CONSUMER_SECRET, OAUTH_PARAM_TOKEN_SECRET, \
    OAUTH_PARAM_SIGNATURE, OAUTH_PARAM_REALM, OAUTH_PARAM_NONCE, \
    OAUTH_PARAM_TIMESTAMP, OAUTH_PARAM_CONSUMER_KEY, \
    OAUTH_PARAM_SIGNATURE_METHOD, OAUTH_PARAM_VERSION, OAUTH_PARAM_TOKEN
from pyoauth.oauth1 import SIGNATURE_METHOD_HMAC_SHA1, \
    SIGNATURE_METHOD_RSA_SHA1, SIGNATURE_METHOD_PLAINTEXT

from tests.constants import constants, \
    RFC_REALM, RFC_TEMP_URI, RFC_CLIENT_SECRET, \
    RFC_CLIENT_IDENTIFIER, RFC_TIMESTAMP_1, \
    RFC_NONCE_1, RFC_OAUTH_CALLBACK_URI, \
    RFC_TOKEN_URI, RFC_TOKEN_SECRET, \
    RFC_TOKEN_IDENTIFIER, RFC_NONCE_2, \
    RFC_TIMESTAMP_2, RFC_OAUTH_VERIFIER, \
    RFC_TEMPORARY_IDENTIFIER, RFC_TEMPORARY_SECRET, \
    RFC_NONCE_3, RFC_TIMESTAMP_3, RFC_TEMP_REQUEST_SIGNATURE, \
    RFC_TOKEN_REQUEST_SIGNATURE, RFC_RESOURCE_REQUEST_SIGNATURE

from pyoauth.error import \
    InvalidOAuthParametersError, \
    InvalidAuthorizationHeaderError, \
    InvalidHttpMethodError, \
    InvalidUrlError
from pyoauth.oauth1.protocol import parse_authorization_header, \
    generate_base_string_query, \
    generate_authorization_header, \
    percent_decode, \
    _generate_hex_verification_code, \
    generate_timestamp, \
    generate_hmac_sha1_signature, \
    generate_rsa_sha1_signature, \
    verify_rsa_sha1_signature, \
    generate_plaintext_signature, \
    generate_base_string, \
    _generate_plaintext_signature, \
    generate_nonce, _authorization_header_strip_scheme, \
    _authorization_header_parse_param, generate_client_secret


class Test_generate_nonce(unittest2.TestCase):
    def test_uniqueness(self):
        self.assertNotEqual(generate_nonce(), generate_nonce())

    def test_unsigned_integer(self):
        self.assertTrue(int(generate_nonce(64)) >= 0)

    def test_result_is_string(self):
        self.assertTrue(is_bytes(generate_nonce(64)))

    def test_range(self):
        value = int(generate_nonce(64))
        self.assertTrue(value >= 0 and value < (1 << 64)) # 2**64


class Test_generate_client_secret(unittest2.TestCase):
    def test_uniqueness(self):
        self.assertNotEqual(generate_client_secret(), generate_client_secret())

    def test_result_is_string(self):
        self.assertTrue(is_bytes(generate_client_secret()))

    def test_range(self):
        for i in range(100):
            n_bits = 144
            value = bytes_to_integer(base64_decode(generate_client_secret(144)))
            self.assertTrue(value >= 0 and value < (1 << n_bits)) # 2**n_bits


class Test_generate_verification_code(unittest2.TestCase):
    def test_length(self):
        default_length = 8
        self.assertEqual(len(_generate_hex_verification_code()), default_length,
                     "Verification code length does not match "\
                     "default expected length of %d." % default_length)
        self.assertEqual(len(_generate_hex_verification_code(length=10)), 10,
                     "Verification code length does not match expected length.")

        self.assertRaises(ValueError, _generate_hex_verification_code, 33)
        self.assertRaises(ValueError, _generate_hex_verification_code, 0)
        self.assertRaises(ValueError, _generate_hex_verification_code, -1)
        self.assertRaises(ValueError, _generate_hex_verification_code, 33)
        self.assertRaises(TypeError, _generate_hex_verification_code, None)
        self.assertRaises(TypeError, _generate_hex_verification_code, "")

    def test_uniqueness(self):
        self.assertNotEqual(_generate_hex_verification_code(),
                         _generate_hex_verification_code(),
                         "Verification code is not unique.")

    def test_is_string(self):
        self.assertTrue(is_bytes(_generate_hex_verification_code()),
                    "Verification code is not a byte string.")


class Test_generate_timestamp(unittest2.TestCase):
    def test_is_positive_integer_string(self):
        self.assertTrue(int(generate_timestamp()) > 0,
                    "Timestamp is not positive integer string.")

    def test_is_string(self):
        self.assertTrue(is_bytes_or_unicode(generate_timestamp()),
                    "Timestamp is not a string.")

    def test_is_not_empty_string(self):
        self.assertTrue(len(generate_timestamp()) > 0,
                    "Timestamp is an empty string.")


class Test_generate_hmac_sha1_signature(unittest2.TestCase):
    _examples = (
        # Temporary credentials request.
        {
            "method": HTTP_POST,
            "realm": RFC_REALM,
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
        },
        # Token credentials request.
        {
            "method": HTTP_POST,
            "realm": RFC_REALM,
            "url": RFC_TOKEN_URI,
            OAUTH_PARAM_CONSUMER_SECRET: RFC_CLIENT_SECRET,
            OAUTH_PARAM_TOKEN_SECRET: RFC_TEMPORARY_SECRET,
            OAUTH_PARAM_SIGNATURE: RFC_TOKEN_REQUEST_SIGNATURE,
            "oauth_params": dict(
                oauth_consumer_key=RFC_CLIENT_IDENTIFIER,
                oauth_token=RFC_TEMPORARY_IDENTIFIER,
                oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                oauth_timestamp=RFC_TIMESTAMP_2,
                oauth_nonce=RFC_NONCE_2,
                oauth_verifier=RFC_OAUTH_VERIFIER,
            )
        },
        # Resource access request.
        {
            "method": HTTP_GET,
            "realm": RFC_REALM,
            "url": b("http://photos.example.net/photos?"
                   "file=vacation.jpg&size=original"),
            OAUTH_PARAM_CONSUMER_SECRET: RFC_CLIENT_SECRET,
            OAUTH_PARAM_TOKEN_SECRET: RFC_TOKEN_SECRET,
            OAUTH_PARAM_SIGNATURE: RFC_RESOURCE_REQUEST_SIGNATURE,
            "oauth_params": dict(
                oauth_consumer_key=RFC_CLIENT_IDENTIFIER,
                oauth_token=RFC_TOKEN_IDENTIFIER,
                oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                oauth_timestamp=RFC_TIMESTAMP_3,
                oauth_nonce=RFC_NONCE_3,
            ),
        },
    )

    def test_signature_is_valid(self):
        for example in self._examples:
            client_shared_secret = example[OAUTH_PARAM_CONSUMER_SECRET]
            token_shared_secret = example[OAUTH_PARAM_TOKEN_SECRET]
            url = example["url"]
            method = example["method"]
            oauth_params = example["oauth_params"]
            expected_signature = example[OAUTH_PARAM_SIGNATURE]
            base_string = generate_base_string(method, url, oauth_params)
            self.assertEqual(expected_signature,
                         generate_hmac_sha1_signature(
                             base_string,
                             client_shared_secret,
                             token_shared_secret
                         ))


class Test_generate_and_verify_rsa_sha1_signature(unittest2.TestCase):
    def setUp(self):
        self._examples = (
            # http://wiki.oauth.net/w/page/12238556/TestCases
            dict(
                private_key=b('''
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
Lw03eHTNQghS0A==
-----END PRIVATE KEY-----'''),
                certificate=b('''\
-----BEGIN CERTIFICATE-----
MIIBpjCCAQ+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAZMRcwFQYDVQQDDA5UZXN0
IFByaW5jaXBhbDAeFw03MDAxMDEwODAwMDBaFw0zODEyMzEwODAwMDBaMBkxFzAV
BgNVBAMMDlRlc3QgUHJpbmNpcGFsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQC0YjCwIfYoprq/FQO6lb3asXrxLlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlY
zypSRjVxwxrsuRcP3e641SdASwfrmzyvIgP08N4S0IFzEURkV1wp/IpH7kH41Etb
mUmrXSwfNZsnQRE5SYSOhh+LcK2wyQkdgcMv11l4KoBkcwIDAQABMA0GCSqGSIb3
DQEBBQUAA4GBAGZLPEuJ5SiJ2ryq+CmEGOXfvlTtEL2nuGtr9PewxkgnOjZpUy+d
4TvuXJbNQc8f4AMWL/tO9w0Fk80rWKp9ea8/df4qMq5qlFWlx6yOLQxumNOmECKb
WpkUQDIDJEoFUzKMVuJf4KO/FJ345+BNLGgbJ6WujreoM1X/gYfdnJ/J
-----END CERTIFICATE-----'''),
                public_key=b('''\
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0YjCwIfYoprq/FQO6lb3asXrx
LlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlYzypSRjVxwxrsuRcP3e641SdASwfr
mzyvIgP08N4S0IFzEURkV1wp/IpH7kH41EtbmUmrXSwfNZsnQRE5SYSOhh+LcK2w
yQkdgcMv11l4KoBkcwIDAQAB
-----END PUBLIC KEY-----'''),
                method=HTTP_GET,
                url=b('http://photos.example.net/photos?'
                    'file=vacaction.jpg&size=original'), # <-- yes "vacaction"
                oauth_params=dict(
                    oauth_consumer_key=RFC_CLIENT_IDENTIFIER,
                    oauth_signature_method=SIGNATURE_METHOD_RSA_SHA1,
                    oauth_version=OAUTH_VERSION_1,
                    oauth_timestamp=b("1196666512"),
                    oauth_nonce="13917289812797014437",
                ),
                oauth_signature=b("\
jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5\
wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26d\
yF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE="),
        ),
    )

    def test_valid_signature(self):
        for example in self._examples:
            client_shared_secret = example["private_key"]
            client_certificate = example["certificate"]
            public_key = example["public_key"]
            url = example["url"]
            method = example["method"]
            oauth_params = example["oauth_params"]
            expected_signature = example[OAUTH_PARAM_SIGNATURE]
            # Using the RSA private key.
            base_string = generate_base_string(method, url, oauth_params)
            self.assertEqual(expected_signature,
                         generate_rsa_sha1_signature(base_string,
                                                     client_shared_secret))
            # Using the X.509 certificate.
            self.assertTrue(verify_rsa_sha1_signature(
                expected_signature,
                base_string,
                client_certificate))
            # Using the RSA public key.
            self.assertTrue(verify_rsa_sha1_signature(
                expected_signature,
                base_string,
                public_key))


class Test_generate_plaintext_signature(unittest2.TestCase):
    def setUp(self):
        self.oauth_signature_method = SIGNATURE_METHOD_PLAINTEXT
        self.oauth_token_key = b("token test key")
        self.oauth_token_secret = b("token test secret")
        self.oauth_consumer_key = b("consumer test key")
        self.oauth_consumer_secret = b("consumer test secret")
        self.oauth_params = dict(
            oauth_version=OAUTH_VERSION_1,
            oauth_nonce=b("4572616e48616d6d65724c61686176"),
            oauth_timestamp=b("137131200"),
            oauth_token=self.oauth_token_key,
            oauth_consumer_key=self.oauth_consumer_key,
            oauth_signature_method=self.oauth_signature_method,
            bar=b("blerg"),
            multi=[b("FOO"), b("BAR")],
            foo=59
        )

    def test_when_both_secrets_present(self):
        base_string = generate_base_string(
            HTTP_POST, b("http://example.com/"), self.oauth_params)
        self.assertEqual(generate_plaintext_signature(
            base_string,
            self.oauth_consumer_secret,
            self.oauth_token_secret,
            ), b("consumer%20test%20secret&token%20test%20secret"))

    def test_when_consumer_secret_present(self):
        base_string = generate_base_string(
            HTTP_POST, b("http://example.com/"), self.oauth_params)
        self.assertEqual(generate_plaintext_signature(
            base_string,
            self.oauth_consumer_secret,
            None
        ), b("consumer%20test%20secret&"))

    def test_when_token_secret_present(self):
        base_string = generate_base_string(
            HTTP_POST, b("http://example.com/"), self.oauth_params)
        self.assertEqual(generate_plaintext_signature(
            base_string,
            b(""),
            self.oauth_token_secret
        ), b("&token%20test%20secret"))

    def test_when_neither_secret_present(self):
        base_string = generate_base_string(
            HTTP_POST, b("http://example.com/"), self.oauth_params)
        self.assertEqual(generate_plaintext_signature(
            base_string,
            b(""),
            None
        ), b("&"))


class Test__generate_plaintext_signature(unittest2.TestCase):
    def test_both_secrets_present(self):
        self.assertEqual(_generate_plaintext_signature(b("ab cd"), b("47fba")),
                     b("ab%20cd&47fba"))

    def test_consumer_secret_absent(self):
        self.assertEqual(_generate_plaintext_signature(None, b("47fba")),
                         b("&47fba"))
        self.assertEqual(_generate_plaintext_signature(
            b(""), b("47fba")), b("&47fba"))


    def test_token_secret_absent(self):
        self.assertEqual(
            _generate_plaintext_signature(b("ab cd"), None), b("ab%20cd&"))
        self.assertEqual(
            _generate_plaintext_signature(b("ab cd"), b("")), b("ab%20cd&"))

    def test_both_secrets_absent(self):
        self.assertEqual(_generate_plaintext_signature(None, None), b("&"))
        self.assertEqual(_generate_plaintext_signature(b(""), b("")), b("&"))

    def test_both_secrets_are_encoded(self):
        self.assertEqual(_generate_plaintext_signature(b("ab cd"), b("47 f$a")),
                     b("ab%20cd&47%20f%24a"))

    def test_without_encoding(self):
        self.assertEqual(_generate_plaintext_signature(b("ab cd"), b("47 f$a"),
                                                       False), b("ab cd&47 f$a"))


class Test_generate_base_string(unittest2.TestCase):
    def setUp(self):
        self.oauth_params = dict(
            oauth_consumer_key=b("9djdj82h48djs9d2"),
            oauth_token=b("kkk9d7dh3k39sjv7"),
            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
            oauth_timestamp=b("137131201"),
            oauth_nonce=b("7d8f3e4a"),
            oauth_signature=b("bYT5CMsGcbgUdFHObYMEfcx6bsw%3D")
        )

    def test_valid_base_string(self):
        base_string = generate_base_string(HTTP_POST,
          b("http://example.com/request?"\
          "b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q"),
          self.oauth_params)
        self.assertEqual(base_string,
                     b("POST&"\
                     "http%3A%2F%2Fexample.com%2Frequest&"\
                     "a2%3Dr%2520b%26"\
                     "a3%3D2%2520q%26a3%3Da%26"\
                     "b5%3D%253D%25253D%26"\
                     "c%2540%3D%26"\
                     "c2%3D%26"\
                     "oauth_consumer_key%3D9djdj82h48djs9d2%26"\
                     "oauth_nonce%3D7d8f3e4a%26"\
                     "oauth_signature_method%3DHMAC-SHA1%26"\
                     "oauth_timestamp%3D137131201%26"\
                     "oauth_token%3Dkkk9d7dh3k39sjv7"))

    def test_InvalidHttpMethodError_when_invalid_http_method(self):
        self.assertRaises(InvalidHttpMethodError,
                          generate_base_string, b("TypO"),
                          b("http://example.com/request"), {})

    def test_InvalidUrlError_when_url_blank_or_None(self):
        self.assertRaises(InvalidUrlError, generate_base_string, HTTP_POST,
                          b(""), {})

    def test_InvalidOAuthParametersError_when_query_params_is_not_dict(self):
        self.assertRaises(InvalidOAuthParametersError, generate_base_string,
                          HTTP_POST, b("http://www.google.com/"), None)

    def test_base_string_does_not_contain_oauth_signature(self):
        # Ensure both are present in the query parameters as well as the URL.
        oauth_params = {
            OAUTH_PARAM_REALM: b("example.com"),
        }
        oauth_params.update(self.oauth_params)
        url = b("http://example.com/request?"
              "oauth_signature=foobar&realm=something")
        base_string = generate_base_string(HTTP_POST, url, oauth_params)
        self.assertTrue(b("oauth_signature%3D") not in base_string)
        self.assertTrue(b("realm%3Dexample.com") not in base_string)
        self.assertTrue(b("realm%3Dsomething") in base_string)


    def test_base_string_preserves_matrix_params_and_drops_default_ports(self):
        url = b("http://social.yahooapis.com:80/v1/user/6677/connections"
              ";start=0;count=20?format=json#fragment")
        decoded_base_string = "POST&" \
                      "http://social.yahooapis.com/v1/user/6677/connections" \
                      ";start=0;count=20&format=json"
        self.assertEqual(
            percent_decode(generate_base_string(HTTP_POST, url, dict())),
            decoded_base_string
        )



class Test_generate_signature_base_string_query(unittest2.TestCase):
    def setUp(self):
        self.specification_url_query_params = {
            'b5': ['=%3D'],
            'a3': ['a', '2 q'],
            'c@': [''],
            'a2': ['r b'],
            'c2': [''],
            }
        self.specification_example_oauth_params = {
            OAUTH_PARAM_SIGNATURE: 'ja87asdkhasd',
            OAUTH_PARAM_REALM: 'http://example.com',
            OAUTH_PARAM_CONSUMER_KEY: '9djdj82h48djs9d2',
            OAUTH_PARAM_TOKEN: 'kkk9d7dh3k39sjv7',
            OAUTH_PARAM_SIGNATURE_METHOD: SIGNATURE_METHOD_HMAC_SHA1,
            OAUTH_PARAM_TIMESTAMP: '137131201',
            OAUTH_PARAM_NONCE: '7d8f3e4a',
            }
        self.specification_example_query_string = b("""\
a2=r%20b\
&a3=2%20q\
&a3=a\
&b5=%3D%253D\
&c%40=\
&c2=\
&oauth_consumer_key=9djdj82h48djs9d2\
&oauth_nonce=7d8f3e4a\
&oauth_signature_method=HMAC-SHA1\
&oauth_timestamp=137131201\
&oauth_token=kkk9d7dh3k39sjv7""")
        self.simplegeo_example_url_query_params = {
            'multi': ['FOO', 'BAR', constants.test_unicode_string, constants.test_utf8_bytes],
            'multi_same': ['FOO', 'FOO'],
            'uni_utf8_bytes': constants.test_utf8_bytes,
            'uni_unicode_object': constants.test_unicode_string,
        }
        self.simplegeo_example_oauth_params = {
            OAUTH_PARAM_VERSION: OAUTH_VERSION_1,
            OAUTH_PARAM_NONCE: "4572616e48616d6d65724c61686176",
            OAUTH_PARAM_TIMESTAMP: "137131200",
            OAUTH_PARAM_CONSUMER_KEY: "0685bd9184jfhq22",
            OAUTH_PARAM_SIGNATURE_METHOD: SIGNATURE_METHOD_HMAC_SHA1,
            OAUTH_PARAM_TOKEN: "ad180jjd733klru7",
        }
        # They've got this wrong. The specification specifies sorting
        # AFTER percent-encoding. The following string is generated by sorting
        # BEFORE percent-encoding.
        self.simplegeo_example_wrong_order_query_string = \
            b("""\
multi=BAR\
&multi=FOO\
&multi=%C2%AE\
&multi=%C2%AE\
&multi_same=FOO\
&multi_same=FOO\
&oauth_consumer_key=0685bd9184jfhq22\
&oauth_nonce=4572616e48616d6d65724c61686176\
&oauth_signature_method=HMAC-SHA1\
&oauth_timestamp=137131200\
&oauth_token=ad180jjd733klru7\
&oauth_version=1.0\
&uni_unicode_object=%C2%AE\
&uni_utf8_bytes=%C2%AE""")
        self.simplegeo_example_correct_query_string = \
            b("""\
multi=%C2%AE\
&multi=%C2%AE\
&multi=BAR\
&multi=FOO\
&multi_same=FOO\
&multi_same=FOO\
&oauth_consumer_key=0685bd9184jfhq22\
&oauth_nonce=4572616e48616d6d65724c61686176\
&oauth_signature_method=HMAC-SHA1\
&oauth_timestamp=137131200\
&oauth_token=ad180jjd733klru7\
&oauth_version=1.0\
&uni_unicode_object=%C2%AE\
&uni_utf8_bytes=%C2%AE""")

    def test_oauth_specification_example(self):
        self.assertEqual(generate_base_string_query(
            self.specification_url_query_params,
            self.specification_example_oauth_params),
                     self.specification_example_query_string)

    def test_simplegeo_example(self):
        self.assertNotEqual(
            generate_base_string_query(self.simplegeo_example_url_query_params,
                                       self.simplegeo_example_oauth_params),
            self.simplegeo_example_wrong_order_query_string)
        self.assertEqual(
            generate_base_string_query(self.simplegeo_example_url_query_params,
                                       self.simplegeo_example_oauth_params),
            self.simplegeo_example_correct_query_string)

    def test_query_params_sorted_order(self):
        self.assertEqual(
            generate_base_string_query(dict(b=[8, 2, 4], a=1), {}),
            b("a=1&b=2&b=4&b=8"))
        qs = generate_base_string_query(
            dict(a=5, b=6, c=["w", "a", "t", "e", "r"]), {})
        self.assertEqual(qs, b("a=5&b=6&c=a&c=e&c=r&c=t&c=w"))

    def test_multiple_values(self):
        self.assertEqual(
            generate_base_string_query(dict(a=[5, 8]), {}),
            b("a=5&a=8")
        )

    def test_non_string_single_value(self):
        self.assertEqual(generate_base_string_query(dict(a=5), None), b("a=5"))
        self.assertEqual(
            generate_base_string_query(dict(aFlag=True, bFlag=False), None),
            b("aFlag=True&bFlag=False")
        )

    def test_no_query_params_returns_empty_string(self):
        self.assertEqual(generate_base_string_query({}, {}), b(""))
        self.assertEqual(generate_base_string_query(None, None), b(""))

    def test_oauth_signature_and_realm_are_excluded_properly(self):
        qs = generate_base_string_query({
            OAUTH_PARAM_SIGNATURE: "something"
            },
            self.specification_example_oauth_params
        )
        self.assertTrue(b("oauth_signature=") not in qs)
        self.assertTrue(b("realm=") not in qs)

        self.assertTrue(
            generate_base_string_query(dict(realm="something"), dict()),
            b("realm=something")
        )


class Test_generate_authorization_header(unittest2.TestCase):
    def test_equality_and_realm(self):
        params = {
            OAUTH_PARAM_REALM: ['Examp%20le'],
            OAUTH_PARAM_NONCE: ['4572616e48616d6d65724c61686176'],
            OAUTH_PARAM_TIMESTAMP: ['137131200'],
            OAUTH_PARAM_CONSUMER_KEY: ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example'],
            OAUTH_PARAM_SIGNATURE_METHOD: ['HMAC-SHA1'],
            OAUTH_PARAM_VERSION: [OAUTH_VERSION_1],
            OAUTH_PARAM_TOKEN: ['ad180jjd733klru7'],
            'oauth_empty': [''],
            OAUTH_PARAM_SIGNATURE: ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
            }
        expected_value = b('''\
OAuth \
oauth_consumer_key="0685bd9184jfhq22"\
,oauth_empty=""\
,oauth_nonce="4572616e48616d6d65724c61686176"\
,oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"\
,oauth_signature_method="HMAC-SHA1"\
,oauth_something="%20Some%20Example"\
,oauth_timestamp="137131200"\
,oauth_token="ad180jjd733klru7"\
,oauth_version="1.0"''')
        self.assertEqual(generate_authorization_header(params),
                         expected_value)

        expected_value = b('''\
OAuth \
realm="http://example.com/"\
,oauth_consumer_key="0685bd9184jfhq22"\
,oauth_empty=""\
,oauth_nonce="4572616e48616d6d65724c61686176"\
,oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"\
,oauth_signature_method="HMAC-SHA1"\
,oauth_something="%20Some%20Example"\
,oauth_timestamp="137131200"\
,oauth_token="ad180jjd733klru7"\
,oauth_version="1.0"''')
        self.assertEqual(
            generate_authorization_header(params, realm="http://example.com/"),
            expected_value)


    def test_param_delimiter_can_be_changed(self):
        params = {
            OAUTH_PARAM_REALM: ['Examp%20le'],
            OAUTH_PARAM_NONCE: ['4572616e48616d6d65724c61686176'],
            OAUTH_PARAM_TIMESTAMP: ['137131200'],
            OAUTH_PARAM_CONSUMER_KEY: ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example'],
            OAUTH_PARAM_SIGNATURE_METHOD: ['HMAC-SHA1'],
            OAUTH_PARAM_VERSION: [OAUTH_VERSION_1],
            OAUTH_PARAM_TOKEN: ['ad180jjd733klru7'],
            'oauth_empty': [''],
            OAUTH_PARAM_SIGNATURE: ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
            }
        expected_value = b('''OAuth \
realm="http://example.com/"\
&oauth_consumer_key="0685bd9184jfhq22"\
&oauth_empty=""\
&oauth_nonce="4572616e48616d6d65724c61686176"\
&oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"\
&oauth_signature_method="HMAC-SHA1"\
&oauth_something="%20Some%20Example"\
&oauth_timestamp="137131200"\
&oauth_token="ad180jjd733klru7"\
&oauth_version="1.0"''')
        self.assertEqual(generate_authorization_header(params,
                                                   realm="http://example.com/",
                                                   param_delimiter="&")
                     , expected_value)

    def test_InvalidOAuthParametersError_when_multiple_values(self):
        params = {
            OAUTH_PARAM_REALM: ['Examp%20le'],
            'oauth_something': [' Some Example', "another thing"],
            }
        self.assertRaises(InvalidOAuthParametersError,
                          generate_authorization_header, params)



class Test_parse_authorization_header(unittest2.TestCase):
    def test_InvalidOAuthParametersError_when_multiple_values(self):
        test_value = '''OAuth realm="Examp%20le",\
            oauth_something="%20Some+Example",\
            oauth_something="another%20thing"\
        '''
        self.assertRaises(InvalidOAuthParametersError,
                          parse_authorization_header, test_value)

    def test_value_must_not_have_newlines_when_strict(self):
        test_value = '''OAuth realm="Examp%20le",
            oauth_something="%20Some+Example",
        '''
        self.assertRaises(ValueError,
                          parse_authorization_header, test_value, strict=True)

    def test_value_can_have_newlines_when_not_strict(self):
        test_value = '''OAuth realm="Examp%20le",
            oauth_something="%20Some+Example"
        '''
        expected_value = ({
            "oauth_something": [" Some Example"],
        }, "Examp%20le")
        got = parse_authorization_header(test_value, strict=False)
        self.assertDictEqual(got[0], expected_value[0])
        self.assertEqual(got[1], expected_value[1])

    def test_param_delimiter_can_be_changed(self):
        expected_value = ({
            OAUTH_PARAM_NONCE: ['4572616e48616d6d65724c61686176'],
            OAUTH_PARAM_TIMESTAMP: ['137131200'],
            OAUTH_PARAM_CONSUMER_KEY: ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example'],
            OAUTH_PARAM_SIGNATURE_METHOD: ['HMAC-SHA1'],
            OAUTH_PARAM_VERSION: [utf8_decode(OAUTH_VERSION_1)],
            OAUTH_PARAM_TOKEN: ['ad180jjd733klru7'],
            'oauth_empty': [''],
            OAUTH_PARAM_SIGNATURE: ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
            }, 'Examp%20le'
        )
        self.assertEqual(expected_value, parse_authorization_header(b('''\
            OAuth\
\
            realm="Examp%20le"&\
            oauth_consumer_key="0685bd9184jfhq22"&\
            oauth_token="ad180jjd733klru7"&\
            oauth_signature_method="HMAC-SHA1"&\
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"&\
            oauth_timestamp="137131200"&\
            oauth_nonce="4572616e48616d6d65724c61686176"&\
            oauth_version="1.0"&\
            oauth_something="%20Some+Example"&\
            oauth_empty=""\
        '''), param_delimiter="&", strict=False), "parsing failed.")

    def test_param_delimiter_must_be_comma_when_strict(self):
        self.assertRaises(ValueError, parse_authorization_header, '''\
            OAuth\
\
            realm="Examp%20le"&\
            oauth_consumer_key="0685bd9184jfhq22"&\
            oauth_token="ad180jjd733klru7"&\
            oauth_signature_method="HMAC-SHA1"&\
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"&\
            oauth_timestamp="137131200"&\
            oauth_nonce="4572616e48616d6d65724c61686176"&\
            oauth_version="1.0"&\
            oauth_something="%20Some+Example"&\
            oauth_empty=""\
        ''', param_delimiter="&", strict=True)

    def test_equality_encoding_realm_emptyValues(self):
        expected_value = ({
            OAUTH_PARAM_NONCE: ['4572616e48616d6d65724c61686176'],
            OAUTH_PARAM_TIMESTAMP: ['137131200'],
            OAUTH_PARAM_CONSUMER_KEY: ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example'],
            OAUTH_PARAM_SIGNATURE_METHOD: ['HMAC-SHA1'],
            OAUTH_PARAM_VERSION: [utf8_decode(OAUTH_VERSION_1)],
            OAUTH_PARAM_TOKEN: ['ad180jjd733klru7'],
            'oauth_empty': [''],
            OAUTH_PARAM_SIGNATURE: ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
            }, 'Examp%20le'
        )
        self.assertEqual(expected_value, parse_authorization_header('''\
            OAuth\
\
            realm="Examp%20le",\
            oauth_consumer_key="0685bd9184jfhq22",\
            oauth_token="ad180jjd733klru7",\
            oauth_signature_method="HMAC-SHA1",\
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",\
            oauth_timestamp="137131200",\
            oauth_nonce="4572616e48616d6d65724c61686176",\
            oauth_version="1.0",\
            oauth_something="%20Some+Example",\
            oauth_empty=""\
        '''), "parsing failed.")

    def test_dict_does_not_contain_string_OAuth_realm(self):
        header = b('''OAuth realm="http://example.com",\
            oauth_consumer_key="0685bd9184jfhq22",\
            oauth_token="ad180jjd733klru7",\
            oauth_signature_method="HMAC-SHA1",\
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",\
            oauth_timestamp="137131200",\
            oauth_nonce="4572616e48616d6d65724c61686176",\
            oauth_version="1.0",\
            oauth_something="%20Some+Example",\
            oauth_empty=""\
        ''')
        params, _ = parse_authorization_header(header)
        for name, _ in params.items():
            self.assertFalse(name.lower() == 'oauth realm',
                         '`OAuth realm` found in header names')
            self.assertFalse(name.lower() == "realm",
                             '`realm` found in header names')

    def test_InvalidAuthorizationHeaderError_when_trailing_comma_is_found(self):
        header = '''OAuth oauth_consumer_key="0685bd9184jfhq22",\
            oauth_token="ad180jjd733klru7",'''
        self.assertRaises(InvalidAuthorizationHeaderError,
                          parse_authorization_header, header)

    def test_InvalidAuthorizationHeaderError_when_blank_parameter(self):
        header = '''OAuth realm="http://google.com/",,something="something"'''
        #                                           ^ Notice that?
        self.assertRaises(InvalidAuthorizationHeaderError,
                          parse_authorization_header, header)


class Test__auth_header_strip_scheme(unittest2.TestCase):
    def test_strips_auth_scheme_from_header(self):
        header = 'OAuth realm="example.com"'
        expected = 'realm="example.com"'
        self.assertEqual(_authorization_header_strip_scheme(header), expected)

    def test_ValueError_when_invalid_auth_scheme(self):
        self.assertRaises(ValueError, _authorization_header_strip_scheme,
                          'auth realm="example.com"')


class Test__auth_header_parse_param(unittest2.TestCase):
    def test_parses_param(self):
        self.assertEqual(
            _authorization_header_parse_param
                ('oauth_token="DcTLsknQAZcrPNdsu4JM%2FPX%2F"'),
            (OAUTH_PARAM_TOKEN, 'DcTLsknQAZcrPNdsu4JM/PX/')
        )

    def test_parses_realm_without_decoding(self):
        self.assertEqual(
            _authorization_header_parse_param('realm="example%20com"'),
            ("realm", "example%20com")
        )

    def test_parses_without_stripping_multiple_end_quotes(self):
        self.assertEqual(
            _authorization_header_parse_param('realm=""example.com""'),
            ("realm", '"example.com"'),
        )

    def test_InvalidAuthorizationHeaderError_when_missing_quotes(self):
        params = [
            # Missing quotes
            'something=something"',
            'something="something',
            'something=something',
            # Bad parameter value.
            '''something=''',
            '''something="''',
            # Bad parameter field.
            'something',
        ]
        for param in params:
            self.assertRaises(InvalidAuthorizationHeaderError,
                              _authorization_header_parse_param, param)




if __name__ == "__main__":
    unittest2.main()
