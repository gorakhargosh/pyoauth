# -*- coding: utf-8 -*-

from nose.tools import assert_equal, \
    assert_not_equal, \
    assert_false, \
    assert_true, \
    assert_raises
from nose import SkipTest
try:
    from nose.tools import assert_dict_equal
except ImportError:
    assert_dict_equal = assert_equal

from mom.builtins import bytes

from pyoauth.error import \
    InvalidOAuthParametersError, \
    InvalidAuthorizationHeaderError, \
    InvalidHttpMethodError, \
    InvalidUrlError
from pyoauth.protocol import parse_authorization_header, \
    generate_base_string_query, \
    generate_authorization_header, \
    percent_decode, \
    generate_verification_code, \
    generate_timestamp, \
    generate_hmac_sha1_signature, \
    generate_rsa_sha1_signature, \
    verify_rsa_sha1_signature, \
    generate_plaintext_signature, \
    generate_base_string, \
    _generate_plaintext_signature, \
    generate_nonce


class Test_generate_nonce(object):
    def test_uniqueness(self):
        assert_not_equal(generate_nonce(), generate_nonce())

    def test_hex_length(self):
        for i in range(1, 1000):
            assert_equal(len(generate_nonce(64, 16)), 16)

    def test_unsigned_integer(self):
        assert_true(int(generate_nonce(64, 10)) >= 0)
        assert_true(int(generate_nonce(64, 16), 16) >= 0)

    def test_raises_ValueError_when_invalid_bit_strength(self):
        assert_raises(ValueError, generate_nonce, 63)
        assert_raises(ValueError, generate_nonce, 0)

    def test_result_is_string(self):
        assert_true(isinstance(generate_nonce(64, 10), bytes))
        assert_true(isinstance(generate_nonce(64, 16), bytes))


class Test_generate_verification_code(object):
    def test_length(self):
        default_length = 8
        assert_equal(len(generate_verification_code()), default_length,
                     "Verification code length does not match "\
                     "default expected length of %d." % default_length)
        assert_equal(len(generate_verification_code(length=10)), 10,
                     "Verification code length does not match expected length.")

        assert_raises(ValueError, generate_verification_code, 33)
        assert_raises(ValueError, generate_verification_code, 0)
        assert_raises(ValueError, generate_verification_code, -1)
        assert_raises(ValueError, generate_verification_code, 33)
        assert_raises(TypeError, generate_verification_code, None)
        assert_raises(TypeError, generate_verification_code, "")

    def test_uniqueness(self):
        assert_not_equal(generate_verification_code(),
                         generate_verification_code(),
                         "Verification code is not unique.")

    def test_is_string(self):
        assert_true(isinstance(generate_verification_code(), bytes),
                    "Verification code is not a bytestring.")


class Test_generate_timestamp(object):
    def test_is_positive_integer_string(self):
        assert_true(int(generate_timestamp()) > 0,
                    "Timestamp is not positive integer string.")

    def test_is_string(self):
        assert_true(isinstance(generate_timestamp(), bytes),
                    "Timestamp is not a string.")

    def test_is_not_empty_string(self):
        assert_true(len(generate_timestamp()) > 0,
                    "Timestamp is an empty string.")


class Test_generate_hmac_sha1_signature(object):
    _examples = (
        # Temporary credentials request.
        {
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
        },
        # Token credentials request.
        {
            "method": "POST",
            "realm": "Photos",
            "url": "https://photos.example.net/token",
            "oauth_consumer_secret": "kd94hf93k423kf44",
            "oauth_token_secret": "hdhd0244k9j7ao03",
            "oauth_signature": "gKgrFCywp7rO0OXSjdot/IHF7IU=",
            "oauth_params": dict(
                oauth_consumer_key="dpf43f3p2l4k3l03",
                oauth_token="hh5s93j4hdidpola",
                oauth_signature_method="HMAC-SHA1",
                oauth_timestamp="137131201",
                oauth_nonce="walatlh",
                oauth_verifier="hfdp7dh39dks9884",
            )
        },
        # Resource access request.
        {
            "method": "GET",
            "realm": "Photos",
            "url": "http://photos.example.net/photos?"\
                   "file=vacation.jpg&size=original",
            "oauth_consumer_secret": "kd94hf93k423kf44",
            "oauth_token_secret": "pfkkdhi9sl3r4s00",
            "oauth_signature": "MdpQcU8iPSUjWoN/UDMsK2sui9I=",
            "oauth_params": dict(
                oauth_consumer_key="dpf43f3p2l4k3l03",
                oauth_token="nnch734d00sl2jdk",
                oauth_signature_method="HMAC-SHA1",
                oauth_timestamp="137131202",
                oauth_nonce="chapoH",
            ),
        },
    )

    def test_signature_is_valid(self):
        for example in self._examples:
            client_shared_secret = example["oauth_consumer_secret"]
            token_shared_secret = example["oauth_token_secret"]
            url = example["url"]
            method = example["method"]
            oauth_params = example["oauth_params"]
            expected_signature = example["oauth_signature"]
            base_string = generate_base_string(method, url, oauth_params)
            assert_equal(expected_signature,
                         generate_hmac_sha1_signature(
                             base_string,
                             client_shared_secret,
                             token_shared_secret
                         ))


class Test_generate_and_verify_rsa_sha1_signature(object):
    def setUp(self):
        self._examples = (
            # http://wiki.oauth.net/w/page/12238556/TestCases
            dict(
                private_key='''
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
-----END PRIVATE KEY-----''',
                certificate='''\
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
-----END CERTIFICATE-----''',
                public_key='''\
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0YjCwIfYoprq/FQO6lb3asXrx
LlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlYzypSRjVxwxrsuRcP3e641SdASwfr
mzyvIgP08N4S0IFzEURkV1wp/IpH7kH41EtbmUmrXSwfNZsnQRE5SYSOhh+LcK2w
yQkdgcMv11l4KoBkcwIDAQAB
-----END PUBLIC KEY-----''',
                method="GET",
                url='http://photos.example.net/photos?'\
                    'file=vacaction.jpg&size=original', # <-- yes "vacaction"
                oauth_params=dict(
                    oauth_consumer_key="dpf43f3p2l4k3l03",
                    oauth_signature_method="RSA-SHA1",
                    oauth_version="1.0",
                    oauth_timestamp="1196666512",
                    oauth_nonce="13917289812797014437",
                ),
                oauth_signature="\
jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5\
wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26d\
yF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE=",
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
            expected_signature = example["oauth_signature"]
            # Using the RSA private key.
            base_string = generate_base_string(method, url, oauth_params)
            assert_equal(expected_signature,
                         generate_rsa_sha1_signature(base_string,
                                                     client_shared_secret))
            # Using the X.509 certificate.
            assert_true(verify_rsa_sha1_signature(
                expected_signature,
                base_string,
                client_certificate))
            # Using the RSA public key.
            assert_true(verify_rsa_sha1_signature(
                expected_signature,
                base_string,
                public_key))


class Test_generate_plaintext_signature(object):
    def setUp(self):
        self.oauth_signature_method = "PLAINTEXT"
        self.oauth_token_key = "token test key"
        self.oauth_token_secret = "token test secret"
        self.oauth_consumer_key = "consumer test key"
        self.oauth_consumer_secret = "consumer test secret"
        self.oauth_params = dict(
            oauth_version='1.0',
            oauth_nonce="4572616e48616d6d65724c61686176",
            oauth_timestamp="137131200",
            oauth_token=self.oauth_token_key,
            oauth_consumer_key=self.oauth_consumer_key,
            oauth_signature_method=self.oauth_signature_method,
            bar="blerg",
            multi=["FOO", "BAR"],
            foo=59
        )

    def test_when_both_secrets_present(self):
        base_string = generate_base_string(
            "POST", "http://example.com/", self.oauth_params)
        assert_equal(generate_plaintext_signature(
            base_string,
            self.oauth_consumer_secret,
            self.oauth_token_secret,
            ), "consumer%20test%20secret&token%20test%20secret")

    def test_when_consumer_secret_present(self):
        base_string = generate_base_string(
            "POST", "http://example.com/", self.oauth_params)
        assert_equal(generate_plaintext_signature(
            base_string,
            self.oauth_consumer_secret,
            None
        ), "consumer%20test%20secret&")

    def test_when_token_secret_present(self):
        base_string = generate_base_string(
            "POST", "http://example.com/", self.oauth_params)
        assert_equal(generate_plaintext_signature(
            base_string,
            "",
            self.oauth_token_secret
        ), "&token%20test%20secret")

    def test_when_neither_secret_present(self):
        base_string = generate_base_string(
            "POST", "http://example.com/", self.oauth_params)
        assert_equal(generate_plaintext_signature(
            base_string,
            "",
            None
        ), "&")


class Test__generate_plaintext_signature(object):
    def test_both_secrets_present(self):
        assert_equal(_generate_plaintext_signature("ab cd", "47fba"),
                     "ab%20cd&47fba")

    def test_consumer_secret_absent(self):
        assert_equal(_generate_plaintext_signature(None, "47fba"), "&47fba")
        assert_equal(_generate_plaintext_signature("", "47fba"), "&47fba")


    def test_token_secret_absent(self):
        assert_equal(_generate_plaintext_signature("ab cd", None), "ab%20cd&")
        assert_equal(_generate_plaintext_signature("ab cd", ""), "ab%20cd&")

    def test_both_secrets_absent(self):
        assert_equal(_generate_plaintext_signature(None, None), "&")
        assert_equal(_generate_plaintext_signature("", ""), "&")

    def test_both_secrets_are_encoded(self):
        assert_equal(_generate_plaintext_signature("ab cd", "47 f$a"),
                     "ab%20cd&47%20f%24a")


class Test_generate_base_string(object):
    def setUp(self):
        self.oauth_params = dict(
            oauth_consumer_key="9djdj82h48djs9d2",
            oauth_token="kkk9d7dh3k39sjv7",
            oauth_signature_method="HMAC-SHA1",
            oauth_timestamp="137131201",
            oauth_nonce="7d8f3e4a",
            oauth_signature="bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
        )

    def test_valid_base_string(self):
        base_string = generate_base_string("POST",
          "http://example.com/request?"\
          "b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q",
          self.oauth_params)
        assert_equal(base_string,
                     "POST&"\
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
                     "oauth_token%3Dkkk9d7dh3k39sjv7")

    def test_InvalidHttpMethodError_when_invalid_http_method(self):
        assert_raises(InvalidHttpMethodError, generate_base_string, "TypO",
                      "http://example.com/request", {})

    def test_InvalidUrlError_when_url_blank_or_None(self):
        assert_raises(InvalidUrlError, generate_base_string, "POST", "",
                {})

    def test_InvalidOAuthParametersError_when_query_params_is_not_dict(self):
        assert_raises(InvalidOAuthParametersError, generate_base_string, "POST",
                      "http://www.google.com/", None)

    def test_base_string_does_not_contain_oauth_signature(self):
        # Ensure both are present in the query params as well as the URL.
        oauth_params = {
            "realm": "example.com",
        }
        oauth_params.update(self.oauth_params)
        url = "http://example.com/request?"\
              "oauth_signature=foobar&realm=something"
        base_string = generate_base_string("POST", url, oauth_params)
        assert_true("oauth_signature%3D" not in base_string)
        assert_true("realm%3Dexample.com" not in base_string)
        assert_true("realm%3Dsomething" in base_string)


    def test_base_string_preserves_matrix_params_and_drops_default_ports(self):
        url = "http://social.yahooapis.com:80/v1/user/6677/connections"\
              ";start=0;count=20?format=json#fragment"
        base_string = "POST&"\
                      "http://social.yahooapis.com/v1/user/6677/connections"\
                      ";start=0;count=20&format=json"
        assert_equal(
            percent_decode(
                generate_base_string("POST", url, dict())), base_string)



class Test_generate_signature_base_string_query(object):
    def setUp(self):
        self.specification_url_query_params = {
            'b5': ['=%3D'],
            'a3': ['a', '2 q'],
            'c@': [''],
            'a2': ['r b'],
            'c2': [''],
            }
        self.specification_example_oauth_params = {
            'oauth_signature': 'ja87asdkhasd',
            'realm': 'http://example.com',
            'oauth_consumer_key': '9djdj82h48djs9d2',
            'oauth_token': 'kkk9d7dh3k39sjv7',
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_timestamp': '137131201',
            'oauth_nonce': '7d8f3e4a',
            }
        self.specification_example_query_string = "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        self.simplegeo_example_url_query_params = {
            'multi': ['FOO', 'BAR', u'\u00ae', '\xc2\xae'],
            'multi_same': ['FOO', 'FOO'],
            'uni_utf8_bytes': '\xc2\xae',
            'uni_unicode_object': u'\u00ae',
        }
        self.simplegeo_example_oauth_params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
        }
        # They've got this wrong. The spec specifies sorting AFTER encoding.
        # The following string is generated by sorting BEFORE encoding.
        self.simplegeo_example_wrong_order_query_string = 'multi=BAR&multi=FOO&multi=%C2%AE&multi=%C2%AE&multi_same=FOO&multi_same=FOO&oauth_consumer_key=0685bd9184jfhq22&oauth_nonce=4572616e48616d6d65724c61686176&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131200&oauth_token=ad180jjd733klru7&oauth_version=1.0&uni_unicode_object=%C2%AE&uni_utf8_bytes=%C2%AE'
        self.simplegeo_example_correct_query_string = 'multi=%C2%AE&multi=%C2%AE&multi=BAR&multi=FOO&multi_same=FOO&multi_same=FOO&oauth_consumer_key=0685bd9184jfhq22&oauth_nonce=4572616e48616d6d65724c61686176&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131200&oauth_token=ad180jjd733klru7&oauth_version=1.0&uni_unicode_object=%C2%AE&uni_utf8_bytes=%C2%AE'

    def test_oauth_specification_example(self):
        assert_equal(generate_base_string_query(
            self.specification_url_query_params,
            self.specification_example_oauth_params),
                     self.specification_example_query_string)

    def test_simplegeo_example(self):
        assert_not_equal(
            generate_base_string_query(self.simplegeo_example_url_query_params,
                                              self.simplegeo_example_oauth_params),
            self.simplegeo_example_wrong_order_query_string)
        assert_equal(
            generate_base_string_query(self.simplegeo_example_url_query_params,
                                              self.simplegeo_example_oauth_params),
            self.simplegeo_example_correct_query_string)

    def test_query_params_sorted_order(self):
        assert_equal("a=1&b=2&b=4&b=8",
                     generate_base_string_query(dict(b=[8, 2, 4], a=1), {}))
        qs = generate_base_string_query(
            dict(a=5, b=6, c=["w", "a", "t", "e", "r"]), {})
        assert_equal("a=5&b=6&c=a&c=e&c=r&c=t&c=w", qs)

    def test_multiple_values(self):
        assert_equal("a=5&a=8",
                     generate_base_string_query(dict(a=[5, 8]), {}))

    def test_non_string_single_value(self):
        assert_equal("a=5", generate_base_string_query(dict(a=5), None))
        assert_equal("aFlag=True&bFlag=False",
                     generate_base_string_query(
                         dict(aFlag=True, bFlag=False), None))

    def test_no_query_params_returns_empty_string(self):
        assert_equal("", generate_base_string_query({}, {}))
        assert_equal("", generate_base_string_query(None, None))

    def test_oauth_signature_and_realm_are_excluded_properly(self):
        qs = generate_base_string_query({
            "oauth_signature": "something"
            },
            self.specification_example_oauth_params
        )
        assert_true("oauth_signature=" not in qs)
        assert_true("realm=" not in qs)

        assert_true(
            generate_base_string_query(dict(realm="something"), dict()),
            "realm=something")


class Test_generate_authorization_header(object):
    def test_equality_and_realm(self):
        params = {
            'realm': ['Examp%20le'],
            'oauth_nonce': ['4572616e48616d6d65724c61686176'],
            'oauth_timestamp': ['137131200'],
            'oauth_consumer_key': ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example'],
            'oauth_signature_method': ['HMAC-SHA1'],
            'oauth_version': ['1.0'],
            'oauth_token': ['ad180jjd733klru7'],
            'oauth_empty': [''],
            'oauth_signature': ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
            }
        expected_value = 'OAuth oauth_consumer_key="0685bd9184jfhq22",oauth_empty="",oauth_nonce="4572616e48616d6d65724c61686176",oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",oauth_signature_method="HMAC-SHA1",oauth_something="%20Some%20Example",oauth_timestamp="137131200",oauth_token="ad180jjd733klru7",oauth_version="1.0"'
        assert_equal(generate_authorization_header(params),
                     expected_value)

        expected_value = 'OAuth realm="http://example.com/",oauth_consumer_key="0685bd9184jfhq22",oauth_empty="",oauth_nonce="4572616e48616d6d65724c61686176",oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",oauth_signature_method="HMAC-SHA1",oauth_something="%20Some%20Example",oauth_timestamp="137131200",oauth_token="ad180jjd733klru7",oauth_version="1.0"'
        assert_equal(generate_authorization_header(params,
                                                   realm="http://example.com/")
                     , expected_value)


    def test_param_delimiter_can_be_changed(self):
        params = {
            'realm': ['Examp%20le'],
            'oauth_nonce': ['4572616e48616d6d65724c61686176'],
            'oauth_timestamp': ['137131200'],
            'oauth_consumer_key': ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example'],
            'oauth_signature_method': ['HMAC-SHA1'],
            'oauth_version': ['1.0'],
            'oauth_token': ['ad180jjd733klru7'],
            'oauth_empty': [''],
            'oauth_signature': ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
            }
        expected_value = 'OAuth realm="http://example.com/"&oauth_consumer_key="0685bd9184jfhq22"&oauth_empty=""&oauth_nonce="4572616e48616d6d65724c61686176"&oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D"&oauth_signature_method="HMAC-SHA1"&oauth_something="%20Some%20Example"&oauth_timestamp="137131200"&oauth_token="ad180jjd733klru7"&oauth_version="1.0"'
        assert_equal(generate_authorization_header(params,
                                                   realm="http://example.com/",
                                                   param_delimiter="&")
                     , expected_value)

    def test_InvalidOAuthParametersError_when_multiple_values(self):
        params = {
            'realm': ['Examp%20le'],
            'oauth_something': [' Some Example', "another thing"],
            }
        assert_raises(InvalidOAuthParametersError, generate_authorization_header, params)



class Test_parse_authorization_header(object):
    def test_InvalidOAuthParametersError_when_multiple_values(self):
        test_value = '''OAuth realm="Examp%20le",\
            oauth_something="%20Some+Example",\
            oauth_something="another%20thing"\
        '''
        assert_raises(InvalidOAuthParametersError, parse_authorization_header, test_value)

    def test_value_must_not_have_newlines_when_strict(self):
        test_value = '''OAuth realm="Examp%20le",
            oauth_something="%20Some+Example",
        '''
        assert_raises(ValueError, parse_authorization_header, test_value, strict=True)

    def test_param_delimiter_can_be_changed(self):
        expected_value = ({
            'oauth_nonce': ['4572616e48616d6d65724c61686176'],
            'oauth_timestamp': ['137131200'],
            'oauth_consumer_key': ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example'],
            'oauth_signature_method': ['HMAC-SHA1'],
            'oauth_version': ['1.0'],
            'oauth_token': ['ad180jjd733klru7'],
            'oauth_empty': [''],
            'oauth_signature': ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
            }, 'Examp%20le'
        )
        assert_equal(expected_value, parse_authorization_header('''\
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
        ''', param_delimiter="&", strict=False), "parsing failed.")

    def test_param_delimiter_must_be_comma_when_strict(self):
        assert_raises(ValueError, parse_authorization_header, '''\
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
            'oauth_nonce': ['4572616e48616d6d65724c61686176'],
            'oauth_timestamp': ['137131200'],
            'oauth_consumer_key': ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example'],
            'oauth_signature_method': ['HMAC-SHA1'],
            'oauth_version': ['1.0'],
            'oauth_token': ['ad180jjd733klru7'],
            'oauth_empty': [''],
            'oauth_signature': ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
            }, 'Examp%20le'
        )
        assert_equal(expected_value, parse_authorization_header('''\
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
        header_value = '''OAuth realm="http://example.com",\
            oauth_consumer_key="0685bd9184jfhq22",\
            oauth_token="ad180jjd733klru7",\
            oauth_signature_method="HMAC-SHA1",\
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",\
            oauth_timestamp="137131200",\
            oauth_nonce="4572616e48616d6d65724c61686176",\
            oauth_version="1.0",\
            oauth_something="%20Some+Example",\
            oauth_empty=""\
        '''
        params, realm = parse_authorization_header(
            header_value)
        for name, value in params.items():
            assert_false(name.lower() == 'oauth realm',
                         '`OAuth realm` found in header names')
            assert_false(name.lower() == "realm", '`realm` found in header names')

    def test_InvalidAuthorizationHeaderError_when_trailing_comma_is_found(self):
        header_value = '''OAuth oauth_consumer_key="0685bd9184jfhq22",\
            oauth_token="ad180jjd733klru7",'''
        assert_raises(InvalidAuthorizationHeaderError, parse_authorization_header, header_value)

    def test_InvalidAuthorizationHeaderError_when_bad_parameter_field(self):
        header_value = '''OAuth realm="http://www.google.com/",something'''
        assert_raises(InvalidAuthorizationHeaderError, parse_authorization_header,
                      header_value)

    def test_InvalidAuthorizationHeaderError_when_bad_parameter_value(self):
        header_value = '''OAuth realm="http://www.google.com/",something='''
        assert_raises(InvalidAuthorizationHeaderError, parse_authorization_header,
                      header_value)

        header_value = '''OAuth realm="http://www.google.com/",something="'''
        assert_raises(InvalidAuthorizationHeaderError, parse_authorization_header,
                      header_value)

    def test_InvalidAuthorizationHeaderError_when_missing_quotes_around_value(self):
        header_value = '''OAuth realm="http://www.google.com/",something="something'''
        assert_raises(InvalidAuthorizationHeaderError, parse_authorization_header,
                      header_value)

        header_value = '''OAuth realm="http://www.google.com/",something=something"'''
        assert_raises(InvalidAuthorizationHeaderError, parse_authorization_header,
                      header_value)

        header_value = '''OAuth realm="http://www.google.com/",something=something'''
        assert_raises(InvalidAuthorizationHeaderError, parse_authorization_header,
                      header_value)
