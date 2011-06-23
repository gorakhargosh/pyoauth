from nose.tools import assert_equal
from nose import SkipTest
from pyoauth.utils import oauth_parse_authorization_header_value, oauth_parse_qs, oauth_get_normalized_query_string

class TestLongToBytes:
    def test_long_to_bytes(self):
        # assert_equal(expected, long_to_bytes(v))
        raise SkipTest # TODO: implement your test here


class TestBytesToLong:
    def test_bytes_to_long(self):
        # assert_equal(expected, bytes_to_long(v))
        raise SkipTest # TODO: implement your test here


class TestOauthGenerateNonce:
    def test_oauth_generate_nonce(self):
        # assert_equal(expected, oauth_generate_nonce())
        raise SkipTest # TODO: implement your test here


class TestOauthGenerateVerificationCode:
    def test_oauth_generate_verification_code(self):
        # assert_equal(expected, oauth_generate_verification_code(length))
        raise SkipTest # TODO: implement your test here


class TestOauthGenerateTimestamp:
    def test_oauth_generate_timestamp(self):
        # assert_equal(expected, oauth_generate_timestamp())
        raise SkipTest # TODO: implement your test here


class TestOauthParseQs:
    def test_oauth_parse_qs(self):
        # assert_equal(expected, oauth_parse_qs(qs))
        raise SkipTest # TODO: implement your test here


class TestOauthEscape:
    def test_oauth_escape(self):
        # assert_equal(expected, oauth_escape(val))
        raise SkipTest # TODO: implement your test here


class TestOauthUnescape:
    def test_oauth_unescape(self):
        # assert_equal(expected, oauth_unescape(val))
        raise SkipTest # TODO: implement your test here


class TestOauthGetHmacSha1Signature:
    def test_oauth_get_hmac_sha1_signature(self):
        # assert_equal(expected, oauth_get_hmac_sha1_signature(consumer_secret, method, url, query_params, token_secret))
        raise SkipTest # TODO: implement your test here


class TestOauthGetRsaSha1Signature:
    def test_oauth_get_rsa_sha1_signature(self):
        # assert_equal(expected, oauth_get_rsa_sha1_signature(consumer_secret, method, url, query_params, token_secret))
        raise SkipTest # TODO: implement your test here


class TestOauthCheckRsaSha1Signature:
    def test_oauth_check_rsa_sha1_signature(self):
        # assert_equal(expected, oauth_check_rsa_sha1_signature(signature, consumer_secret, method, url, query_params, token_secret))
        raise SkipTest # TODO: implement your test here


class TestOauthGetPlaintextSignature:
    def test_oauth_get_plaintext_signature(self):
        # assert_equal(expected, oauth_get_plaintext_signature(consumer_secret, method, url, query_params, token_secret))
        raise SkipTest # TODO: implement your test here


class TestOauthGetSignatureBaseString:
    def test_oauth_get_signature_base_string(self):
        # assert_equal(expected, oauth_get_signature_base_string(method, url, query_params))
        raise SkipTest # TODO: implement your test here


class TestOauthGetNormalizedQueryString:
    def test_bytestrings_are_not_utf8_encoded(self):
        # Do not UTF-8 encode byte strings. Only Unicode strings should be UTF-8 encoded.
        bytestring = '\x1d\t\xa8\x93\xf9\xc9A\xed\xae\x08\x18\xf5\xe8W\xbd\xd5'
        q = oauth_get_normalized_query_string(bytestring=bytestring)
        assert_equal(oauth_parse_qs(q)['bytestring'][0], bytestring)


class TestOauthGetNormalizedUrlAndQueryParams:
    def test_oauth_get_normalized_url_and_query_params(self):
        # assert_equal(expected, oauth_get_normalized_url_and_query_params(url))
        raise SkipTest # TODO: implement your test here


class TestOauthParseAuthorizationHeader:
    def test_oauth_parse_authorization_header_value(self):
        # assert_equal(expected, oauth_parse_authorization_header_value(header_value))
        expected_value = {
            'realm': ['Examp%20le'],
            'oauth_nonce': ['4572616e48616d6d65724c61686176'],
            'oauth_timestamp': ['137131200'],
            'oauth_consumer_key': ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example'],
            'oauth_signature_method': ['HMAC-SHA1'], 'oauth_version': ['1.0'],
            'oauth_token': ['ad180jjd733klru7'], 'oauth_empty': [''],
            'oauth_signature': ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
        }
        assert_equal(expected_value, oauth_parse_authorization_header_value('''
            OAuth

            realm="Examp%20le",
            oauth_consumer_key="0685bd9184jfhq22",
            oauth_token="ad180jjd733klru7",
            oauth_signature_method="HMAC-SHA1",
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
            oauth_timestamp="137131200",
            oauth_nonce="4572616e48616d6d65724c61686176",
            oauth_version="1.0",
            oauth_something="%20Some+Example",
            oauth_empty="",
        '''))

