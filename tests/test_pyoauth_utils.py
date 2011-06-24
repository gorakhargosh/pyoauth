# -*- coding: utf-8 -*-

from nose.tools import assert_equal, assert_false, assert_true, assert_raises
from nose import SkipTest
from pyoauth.utils import oauth_parse_authorization_header_value, oauth_parse_qs, oauth_get_normalized_query_string, oauth_get_normalized_authorization_header_value, oauth_escape, oauth_unescape

class Test_oauth_escape:
    def test_unicode_input_encoded_to_utf8(self):
        assert_equal(oauth_escape(u'åéîøü'.encode('utf16')), "%FF%FE%E5%00%E9%00%EE%00%F8%00%FC%00")

class Test_oauth_unescape:
    def test_unicode_input_encoded_to_utf8(self):
        assert_equal(oauth_unescape("%FF%FE%E5%00%E9%00%EE%00%F8%00%FC%00"), u'åéîøü'.encode("utf-16"))


class Test_oauth_get_normalized_authorization_header_value:
    def test_equality_and_realm(self):
        params = {
            'realm': ['Examp%20le'],
            'oauth_nonce': ['4572616e48616d6d65724c61686176'],
            'oauth_timestamp': ['137131200'],
            'oauth_consumer_key': ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example', 'another entry'],
            'oauth_signature_method': ['HMAC-SHA1'],
            'oauth_version': ['1.0'],
            'oauth_token': ['ad180jjd733klru7'], 'oauth_empty': [''],
            'oauth_signature': ['wOJIO9A2W5mFwDgiDvZbTSMK/PY='],
        }
        expected_value = 'OAuth oauth_consumer_key="0685bd9184jfhq22",\n               oauth_empty="",\n               oauth_nonce="4572616e48616d6d65724c61686176",\n               oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",\n               oauth_signature_method="HMAC-SHA1",\n               oauth_something="%20Some%20Example",\n               oauth_something="another%20entry",\n               oauth_timestamp="137131200",\n               oauth_token="ad180jjd733klru7",\n               oauth_version="1.0"'
        assert_equal(oauth_get_normalized_authorization_header_value(params), expected_value)

        expected_value = 'OAuth realm="http://example.com/",\n               oauth_consumer_key="0685bd9184jfhq22",\n               oauth_empty="",\n               oauth_nonce="4572616e48616d6d65724c61686176",\n               oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",\n               oauth_signature_method="HMAC-SHA1",\n               oauth_something="%20Some%20Example",\n               oauth_something="another%20entry",\n               oauth_timestamp="137131200",\n               oauth_token="ad180jjd733klru7",\n               oauth_version="1.0"'
        assert_equal(oauth_get_normalized_authorization_header_value(params, realm="http://example.com/"), expected_value)

class Test_oauth_parse_authorization_header:
    def test_equality_encoding_realm_emptyValues_and_multipleValues(self):
        # assert_equal(expected, oauth_parse_authorization_header_value(header_value))
        expected_value = {
            'realm': ['Examp%20le'],
            'oauth_nonce': ['4572616e48616d6d65724c61686176'],
            'oauth_timestamp': ['137131200'],
            'oauth_consumer_key': ['0685bd9184jfhq22'],
            'oauth_something': [' Some Example', 'another entry'],
            'oauth_signature_method': ['HMAC-SHA1'],
            'oauth_version': ['1.0'],
            'oauth_token': ['ad180jjd733klru7'],
            'oauth_empty': [''],
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
            oauth_something="another%20entry",
            oauth_empty="",
        '''), "parsing failed.")

    def test_dict_does_not_contain_string_OAuth_realm(self):
        header_value = '''OAuth realm="http://example.com",
            oauth_consumer_key="0685bd9184jfhq22",
            oauth_token="ad180jjd733klru7",
            oauth_signature_method="HMAC-SHA1",
            oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
            oauth_timestamp="137131200",
            oauth_nonce="4572616e48616d6d65724c61686176",
            oauth_version="1.0",
            oauth_something="%20Some+Example",
            oauth_empty=""
        '''
        for name, value in oauth_parse_authorization_header_value(header_value).iteritems():
            assert_false(name == 'OAuth realm', '`OAuth realm` found in header names')

    def test_trailing_comma_is_ignored(self):
        header_value = '''OAuth oauth_consumer_key="0685bd9184jfhq22",
            oauth_token="ad180jjd733klru7",'''
        assert_equal(oauth_parse_authorization_header_value(header_value), {
            'oauth_consumer_key': ['0685bd9184jfhq22'],
            'oauth_token': ['ad180jjd733klru7'],
        }, "trailing comma was not ignored.")

    def test_ValueError_when_bad_parameter_field(self):
        header_value = '''OAuth realm="http://www.google.com/",something'''
        assert_raises(ValueError, oauth_parse_authorization_header_value, header_value)

    def test_ValueError_when_bad_parameter_value(self):
        header_value = '''OAuth realm="http://www.google.com/",something='''
        assert_raises(ValueError, oauth_parse_authorization_header_value, header_value)

        header_value = '''OAuth realm="http://www.google.com/",something="'''
        assert_raises(ValueError, oauth_parse_authorization_header_value, header_value)

    def test_ValueError_when_missing_quotes_around_value(self):
        header_value = '''OAuth realm="http://www.google.com/",something="something'''
        assert_raises(ValueError, oauth_parse_authorization_header_value, header_value)

        header_value = '''OAuth realm="http://www.google.com/",something=something"'''
        assert_raises(ValueError, oauth_parse_authorization_header_value, header_value)

        header_value = '''OAuth realm="http://www.google.com/",something=something'''
        assert_raises(ValueError, oauth_parse_authorization_header_value, header_value)
