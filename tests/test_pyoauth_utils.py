# -*- coding: utf-8 -*-

from nose.tools import assert_equal, assert_not_equal, assert_dict_equal, assert_false, assert_true, assert_raises
from nose import SkipTest
from pyoauth.utils import oauth_parse_authorization_header_value, oauth_parse_qs, oauth_get_normalized_query_string, oauth_get_normalized_authorization_header_value, oauth_escape, oauth_unescape, oauth_generate_nonce, oauth_generate_verification_code, oauth_generate_timestamp

class Test_oauth_generate_nonce(object):
    def test_uniqueness(self):
        assert_not_equal(oauth_generate_nonce(), oauth_generate_nonce(),
                         "Nonce is not unique.")

    def test_is_string(self):
        assert_true(isinstance(oauth_generate_nonce(), str),
                    "Nonce is not a bytestring.")


class Test_oauth_generate_verification_code(object):
    def test_length(self):
        assert_equal(len(oauth_generate_verification_code()), 8,
                     "Verification code length does not match expected length.")
        assert_equal(len(oauth_generate_verification_code(length=10)), 10,
                     "Verification code length does not match expected length.")

    def test_uniqueness(self):
        assert_not_equal(oauth_generate_verification_code(),
                         oauth_generate_verification_code(),
                         "Verification code is not unique.")

    def test_is_string(self):
        assert_true(isinstance(oauth_generate_verification_code(), str),
                    "Verification code is not a bytestring.")


class Test_oauth_generate_timestamp(object):
    def test_is_positive_integer_string(self):
        assert_true(int(oauth_generate_timestamp()) > 0,
                    "Timestamp is not positive integer string.")

    def test_is_string(self):
        assert_true(isinstance(oauth_generate_timestamp(), str),
                    "Timestamp is not a string.")

    def test_is_not_empty_string(self):
        assert_true(len(oauth_generate_timestamp()) > 0,
                    "Timestamp is an empty string.")


class Test_oauth_parse_qs(object):
    def test_are_blank_values_preserved(self):
        assert_dict_equal(oauth_parse_qs("a="), {"a": [""]})
        assert_dict_equal(oauth_parse_qs("a"), {"a": [""]})

    def test_are_multiple_values_obtained(self):
        assert_dict_equal(oauth_parse_qs("a=1&a=2&a=3&b=c"),
                {"a": ["1", "2", "3"], "b": ["c"]})

    def test_single_value_lists_are_not_flattened(self):
        d = oauth_parse_qs("a=1&a=2&a=3&b=c")
        for n, v in d.iteritems():
            assert_true(isinstance(n, str), "Dictionary key is not a string.")
            assert_true(isinstance(v, list), "Dictionary value is not a list.")

    def test_names_and_values_are_percent_decoded(self):
        qs = 'b5=%3D%253D&a3=a&c%40=&a2=r%20b' + '&' + 'c2&a3=2+q'
        q = oauth_parse_qs(qs)
        assert_dict_equal(q,
                {'a2': ['r b'], 'a3': ['a', '2 q'], 'b5': ['=%3D'], 'c@': [''],
                 'c2': ['']})

    def test_percent_decoding_treats_plus_as_space(self):
        assert_dict_equal(oauth_parse_qs('a=2+q'), {'a': ['2 q']})


class Test_oauth_escape(object):
    #def test_unicode_input_encoded_to_utf8(self):
    #    assert_equal(oauth_escape(u'åéîøü'.encode('utf16')),
    #                 "%FF%FE%E5%00%E9%00%EE%00%F8%00%FC%00")
    _unsafe_characters = [" ",
                       ":",
                       "!",
                       "@",
                       "#",
                       "$",
                       "%",
                       "^",
                       "&",
                       "*",
                       "(",
                       ")",
                       "+",
                       "{",
                       "}",
                       "[",
                       "]",
                       "|",
                       "\\",
                       ":",
                       ";",
                       '"',
                       "'",
                       ",",
                       "<",
                       ">",
                       "?",
                       "/",
                       "`",
                       "´",
                       u"å",
                       ]

    def test_safe_symbols_are_not_encoded(self):
        safe_symbols = ["-", ".", "_", "~"]
        for symbol in safe_symbols:
            assert_equal(oauth_escape(symbol), symbol,
                         "Symbol %s should not be encoded." % (symbol,))

    def test_digits_are_not_encoded(self):
        digits = [str(x) for x in range(10)]
        for digit in digits:
            assert_equal(oauth_escape(digit), digit,
                         "Digits should not be encoded.")

    def test_alphabets_are_not_encoded(self):
        lowercase_alphabets = [chr(x) for x in range(ord('a'), ord('z') + 1)]
        uppercase_alphabers = [chr(x) for x in range(ord('A'), ord('Z') + 1)]
        alphabets = lowercase_alphabets + uppercase_alphabers
        for alphabet in alphabets:
            assert_equal(oauth_escape(alphabet), alphabet,
                         "Alphabets should not be encoded.")

    def test_space_is_not_encoded_as_plus(self):
        assert_not_equal(oauth_escape(" "), "+")
        assert_equal(oauth_escape(" "), "%20")

    def test_unsafe_characters_are_encoded(self):
        for char in self._unsafe_characters:
            assert_not_equal(oauth_escape(char), char)

    def test_character_encoding_is_uppercase(self):
        for char in self._unsafe_characters:
            for c in oauth_escape(char):
                if c.isalpha():
                    assert_true(c.isupper(), "Percent-encoding is not uppercase: %r for char: %r" % (c, char))

    def test_percent_encoded(self):
        for char in self._unsafe_characters:
            assert_equal(oauth_escape(char)[0], "%", "Character not percent-encoded.")

class Test_oauth_unescape(object):
    #def test_unicode_input_encoded_to_utf8(self):
    #    assert_equal(oauth_unescape("%FF%FE%E5%00%E9%00%EE%00%F8%00%FC%00"),
    #                 u'åéîøü'.encode("utf-16"))
    pass


class Test_oauth_get_normalized_authorization_header_value(object):
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
        assert_equal(oauth_get_normalized_authorization_header_value(params),
                     expected_value)

        expected_value = 'OAuth realm="http://example.com/",\n               oauth_consumer_key="0685bd9184jfhq22",\n               oauth_empty="",\n               oauth_nonce="4572616e48616d6d65724c61686176",\n               oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",\n               oauth_signature_method="HMAC-SHA1",\n               oauth_something="%20Some%20Example",\n               oauth_something="another%20entry",\n               oauth_timestamp="137131200",\n               oauth_token="ad180jjd733klru7",\n               oauth_version="1.0"'
        assert_equal(oauth_get_normalized_authorization_header_value(params,
                                                                     realm="http://example.com/")
                     , expected_value)


class Test_oauth_parse_authorization_header(object):
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
        for name, value in oauth_parse_authorization_header_value(
            header_value).iteritems():
            assert_false(name == 'OAuth realm',
                         '`OAuth realm` found in header names')

    def test_trailing_comma_is_ignored(self):
        header_value = '''OAuth oauth_consumer_key="0685bd9184jfhq22",
            oauth_token="ad180jjd733klru7",'''
        assert_equal(oauth_parse_authorization_header_value(header_value), {
            'oauth_consumer_key': ['0685bd9184jfhq22'],
            'oauth_token': ['ad180jjd733klru7'],
            }, "trailing comma was not ignored.")

    def test_ValueError_when_bad_parameter_field(self):
        header_value = '''OAuth realm="http://www.google.com/",something'''
        assert_raises(ValueError, oauth_parse_authorization_header_value,
                      header_value)

    def test_ValueError_when_bad_parameter_value(self):
        header_value = '''OAuth realm="http://www.google.com/",something='''
        assert_raises(ValueError, oauth_parse_authorization_header_value,
                      header_value)

        header_value = '''OAuth realm="http://www.google.com/",something="'''
        assert_raises(ValueError, oauth_parse_authorization_header_value,
                      header_value)

    def test_ValueError_when_missing_quotes_around_value(self):
        header_value = '''OAuth realm="http://www.google.com/",something="something'''
        assert_raises(ValueError, oauth_parse_authorization_header_value,
                      header_value)

        header_value = '''OAuth realm="http://www.google.com/",something=something"'''
        assert_raises(ValueError, oauth_parse_authorization_header_value,
                      header_value)

        header_value = '''OAuth realm="http://www.google.com/",something=something'''
        assert_raises(ValueError, oauth_parse_authorization_header_value,
                      header_value)
