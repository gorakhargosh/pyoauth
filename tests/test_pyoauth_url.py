#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nose.tools import assert_equal, assert_not_equal, assert_dict_equal, assert_false, assert_true, assert_raises
from nose import SkipTest
from pyoauth.url import oauth_unescape, oauth_escape, oauth_parse_qs, oauth_urlencode, oauth_urlencode_sl, oauth_url_query_params_sanitize

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
    # TODO:
    #def test_unicode_input_encoded_to_utf8(self):
    #    assert_equal(oauth_escape(u'åéîøü'.encode('utf16')),
    #                 "%FF%FE%E5%00%E9%00%EE%00%F8%00%FC%00")

    def setUp(self):
        self._unsafe_characters = [" ",
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
                       "å",
                       ]
        self.uni_utf8_bytes = '\xc2\xae'
        self.uni_unicode_object = u'\u00ae'

    def test_utf8_bytestring_left_as_is(self):
        assert_equal(oauth_escape(self.uni_utf8_bytes), "%C2%AE")

    def test_unicode_utf8_encoded(self):
        assert_equal(oauth_escape(self.uni_unicode_object), "%C2%AE")

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

    def test_non_string_values_are_stringified(self):
        assert_equal(oauth_escape(True), "True")
        assert_equal(oauth_escape(5), "5")

    # TODO:
    #def test_bytestrings_are_not_utf_8_encoded(self):
    #    b = b'\x01s\x95\x8e|HL\xe4\x81\x93\x155\x99@\x8b\xe3'


class Test_oauth_unescape(object):
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

    def test_percent_encoded_unicode_input(self):
        assert_equal(oauth_unescape("%FF%FE%E5%00%E9%00%EE%00%F8%00%FC%00"),
                     u'åéîøü'.encode("utf-16"))

    def test_plus_is_treated_as_space_character(self):
        assert_equal(oauth_unescape('+'), ' ', "Plus character in encoding is not treated as space character.")


    # TODO:
    #def test_percent_encode_decode(self):
    #    for char in self._unsafe_characters:
    #        assert_equal(oauth_unescape(oauth_escape(char)), char, "Percent-encode-decode failed for char: %r" % char)


class Test_oauth_urlencode(object):
    def test_valid_query_string(self):
        params = {
            "a2": "r b",
            "b5": "=%3D",
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": "",
            "oauth_consumer_key": "9djdj82h48djs9d2",
            "oauth_token": "kkk9d7dh3k39sjv7",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": ["137131201"],
            "oauth_nonce": "7d8f3e4a",
        }
        valid_query_string = "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        assert_equal(oauth_urlencode(params), valid_query_string)


class Test_oauth_urlencode_sl(object):
    def test_valid_query_params_list(self):
        params = {
            "a2": "r b",
            "b5": "=%3D",
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": "",
            "oauth_consumer_key": "9djdj82h48djs9d2",
            "oauth_token": "kkk9d7dh3k39sjv7",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": ["137131201"],
            "oauth_nonce": "7d8f3e4a",
        }
        valid_params_list = [
            ("a2", "r%20b"),
            ("a3", "2%20q"),
            ("a3", "a"),
            ("b5", "%3D%253D"),
            ("c%40", ""),
            ("c2", ""),
            ("oauth_consumer_key", "9djdj82h48djs9d2"),
            ("oauth_nonce", "7d8f3e4a"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", "137131201"),
            ("oauth_token", "kkk9d7dh3k39sjv7"),
        ]
        assert_equal(oauth_urlencode_sl(params), valid_params_list)


class Test_oauth_url_query_params_add(object):
    def test_adds_query_params_properly(self):
        pass

class Test_oauth_url_query_params_sanitize(object):
    def test_unflattens_dict(self):
        params = {
            "a2": "r b",
            "b5": "=%3D",
            "a3": ["a", "2 q"],
            "c@": "",
            "c2": [""],
            "oauth_consumer_key": "9djdj82h48djs9d2",
            "oauth_token": "kkk9d7dh3k39sjv7",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": ["137131201"],
            "oauth_nonce": "7d8f3e4a",
        }
        expected_params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            "oauth_consumer_key": ["9djdj82h48djs9d2"],
            "oauth_token": ["kkk9d7dh3k39sjv7"],
            "oauth_signature_method": ["HMAC-SHA1"],
            "oauth_timestamp": ["137131201"],
            "oauth_nonce": ["7d8f3e4a"],
        }
        assert_dict_equal(oauth_url_query_params_sanitize(params), expected_params)

    def test_parses_query_string(self):
        query_string = "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        expected_params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            "oauth_consumer_key": ["9djdj82h48djs9d2"],
            "oauth_token": ["kkk9d7dh3k39sjv7"],
            "oauth_signature_method": ["HMAC-SHA1"],
            "oauth_timestamp": ["137131201"],
            "oauth_nonce": ["7d8f3e4a"],
        }
        assert_dict_equal(oauth_url_query_params_sanitize(query_string), expected_params)
