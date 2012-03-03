#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
# Copyright (C) 2012 Google, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from __future__ import absolute_import
import logging

import unittest2

from mom.builtins import b, is_bytes
from mom.codec.text import utf8_encode_if_unicode, \
    utf8_decode_if_bytes, utf8_encode

from pyoauth._compat import urlparse
from pyoauth.constants import \
    OAUTH_PARAM_TOKEN, OAUTH_PARAM_SIGNATURE_METHOD, \
    OAUTH_PARAM_TIMESTAMP, OAUTH_PARAM_NONCE, OAUTH_PARAM_SIGNATURE, \
    OAUTH_PARAM_TOKEN_SECRET, OAUTH_PARAM_CALLBACK, \
    OAUTH_PARAM_CONSUMER_SECRET, OAUTH_PARAM_VERIFIER, OAUTH_PARAM_VERSION, \
    OAUTH_PARAM_CONSUMER_KEY
from pyoauth.error import InvalidUrlError, \
    InvalidQueryParametersError, \
    InsecureOAuthUrlError, \
    InvalidOAuthParametersError, \
    InsecureOAuthParametersError
from pyoauth.url import \
    percent_decode, \
    percent_encode, \
    parse_qs, \
    urlencode_s, \
    urlencode_sl, \
    query_unflatten, \
    query_add, \
    urlparse_normalized, \
    url_add_query, \
    query_remove_oauth, \
    request_query_remove_non_oauth, \
    oauth_url_sanitize, \
    url_append_query, \
    query_append, \
    is_valid_callback_url

from pyoauth.tests.constants import constants


def _url_equals(url1, url2):
    """
    Compares two URLs and determines whether they are the equal.

    :param url1:
        First URL.
    :param url2:
        Second URL.
    :returns:
        ``True`` if equal; ``False`` otherwise.

    Usage::

        >>> _url_equals("http://www.google.com/a", "http://www.google.com/a")
        True
        >>> _url_equals("https://www.google.com/a", "http://www.google.com/a")
        False
        >>> _url_equals("http://www.google.com/", "http://www.example.com/")
        False
        >>> _url_equals("http://example.com:80/", "http://example.com:8000/")
        False
        >>> _url_equals("http://user@example.com/", "http://user2@example.com.com/")
        False
        >>> _url_equals("http://user@example.com/request?a=b&b=c&b=d#fragment", "http://user@example.com/request?b=c&b=d&a=b#fragment")
        True
        >>> _url_equals("http://user@example.com/request?a=b&b=c&b=d#fragment", "http://user@example.com/request?b=c&b=d&a=b#fragment2")
        False
        >>> _url_equals("http://www.google.com/request?a=b", "http://www.google.com/request?b=c")
        False
    """
    u1 = urlparse(url1)
    u2 = urlparse(url2)
    return u1.scheme == u2.scheme and \
        u1.path == u2.path and \
        u1.params == u2.params and \
        u1.netloc == u2.netloc and \
        u1.fragment == u2.fragment and \
        parse_qs(u1.query, keep_blank_values=True) == \
            parse_qs(u2.query, keep_blank_values=True)


class Test_parse_qs(unittest2.TestCase):
    def test_are_blank_values_preserved(self):
        self.assertDictEqual(parse_qs("a="), {b("a"): [b("")]})
        self.assertDictEqual(parse_qs("a"), {b("a"): [b("")]})

    def test_are_multiple_values_obtained(self):
        self.assertDictEqual(parse_qs("a=1&a=2&a=3&b=c"),
                {b("a"): [b("1"), b("2"), b("3")], b("b"): [b("c")]})

    def test_single_value_lists_are_not_flattened(self):
        d = parse_qs("a=1&a=2&a=3&b=c")
        for n, v in d.items():
            self.assertTrue(is_bytes(n),
                            "Dictionary key is not bytes.")
            self.assertTrue(isinstance(v, list),
                            "Dictionary value is not a list.")

    def test_names_and_values_are_percent_decoded(self):
        qs = 'b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q'
        q = parse_qs(qs)
        self.assertDictEqual(q,
                {b('a2'): [b('r b')],
                 b('a3'): [b('a'), b('2 q')],
                 b('b5'): [b('=%3D')],
                 b('c@'): [b('')],
                 b('c2'): [b('')]})

    def test_percent_decoding_treats_plus_as_space(self):
        self.assertDictEqual(parse_qs('a=2+q'), {b('a'): [b('2 q')]})

    def test_ignores_prefixed_question_mark_character_if_included(self):
        qs = '?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q'
        q = parse_qs(qs)
        self.assertDictEqual(q,
                {b('a2'): [b('r b')],
                 b('a3'): [b('a'), b('2 q')],
                 b('b5'): [b('=%3D')],
                 b('c@'): [b('')],
                 b('c2'): [b('')]})


class Test_percent_encode(unittest2.TestCase):
    # TODO:
    #def test_unicode_input_encoded_to_utf8(self):
    #    self.assertEqual(percent_encode(u'åéîøü'.encode('utf16')),
    #                 "%FF%FE%E5%00%E9%00%EE%00%F8%00%FC%00")

    def setUp(self):
        self._unsafe_characters = [
                       b(" "),
                       b(":"),
                       b("!"),
                       b("@"),
                       b("#"),
                       b("$"),
                       b("%"),
                       b("^"),
                       b("&"),
                       b("*"),
                       b("("),
                       b(")"),
                       b("+"),
                       b("{"),
                       b("}"),
                       b("["),
                       b("]"),
                       b("|"),
                       b("\\"),
                       b(":"),
                       b(";"),
                       b('"'),
                       b("'"),
                       b(","),
                       b("<"),
                       b(">"),
                       b("?"),
                       b("/"),
                       b("`"),
                       b("´"),
                       constants.test_unicode_angstrom,
                       ]
        self.uni_utf8_bytes = constants.test_utf8_bytes
        self.uni_unicode_object = constants.test_unicode_string

    def test_oauth_test_cases(self):
        # http://wiki.oauth.net/w/page/12238556/TestCases
        ex = constants.percent_encode_test_cases
        for k, v in ex:
            self.assertEqual(percent_encode(k), v)

    def test_utf8_bytestring_left_as_is(self):
        self.assertEqual(percent_encode(self.uni_utf8_bytes), b("%C2%AE"))

    def test_unicode_utf8_encoded(self):
        self.assertEqual(percent_encode(self.uni_unicode_object), b("%C2%AE"))

    def test_safe_symbols_are_not_encoded(self):
        safe_symbols = ["-", ".", "_", "~"]
        for symbol in safe_symbols:
            self.assertEqual(percent_encode(symbol), symbol.encode("ascii"),
                         "Symbol %s should not be encoded." % (symbol,))

    def test_digits_are_not_encoded(self):
        digits = [str(x) for x in range(10)]
        for digit in digits:
            self.assertEqual(percent_encode(digit), digit.encode("ascii"),
                         "Digits should not be encoded.")

    def test_alphabets_are_not_encoded(self):
        lowercase_alphabets = [chr(x) for x in range(ord('a'), ord('z') + 1)]
        uppercase_alphabers = [chr(x) for x in range(ord('A'), ord('Z') + 1)]
        alphabets = lowercase_alphabets + uppercase_alphabers
        for alphabet in alphabets:
            self.assertEqual(percent_encode(alphabet), alphabet.encode("ascii"),
                         "Alphabets should not be encoded.")

    def test_space_is_not_encoded_as_plus(self):
        self.assertNotEqual(percent_encode(" "), b("+"))
        self.assertEqual(percent_encode(" "), b("%20"))

    def test_unsafe_characters_are_encoded(self):
        for char in self._unsafe_characters:
            self.assertNotEqual(percent_encode(char), char)

    def test_character_encoding_is_uppercase(self):
        for char in self._unsafe_characters:
            for c in percent_encode(char):
                if isinstance(c, int):
                    c = chr(c)
                if c.isalpha():
                    self.assertTrue(
                        c.isupper(),
                        "Percent-encoding is not uppercase: %r for char: %r" \
                        % (c, char))

    def test_percent_encoded(self):
        for char in self._unsafe_characters:
            self.assertEqual(
                percent_encode(char)[0], b("%")[0],
                "Character not percent-encoded.")

    def test_non_string_values_are_stringified(self):
        self.assertEqual(percent_encode(True), b("True"))
        self.assertEqual(percent_encode(5), b("5"))


class Test_percent_decode(unittest2.TestCase):
    _unsafe_characters = [
                       b(" "),
                       b(":"),
                       b("!"),
                       b("@"),
                       b("#"),
                       b("$"),
                       b("%"),
                       b("^"),
                       b("&"),
                       b("*"),
                       b("("),
                       b(")"),
                       b("+"),
                       b("{"),
                       b("}"),
                       b("["),
                       b("]"),
                       b("|"),
                       b("\\"),
                       b(":"),
                       b(";"),
                       b('"'),
                       b("'"),
                       b(","),
                       b("<"),
                       b(">"),
                       b("?"),
                       b("/"),
                       b("`"),
                       b("´"),
                       constants.test_unicode_angstrom,
                       ]

#    def test_percent_encoded_unicode_input(self):
#        self.assertEqual(percent_decode(b("%FF%FE%E5%00%E9%00%EE%00%F8%00%FC%00")),
#                     constants.test_unicode_aeiou.encode("utf-16"))

    def test_plus_is_treated_as_space_character(self):
        self.assertEqual(
            percent_decode(b('+')), " ",
            "Plus character in encoding is not treated as space character.")

    def test_oauth_test_cases(self):
        # http://wiki.oauth.net/w/page/12238556/TestCases
        ex = constants.percent_decode_test_cases
        for decoded, encoded in ex:
            self.assertEqual(percent_decode(encoded), decoded)

            
class Test_urlencode_s(unittest2.TestCase):
    def test_valid_query_string(self):
        params = {
            "a2": "r b",
            "b5": "=%3D",
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": "",
            OAUTH_PARAM_CONSUMER_KEY: "9djdj82h48djs9d2",
            OAUTH_PARAM_TOKEN: "kkk9d7dh3k39sjv7",
            OAUTH_PARAM_SIGNATURE_METHOD: "HMAC-SHA1",
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: "7d8f3e4a",
        }
        valid_query_string = b("""\
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
        self.assertEqual(urlencode_s(params), valid_query_string)

    def test_do_seq_dicts(self):
        # Behaves like doseq=1
        params = dict(a=dict(a='b'), c="something")
        self.assertEqual(urlencode_s(params), b('a=a&c=something'))

    def test_do_seq_removes_blank_lists(self):
        params = dict(a=[], c="something")
        self.assertEqual(urlencode_s(params), b("c=something"))


class Test_urlencode_sl(unittest2.TestCase):
    def test_valid_query_params_list(self):
        params = {
            "a2": "r b",
            "b5": "=%3D",
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": "",
            "non_string": 5,
            "blank_list_value_not_preserved": [],
            OAUTH_PARAM_CONSUMER_KEY: "9djdj82h48djs9d2",
            OAUTH_PARAM_TOKEN: "kkk9d7dh3k39sjv7",
            OAUTH_PARAM_SIGNATURE_METHOD: "HMAC-SHA1",
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: "7d8f3e4a",
        }
        valid_params_list = [
            (b("a2"), b("r%20b")),
            (b("a3"), b("2%20q")),
            (b("a3"), b("a")),
            (b("b5"), b("%3D%253D")),
            (b("c%40"), b("")),
            (b("c2"), b("")),
            (b("non_string"), b("5")),
            (utf8_encode(OAUTH_PARAM_CONSUMER_KEY), b("9djdj82h48djs9d2")),
            (utf8_encode(OAUTH_PARAM_NONCE), b("7d8f3e4a")),
            (utf8_encode(OAUTH_PARAM_SIGNATURE_METHOD), b("HMAC-SHA1")),
            (utf8_encode(OAUTH_PARAM_TIMESTAMP), b("137131201")),
            (utf8_encode(OAUTH_PARAM_TOKEN), b("kkk9d7dh3k39sjv7")),
        ]
        self.assertEqual(urlencode_sl(params), valid_params_list)

    def test_blank_list_value_not_preserved(self):
        params = {
            "blank_list_value_not_preserved": [],
            OAUTH_PARAM_CONSUMER_KEY: "9djdj82h48djs9d2",
            OAUTH_PARAM_TOKEN: "kkk9d7dh3k39sjv7",
            OAUTH_PARAM_SIGNATURE_METHOD: "HMAC-SHA1",
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: "7d8f3e4a",
        }
        valid_params_list = [
            (utf8_encode(OAUTH_PARAM_CONSUMER_KEY), b("9djdj82h48djs9d2")),
            (utf8_encode(OAUTH_PARAM_NONCE), b("7d8f3e4a")),
            (utf8_encode(OAUTH_PARAM_SIGNATURE_METHOD), b("HMAC-SHA1")),
            (utf8_encode(OAUTH_PARAM_TIMESTAMP), b("137131201")),
            (utf8_encode(OAUTH_PARAM_TOKEN), b("kkk9d7dh3k39sjv7")),
        ]
        self.assertEqual(urlencode_sl(params), valid_params_list)



class Test_url_add_query(unittest2.TestCase):
    def test_adds_query_params_properly(self):
        params1 = {
            b("a2"): b("r b"),
            b("b5"): b("=%3D"),
            b("a3"): [b("a"), b("2 q")],
            b("c2"): [b("")],
            b("c@"): b(""),
        }
        url = b("""HTTP://UserName:PassWORdX@WWW.EXAMPLE.COM:8000/result\
;param1?oauth_nonce=7d8f3e4a\
&oauth_signature_method=HMAC-SHA1\
&oauth_timestamp=137131201\
&oauth_token=kkk9d7dh3k39sjv7\
&oauth_consumer_key=9djdj82h48djs9d2\
#fragment""")
        resulting_url = b("""\
http://UserName:PassWORdX@www.example.com:8000/result\
;param1?\
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
&oauth_token=kkk9d7dh3k39sjv7\
#fragment""")
        self.assertEqual(url_add_query(url, params1), resulting_url)

class Test_query_add(unittest2.TestCase):
    def test_adds_query_params_properly(self):
        params1 = {
            b("a2"): b("r b"),
            b("b5"): b("=%3D"),
            b("a3"): [b("a")],
            b("c2"): [b("")],
        }
        params2 = {
            b("a3"): [b("2 q")],
            b("c@"): b(""),
        }
        params3 = b("""oauth_nonce=7d8f3e4a\
&oauth_timestamp=137131201\
&oauth_signature_method=HMAC-SHA1\
&oauth_consumer_key=9djdj82h48djs9d2\
&oauth_token=kkk9d7dh3k39sjv7\
""")
        resulting_query_string = b("""\
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
        self.assertEqual(urlencode_s(query_add(params1, params2, params3)),
                         resulting_query_string)



class Test_query_append(unittest2.TestCase):
    def test_appends_query_params_properly(self):
        params1 = {
            b("a2"): b("r b"),
            b("b5"): b("=%3D"),
            b("a3"): [b("a")],
            b("c2"): [b("")],
        }
        params2 = {
            b("a3"): [b("2 q")],
            b("c@"): b(""),
        }
        params3 = b("oauth_nonce=7d8f3e4a")
        resulting_query_string = b("""\
a2=r%20b\
&a3=a\
&b5=%3D%253D\
&c2=\
&a3=2%20q\
&c%40=\
&oauth_nonce=7d8f3e4a""")
        self.assertEqual(query_append(params1, params2, params3),
                         resulting_query_string)

class Test_urlparse_normalized(unittest2.TestCase):
    def test_valid_parts_and_normalization(self):
        url = b("""HTTP://UserName:PassWORdX@WWW.EXAMPLE.COM:8000/result\
;param1?a=&a=1&a=2&oauth_consumer_key=9djdj82h48djs9d2#fragment""")
        result = (
            b("http"),
            b("UserName:PassWORdX@www.example.com:8000"),
            b("/result"),
            b("param1"),
            b("a=&a=1&a=2&oauth_consumer_key=9djdj82h48djs9d2"),
            b("fragment"),
        )
        self.assertEqual(urlparse_normalized(url), result)

    def test_path_is_never_empty(self):
        url = b("""HTTP://UserName:PassWORdX@WWW.EXAMPLE.COM:8000/\
?a=&a=1&a=2&oauth_consumer_key=9djdj82h48djs9d2#fragment""")
        result = (
            b("http"),
            b("UserName:PassWORdX@www.example.com:8000"),
            b("/"),
            b(""),
            b("a=&a=1&a=2&oauth_consumer_key=9djdj82h48djs9d2"),
            b("fragment"),
        )
        self.assertEqual(urlparse_normalized(url), result)

    def test_only_default_ports_are_dropped(self):
        result = (
            b("http"),
            b("social.yahooapis.com"),
            b("/v1/user/6677/connections"),
            b("start=0;count=20"),
            b(""),
            b(""),
        )
        url = b("""http://social.yahooapis.com:80/v1/user/6677/connections\
;start=0;count=20""")
        self.assertEqual(urlparse_normalized(url), result)

        result = (
            b("https"),
            b("social.yahooapis.com"),
            b("/v1/user/6677/connections"),
            b("start=0;count=20"),
            b(""),
            b(""),
        )
        url = b("""https://social.yahooapis.com:443/v1/user/6677/connections\
;start=0;count=20""")
        self.assertEqual(urlparse_normalized(url), result)

        result = (
            b("http"),
            b("social.yahooapis.com:8000"),
            b("/v1/user/6677/connections"),
            b("start=0;count=20"),
            b(""),
            b(""),
        )
        url = b("""http://social.yahooapis.com:8000/v1/user/6677/connections\
;start=0;count=20""")
        self.assertEqual(urlparse_normalized(url), result)

        result = (
            b("https"),
            b("social.yahooapis.com:8000"),
            b("/v1/user/6677/connections"),
            b("start=0;count=20"),
            b(""),
            b(""),
        )
        url = b("""https://social.yahooapis.com:8000/v1/user/6677/connections\
;start=0;count=20""")
        self.assertEqual(urlparse_normalized(url), result)


    def test_InvalidUrlError_when_url_invalid(self):
        self.assertRaises(InvalidUrlError, urlparse_normalized, None)
        self.assertRaises(InvalidUrlError, urlparse_normalized, "")

    def test_url_with_matrix_params(self):
        result = (
            b("http"),
            b("social.yahooapis.com"),
            b("/v1/user/6677/connections"),
            b("start=0;count=20"),
            b("format=json"),
            b("fragment"),
        )
        url = b("""http://social.yahooapis.com:80/v1/user/6677/connections\
;start=0;count=20?format=json#fragment""")
        self.assertEqual(urlparse_normalized(url), result)


class Test_query_unflatten(unittest2.TestCase):
    def test_unflattens_dict(self):
        params = {
            b("a2"): b("r b"),
            b("b5"): b("=%3D"),
            b("a3"): [b("a"), b("2 q")],
            b("c@"): b(""),
            b("c2"): [b("")],
            OAUTH_PARAM_CONSUMER_KEY: "9djdj82h48djs9d2",
            OAUTH_PARAM_TOKEN: "kkk9d7dh3k39sjv7",
            OAUTH_PARAM_SIGNATURE_METHOD: "HMAC-SHA1",
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: "7d8f3e4a",
        }
        expected_params = {
            b("a2"): [b("r b")],
            b("b5"): [b("=%3D")],
            b("a3"): [b("a"), b("2 q")],
            b("c@"): [b("")],
            b("c2"): [b("")],
            OAUTH_PARAM_CONSUMER_KEY: ["9djdj82h48djs9d2"],
            OAUTH_PARAM_TOKEN: ["kkk9d7dh3k39sjv7"],
            OAUTH_PARAM_SIGNATURE_METHOD: ["HMAC-SHA1"],
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: ["7d8f3e4a"],
        }
        self.assertDictEqual(query_unflatten(params), expected_params)

    def test_parses_query_string(self):
        query_string = """\
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
&oauth_token=kkk9d7dh3k39sjv7"""
        expected_params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            OAUTH_PARAM_CONSUMER_KEY: ["9djdj82h48djs9d2"],
            OAUTH_PARAM_TOKEN: ["kkk9d7dh3k39sjv7"],
            OAUTH_PARAM_SIGNATURE_METHOD: ["HMAC-SHA1"],
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: ["7d8f3e4a"],
        }
        self.assertEqual(urlencode_s(query_unflatten(query_string)),
                         urlencode_s(expected_params))

    def test_ignores_prefixed_question_mark_character_if_included(self):
        query_string = """\
?a2=r%20b\
&a3=2%20q\
&a3=a\
&b5=%3D%253D\
&c%40=\
&c2=\
&oauth_consumer_key=9djdj82h48djs9d2\
&oauth_nonce=7d8f3e4a\
&oauth_signature_method=HMAC-SHA1\
&oauth_timestamp=137131201\
&oauth_token=kkk9d7dh3k39sjv7"""
        expected_params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            OAUTH_PARAM_CONSUMER_KEY: ["9djdj82h48djs9d2"],
            OAUTH_PARAM_TOKEN: ["kkk9d7dh3k39sjv7"],
            OAUTH_PARAM_SIGNATURE_METHOD: ["HMAC-SHA1"],
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: ["7d8f3e4a"],
        }
        self.assertEqual(urlencode_s(query_unflatten(query_string)),
                         urlencode_s(expected_params))

    def test_returns_empty_dict_when_argument_None(self):
        self.assertEqual(query_unflatten(None), {})

    def test_InvalidQueryParametersError_when_invalid_query_params_value(self):
        self.assertRaises(InvalidQueryParametersError, query_unflatten, True)
        self.assertRaises(InvalidQueryParametersError, query_unflatten, 5)


class Test_query_params_sanitize(unittest2.TestCase):
    def test_filter(self):
        params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            OAUTH_PARAM_CONSUMER_KEY: ["9djdj82h48djs9d2"],
            OAUTH_PARAM_TOKEN: ["kkk9d7dh3k39sjv7"],
            OAUTH_PARAM_SIGNATURE_METHOD: ["HMAC-SHA1"],
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: ["7d8f3e4a"],
        }
        query_string = """\
?a2=r%20b\
&a3=2%20q\
&a3=a\
&b5=%3D%253D\
&c%40=\
&c2=\
&oauth_consumer_key=9djdj82h48djs9d2\
&oauth_nonce=7d8f3e4a\
&oauth_signature_method=HMAC-SHA1\
&oauth_timestamp=137131201\
&oauth_token=kkk9d7dh3k39sjv7"""
        expected_params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
        }
        expected_result = urlencode_s(expected_params)

        self.assertEqual(urlencode_s(query_remove_oauth(params)),
                         expected_result)
        self.assertEqual(urlencode_s(query_remove_oauth(query_string)),
                         expected_result)


class Test_url_sanitize(unittest2.TestCase):
    def test_sanitization_force_secure_default_and_removes_fragment(self):
        url = b("""https://www.EXAMPLE.com/request?\
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
&oauth_token=kkk9d7dh3k39sjv7#fragment""")
        expected_params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
        }
        expected_result = b("https://www.example.com/request?") + \
                        urlencode_s(expected_params)  # Fragment ignored.
        self.assertEqual(oauth_url_sanitize(url), expected_result)

    def test_sanitization_force_secure(self):
        insecure_url = b("http://www.EXAMPLE.com/request")
        secure_url = b("https://www.EXAMPLE.com/request")

        self.assertRaises(InsecureOAuthUrlError,
                          oauth_url_sanitize, insecure_url)
        self.assertRaises(InsecureOAuthUrlError,
                          oauth_url_sanitize, insecure_url, True)
        self.assertEqual(
            oauth_url_sanitize(insecure_url, force_secure=False),
            b("http://www.example.com/request"))
        self.assertEqual(
            oauth_url_sanitize(secure_url, force_secure=False),
            b("https://www.example.com/request"))
        self.assertEqual(
            oauth_url_sanitize(secure_url, force_secure=True),
            b("https://www.example.com/request"))


class Test_request_protocol_params_sanitize(unittest2.TestCase):
    def test_filter(self):
        params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            OAUTH_PARAM_CONSUMER_KEY: ["9djdj82h48djs9d2"],
            OAUTH_PARAM_TOKEN: ["kkk9d7dh3k39sjv7"],
            OAUTH_PARAM_SIGNATURE_METHOD: ["HMAC-SHA1"],
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: ["7d8f3e4a"],
        }
        query_string = """\
?a2=r%20b\
&a3=2%20q\
&a3=a\
&b5=%3D%253D\
&c%40=\
&c2=\
&oauth_consumer_key=9djdj82h48djs9d2\
&oauth_nonce=7d8f3e4a\
&oauth_signature_method=HMAC-SHA1\
&oauth_timestamp=137131201\
&oauth_token=kkk9d7dh3k39sjv7"""
        expected_params = {
            OAUTH_PARAM_CONSUMER_KEY: ["9djdj82h48djs9d2"],
            OAUTH_PARAM_TOKEN: ["kkk9d7dh3k39sjv7"],
            OAUTH_PARAM_SIGNATURE_METHOD: ["HMAC-SHA1"],
            OAUTH_PARAM_TIMESTAMP: ["137131201"],
            OAUTH_PARAM_NONCE: ["7d8f3e4a"],
        }
        expected_result = urlencode_s(expected_params)

        self.assertEqual(urlencode_s(request_query_remove_non_oauth(params)),
                         expected_result)
        self.assertEqual(
            urlencode_s(request_query_remove_non_oauth(query_string)),
            expected_result)

    def test_InvalidOAuthParametersError_got_multiple_oauth_param_values(self):
        params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            OAUTH_PARAM_TOKEN: ["kkk9d7dh3k39sjv7", "ahdsa7hd3uhadasd"],
        }
        self.assertRaises(InvalidOAuthParametersError,
                          request_query_remove_non_oauth, params)

    def test_InsecureProtocolParametersError_got_confidential_params(self):
        params1 = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            "oauth_consumer_secret": ["something"]
        }
        params2 = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            "oauth_token_secret": ["something"]
        }
        self.assertRaises(InsecureOAuthParametersError,
                          request_query_remove_non_oauth, params1)
        self.assertRaises(InsecureOAuthParametersError,
                          request_query_remove_non_oauth, params2)

class Test_url_append_query(unittest2.TestCase):
    def test_does_not_prefix_with_ampersand_when_url_has_no_query_params(self):
        url = b("https://www.example.com/authorize")
        self.assertEqual(url_append_query(url, dict(a=1)),
                         b("https://www.example.com/authorize?a=1"))
        self.assertNotEqual(url_append_query(url, dict(a=1)),
                            b("https://www.example.com/authorize?&a=1"))

    def test_returns_url_unchanged_if_no_query_params(self):
        url = b("http://www.example.com/request?a=b")
        self.assertEqual(url_append_query(url, None), url)

    def test_append_to_url_preserving_fragment_doesnt_change_order(self):
        url = b("http://www.example.com/request?b=1#fragment")
        expected_url = b("http://www.example.com/request?b=1&a=1#fragment")
        self.assertEqual(url_append_query(url, {"a": 1}), expected_url)
        self.assertEqual(url_append_query(url, "a=1"), expected_url)


class Test_is_valid_callback_url(unittest2.TestCase):
    def test_oob_case_sensitive_is_valid(self):
        self.assertTrue(is_valid_callback_url(b("oob")))
        self.assertFalse(is_valid_callback_url(b("OOb")))

    def test_non_string_is_invalid(self):
        self.assertFalse(is_valid_callback_url(5))
        self.assertFalse(is_valid_callback_url(None))
        self.assertFalse(is_valid_callback_url(False))
        self.assertFalse(is_valid_callback_url({}))
        self.assertFalse(is_valid_callback_url([]))
        self.assertFalse(is_valid_callback_url(()))

    def test_url_must_be_absolute(self):
        self.assertTrue(is_valid_callback_url(b("http://example.com/")))
        self.assertFalse(is_valid_callback_url(b("mailto:someone@somewhere.com")))
        self.assertFalse(is_valid_callback_url(b("hxp://example.com/")))
        self.assertFalse(is_valid_callback_url(b("http://")))


if __name__ == "__main__":
    unittest2.main()

