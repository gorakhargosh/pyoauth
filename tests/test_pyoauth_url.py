#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest2

from mom.builtins import to_utf8_if_unicode
from urlparse import urlparse

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
        parse_qs(u1.query, keep_blank_values=True) == parse_qs(u2.query, keep_blank_values=True)


class Test_parse_qs(unittest2.TestCase):
    def test_are_blank_values_preserved(self):
        self.assertDictEqual(parse_qs("a="), {"a": [""]})
        self.assertDictEqual(parse_qs("a"), {"a": [""]})

    def test_are_multiple_values_obtained(self):
        self.assertDictEqual(parse_qs("a=1&a=2&a=3&b=c"),
                {"a": ["1", "2", "3"], "b": ["c"]})

    def test_single_value_lists_are_not_flattened(self):
        d = parse_qs("a=1&a=2&a=3&b=c")
        for n, v in d.items():
            self.assertTrue(isinstance(n, str), "Dictionary key is not a string.")
            self.assertTrue(isinstance(v, list), "Dictionary value is not a list.")

    def test_names_and_values_are_percent_decoded(self):
        qs = 'b5=%3D%253D&a3=a&c%40=&a2=r%20b' + '&' + 'c2&a3=2+q'
        q = parse_qs(qs)
        self.assertDictEqual(q,
                {'a2': ['r b'], 'a3': ['a', '2 q'], 'b5': ['=%3D'], 'c@': [''],
                 'c2': ['']})

    def test_percent_decoding_treats_plus_as_space(self):
        self.assertDictEqual(parse_qs('a=2+q'), {'a': ['2 q']})

    def test_ignores_prefixed_question_mark_character_if_included(self):
        qs = '?b5=%3D%253D&a3=a&c%40=&a2=r%20b' + '&' + 'c2&a3=2+q'
        q = parse_qs(qs)
        self.assertDictEqual(q,
                {'a2': ['r b'], 'a3': ['a', '2 q'], 'b5': ['=%3D'], 'c@': [''],
                 'c2': ['']})


class Test_percent_encode(unittest2.TestCase):
    # TODO:
    #def test_unicode_input_encoded_to_utf8(self):
    #    self.assertEqual(percent_encode(u'åéîøü'.encode('utf16')),
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

    def test_oauth_test_cases(self):
        # http://wiki.oauth.net/w/page/12238556/TestCases
        ex = [
            ('abcABC123', 'abcABC123'),
            ('-._~', '-._~'),
            ('%', '%25'),
            ('+', '%2B'),
            ('&=*', '%26%3D%2A'),
            (u'\u000A', '%0A'),
            (u'\u0020', '%20'),
            (u'\u007F', '%7F'),
            (u'\u0080', '%C2%80'),
            (u'\u3001', '%E3%80%81'),
        ]
        for k, v in ex:
            self.assertEqual(percent_encode(k), v)

    def test_utf8_bytestring_left_as_is(self):
        self.assertEqual(percent_encode(self.uni_utf8_bytes), "%C2%AE")

    def test_unicode_utf8_encoded(self):
        self.assertEqual(percent_encode(self.uni_unicode_object), "%C2%AE")

    def test_safe_symbols_are_not_encoded(self):
        safe_symbols = ["-", ".", "_", "~"]
        for symbol in safe_symbols:
            self.assertEqual(percent_encode(symbol), symbol,
                         "Symbol %s should not be encoded." % (symbol,))

    def test_digits_are_not_encoded(self):
        digits = [str(x) for x in range(10)]
        for digit in digits:
            self.assertEqual(percent_encode(digit), digit,
                         "Digits should not be encoded.")

    def test_alphabets_are_not_encoded(self):
        lowercase_alphabets = [chr(x) for x in range(ord('a'), ord('z') + 1)]
        uppercase_alphabers = [chr(x) for x in range(ord('A'), ord('Z') + 1)]
        alphabets = lowercase_alphabets + uppercase_alphabers
        for alphabet in alphabets:
            self.assertEqual(percent_encode(alphabet), alphabet,
                         "Alphabets should not be encoded.")

    def test_space_is_not_encoded_as_plus(self):
        self.assertNotEqual(percent_encode(" "), "+")
        self.assertEqual(percent_encode(" "), "%20")

    def test_unsafe_characters_are_encoded(self):
        for char in self._unsafe_characters:
            self.assertNotEqual(percent_encode(char), char)

    def test_character_encoding_is_uppercase(self):
        for char in self._unsafe_characters:
            for c in percent_encode(char):
                if c.isalpha():
                    self.assertTrue(c.isupper(), "Percent-encoding is not uppercase: %r for char: %r" % (c, char))

    def test_percent_encoded(self):
        for char in self._unsafe_characters:
            self.assertEqual(percent_encode(char)[0], "%", "Character not percent-encoded.")

    def test_non_string_values_are_stringified(self):
        self.assertEqual(percent_encode(True), "True")
        self.assertEqual(percent_encode(5), "5")


class Test_percent_decode(unittest2.TestCase):
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
        self.assertEqual(percent_decode("%FF%FE%E5%00%E9%00%EE%00%F8%00%FC%00"),
                     u'åéîøü'.encode("utf-16"))

    def test_plus_is_treated_as_space_character(self):
        self.assertEqual(percent_decode('+'), ' ', "Plus character in encoding is not treated as space character.")

    def test_oauth_test_cases(self):
        # http://wiki.oauth.net/w/page/12238556/TestCases
        ex = [
            ('abcABC123', 'abcABC123'),
            ('-._~', '-._~'),
            ('%', '%25'),
            ('+', '%2B'),
            ('&=*', '%26%3D%2A'),
            (u'\u000A', '%0A'),
            (u'\u0020', '%20'),
            (u'\u007F', '%7F'),
            (u'\u0080', '%C2%80'),
            (u'\u3001', '%E3%80%81'),
        ]
        for k, v in ex:
            self.assertEqual(percent_decode(v), to_utf8_if_unicode(k))

class Test_urlencode_s(unittest2.TestCase):
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
        self.assertEqual(urlencode_s(params), valid_query_string)

    def test_do_seq_dicts(self):
        # Behaves like doseq=1
        params = dict(a=dict(a='b'), b="something")
        self.assertEqual(urlencode_s(params), 'a=a&b=something')

    def test_do_seq_removes_blank_lists(self):
        params = dict(a=[], b="something")
        self.assertEqual(urlencode_s(params), "b=something")


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
            ("non_string", "5"),
            ("oauth_consumer_key", "9djdj82h48djs9d2"),
            ("oauth_nonce", "7d8f3e4a"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", "137131201"),
            ("oauth_token", "kkk9d7dh3k39sjv7"),
        ]
        self.assertEqual(urlencode_sl(params), valid_params_list)

    def test_blank_list_value_not_preserved(self):
        params = {
            "blank_list_value_not_preserved": [],
            "oauth_consumer_key": "9djdj82h48djs9d2",
            "oauth_token": "kkk9d7dh3k39sjv7",
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": ["137131201"],
            "oauth_nonce": "7d8f3e4a",
        }
        valid_params_list = [
            ("oauth_consumer_key", "9djdj82h48djs9d2"),
            ("oauth_nonce", "7d8f3e4a"),
            ("oauth_signature_method", "HMAC-SHA1"),
            ("oauth_timestamp", "137131201"),
            ("oauth_token", "kkk9d7dh3k39sjv7"),
        ]
        self.assertEqual(urlencode_sl(params), valid_params_list)



class Test_url_add_query(unittest2.TestCase):
    def test_adds_query_params_properly(self):
        params1 = {
            "a2": "r b",
            "b5": "=%3D",
            "a3": ["a", "2 q"],
            "c2": [""],
            "c@": "",
        }
        url = "HTTP://UserName:PassWORdX@WWW.EXAMPLE.COM:8000/result;param1?oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7&oauth_consumer_key=9djdj82h48djs9d2#fragment"
        resulting_url = "http://UserName:PassWORdX@www.example.com:8000/result;param1?a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7#fragment"
        self.assertEqual(url_add_query(url, params1), resulting_url)

class Test_query_add(unittest2.TestCase):
    def test_adds_query_params_properly(self):
        params1 = {
            "a2": "r b",
            "b5": "=%3D",
            "a3": ["a"],
            "c2": [""],
        }
        params2 = {
            "a3": ["2 q"],
            "c@": "",
        }
        params3 = """oauth_nonce=7d8f3e4a\
&oauth_timestamp=137131201\
&oauth_signature_method=HMAC-SHA1\
&oauth_consumer_key=9djdj82h48djs9d2\
&oauth_token=kkk9d7dh3k39sjv7\
"""
        resulting_query_string = "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        self.assertEqual(urlencode_s(query_add(params1, params2, params3)), resulting_query_string)



class Test_query_append(unittest2.TestCase):
    def test_appends_query_params_properly(self):
        params1 = {
            "a2": "r b",
            "b5": "=%3D",
            "a3": ["a"],
            "c2": [""],
        }
        params2 = {
            "a3": ["2 q"],
            "c@": "",
        }
        params3 = "oauth_nonce=7d8f3e4a"
        resulting_query_string = "a2=r%20b&a3=a&b5=%3D%253D&c2=&a3=2%20q&c%40=&oauth_nonce=7d8f3e4a"
        self.assertEqual(query_append(params1, params2, params3), resulting_query_string)

class Test_urlparse_normalized(unittest2.TestCase):
    def test_valid_parts_and_normalization(self):
        url = "HTTP://UserName:PassWORdX@WWW.EXAMPLE.COM:8000/result;param1?a=&a=1&a=2&oauth_consumer_key=9djdj82h48djs9d2#fragment"
        result = (
            "http",
            "UserName:PassWORdX@www.example.com:8000",
            "/result",
            "param1",
            "a=&a=1&a=2&oauth_consumer_key=9djdj82h48djs9d2",
            "fragment",
        )
        self.assertEqual(urlparse_normalized(url), result)

    def test_path_is_never_empty(self):
        url = "HTTP://UserName:PassWORdX@WWW.EXAMPLE.COM:8000/?a=&a=1&a=2&oauth_consumer_key=9djdj82h48djs9d2#fragment"
        result = (
            "http",
            "UserName:PassWORdX@www.example.com:8000",
            "/",
            "",
            "a=&a=1&a=2&oauth_consumer_key=9djdj82h48djs9d2",
            "fragment",
        )
        self.assertEqual(urlparse_normalized(url), result)

    def test_only_default_ports_are_dropped(self):
        result = (
            "http",
            "social.yahooapis.com",
            "/v1/user/6677/connections",
            "start=0;count=20",
            "",
            "",
        )
        url = "http://social.yahooapis.com:80/v1/user/6677/connections;start=0;count=20"
        self.assertEqual(urlparse_normalized(url), result)

        result = (
            "https",
            "social.yahooapis.com",
            "/v1/user/6677/connections",
            "start=0;count=20",
            "",
            "",
        )
        url = "https://social.yahooapis.com:443/v1/user/6677/connections;start=0;count=20"
        self.assertEqual(urlparse_normalized(url), result)

        result = (
            "http",
            "social.yahooapis.com:8000",
            "/v1/user/6677/connections",
            "start=0;count=20",
            "",
            "",
        )
        url = "http://social.yahooapis.com:8000/v1/user/6677/connections;start=0;count=20"
        self.assertEqual(urlparse_normalized(url), result)

        result = (
            "https",
            "social.yahooapis.com:8000",
            "/v1/user/6677/connections",
            "start=0;count=20",
            "",
            "",
        )
        url = "https://social.yahooapis.com:8000/v1/user/6677/connections;start=0;count=20"
        self.assertEqual(urlparse_normalized(url), result)


    def test_InvalidUrlError_when_url_invalid(self):
        self.assertRaises(InvalidUrlError, urlparse_normalized, None)
        self.assertRaises(InvalidUrlError, urlparse_normalized, "")

    def test_url_with_matrix_params(self):
        result = (
            "http",
            "social.yahooapis.com",
            "/v1/user/6677/connections",
            "start=0;count=20",
            "format=json",
            "fragment",
        )
        url = "http://social.yahooapis.com/v1/user/6677/connections;start=0;count=20?format=json#fragment"
        self.assertEqual(urlparse_normalized(url), result)


class Test_query_unflatten(unittest2.TestCase):
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
        self.assertDictEqual(query_unflatten(params), expected_params)

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
        self.assertEqual(urlencode_s(query_unflatten(query_string)), urlencode_s(expected_params))

    def test_ignores_prefixed_question_mark_character_if_included(self):
        query_string = "?a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
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
        self.assertEqual(urlencode_s(query_unflatten(query_string)), urlencode_s(expected_params))

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
            "oauth_consumer_key": ["9djdj82h48djs9d2"],
            "oauth_token": ["kkk9d7dh3k39sjv7"],
            "oauth_signature_method": ["HMAC-SHA1"],
            "oauth_timestamp": ["137131201"],
            "oauth_nonce": ["7d8f3e4a"],
        }
        query_string = "?a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        expected_params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
        }
        expected_result = urlencode_s(expected_params)

        self.assertEqual(urlencode_s(query_remove_oauth(params)), expected_result)
        self.assertEqual(urlencode_s(query_remove_oauth(query_string)), expected_result)


class Test_url_sanitize(unittest2.TestCase):
    def test_sanitization_force_secure_default_and_removes_fragment(self):
        url = "https://www.EXAMPLE.com/request?a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7#fragment"
        expected_params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
        }
        expected_result = "https://www.example.com/request?" + urlencode_s(expected_params)  # Fragment ignored.
        self.assertEqual(oauth_url_sanitize(url), expected_result)

    def test_sanitization_force_secure(self):
        insecure_url = "http://www.EXAMPLE.com/request"
        secure_url = "https://www.EXAMPLE.com/request"

        self.assertRaises(InsecureOAuthUrlError, oauth_url_sanitize, insecure_url)
        self.assertRaises(InsecureOAuthUrlError, oauth_url_sanitize, insecure_url, True)
        self.assertEqual(oauth_url_sanitize(insecure_url, force_secure=False), "http://www.example.com/request")
        self.assertEqual(oauth_url_sanitize(secure_url, force_secure=False), "https://www.example.com/request")
        self.assertEqual(oauth_url_sanitize(secure_url, force_secure=True), "https://www.example.com/request")


class Test_request_protocol_params_sanitize(unittest2.TestCase):
    def test_filter(self):
        params = {
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
        query_string = "?a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        expected_params = {
            "oauth_consumer_key": ["9djdj82h48djs9d2"],
            "oauth_token": ["kkk9d7dh3k39sjv7"],
            "oauth_signature_method": ["HMAC-SHA1"],
            "oauth_timestamp": ["137131201"],
            "oauth_nonce": ["7d8f3e4a"],
        }
        expected_result = urlencode_s(expected_params)

        self.assertEqual(urlencode_s(request_query_remove_non_oauth(params)), expected_result)
        self.assertEqual(urlencode_s(request_query_remove_non_oauth(query_string)), expected_result)

    def test_raises_InvalidOAuthParametersError_when_multiple_protocol_param_values_found(self):
        params = {
            "a2": ["r b"],
            "b5": ["=%3D"],
            "a3": ["a", "2 q"],
            "c@": [""],
            "c2": [""],
            "oauth_token": ["kkk9d7dh3k39sjv7", "ahdsa7hd3uhadasd"],
        }
        self.assertRaises(InvalidOAuthParametersError, request_query_remove_non_oauth, params)

    def test_raises_InsecureProtocolParametersError_when_confidential_params_found(self):
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
        self.assertRaises(InsecureOAuthParametersError, request_query_remove_non_oauth, params1)
        self.assertRaises(InsecureOAuthParametersError, request_query_remove_non_oauth, params2)

class Test_url_append_query(unittest2.TestCase):
    def test_does_not_prefix_with_ampersand_when_url_has_no_query_params(self):
        url = "https://www.example.com/authorize"
        self.assertEqual(url_append_query(url, dict(a=1)), "https://www.example.com/authorize?a=1")
        self.assertNotEqual(url_append_query(url, dict(a=1)), "https://www.example.com/authorize?&a=1")

    def test_returns_url_unchanged_if_no_query_params(self):
        url = "http://www.example.com/request?a=b"
        self.assertEqual(url_append_query(url, None), url)

    def test_appends_to_url_preserving_fragments_and_does_not_change_append_order(self):
        url = "http://www.example.com/request?b=1#fragment"
        expected_url = "http://www.example.com/request?b=1&a=1#fragment"
        self.assertEqual(url_append_query(url, {"a": 1}), expected_url)
        self.assertEqual(url_append_query(url, "a=1"), expected_url)


class Test_is_valid_callback_url(unittest2.TestCase):
    def test_oob_case_sensitive_is_valid(self):
        self.assertTrue(is_valid_callback_url("oob"))
        self.assertFalse(is_valid_callback_url("OOb"))

    def test_non_string_is_invalid(self):
        self.assertFalse(is_valid_callback_url(5))
        self.assertFalse(is_valid_callback_url(None))
        self.assertFalse(is_valid_callback_url(False))
        self.assertFalse(is_valid_callback_url({}))
        self.assertFalse(is_valid_callback_url([]))
        self.assertFalse(is_valid_callback_url(()))

    def test_url_must_be_absolute(self):
        self.assertTrue(is_valid_callback_url("http://example.com/"))
        self.assertFalse(is_valid_callback_url("mailto:someone@somewhere.com"))
        self.assertFalse(is_valid_callback_url("hxp://example.com/"))
        self.assertFalse(is_valid_callback_url("http://"))


if __name__ == "__main__":
    unittest2.main()

