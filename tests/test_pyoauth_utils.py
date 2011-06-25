# -*- coding: utf-8 -*-

from nose.tools import assert_equal, assert_not_equal, assert_dict_equal, assert_false, assert_true, assert_raises
from nose import SkipTest
from pyoauth.utils import oauth_parse_authorization_header_value, oauth_parse_query_string, oauth_get_normalized_query_string, oauth_get_normalized_authorization_header_value, oauth_escape, oauth_unescape, oauth_generate_nonce, oauth_generate_verification_code, oauth_generate_timestamp, oauth_get_hmac_sha1_signature, oauth_get_rsa_sha1_signature, oauth_check_rsa_sha1_signature, oauth_get_plaintext_signature, oauth_get_signature_base_string

class Test_oauth_generate_nonce(object):
    def test_uniqueness(self):
        assert_not_equal(oauth_generate_nonce(), oauth_generate_nonce(),
                         "Nonce is not unique.")

    def test_length(self):
        default_length = 31
        assert_equal(len(oauth_generate_nonce()), default_length,
                     "Nonce length does not match default expected length of %d." % default_length)
        assert_equal(len(oauth_generate_nonce(length=10)), 10,
                     "Nonce length does not match expected length.")

    def test_is_string(self):
        assert_true(isinstance(oauth_generate_nonce(), str),
                    "Nonce is not a bytestring.")


class Test_oauth_generate_verification_code(object):
    def test_length(self):
        default_length = 8
        assert_equal(len(oauth_generate_verification_code()), default_length,
                     "Verification code length does not match default expected length of %d." % default_length)
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
        assert_dict_equal(oauth_parse_query_string("a="), {"a": [""]})
        assert_dict_equal(oauth_parse_query_string("a"), {"a": [""]})

    def test_are_multiple_values_obtained(self):
        assert_dict_equal(oauth_parse_query_string("a=1&a=2&a=3&b=c"),
                {"a": ["1", "2", "3"], "b": ["c"]})

    def test_single_value_lists_are_not_flattened(self):
        d = oauth_parse_query_string("a=1&a=2&a=3&b=c")
        for n, v in d.iteritems():
            assert_true(isinstance(n, str), "Dictionary key is not a string.")
            assert_true(isinstance(v, list), "Dictionary value is not a list.")

    def test_names_and_values_are_percent_decoded(self):
        qs = 'b5=%3D%253D&a3=a&c%40=&a2=r%20b' + '&' + 'c2&a3=2+q'
        q = oauth_parse_query_string(qs)
        assert_dict_equal(q,
                {'a2': ['r b'], 'a3': ['a', '2 q'], 'b5': ['=%3D'], 'c@': [''],
                 'c2': ['']})

    def test_percent_decoding_treats_plus_as_space(self):
        assert_dict_equal(oauth_parse_query_string('a=2+q'), {'a': ['2 q']})


class Test_oauth_escape(object):
    # TODO:
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


class Test_oauth_get_hmac_sha1_signature(object):

    _EXAMPLES = {
        # Example 1.2 in the RFC.
        'ex1.2': dict(
            OAUTH_CONSUMER_KEY="dpf43f3p2l4k3l03",
            OAUTH_CONSUMER_SECRET="kd94hf93k423kf44",

            OAUTH_SIGNATURE_METHOD="HMAC-SHA1",

            REQUEST_TOKEN_REALM="Photos",
            REQUEST_TOKEN_METHOD="POST",
            REQUEST_TOKEN_URL="https://photos.example.net/initiate",
            REQUEST_TOKEN_OAUTH_TIMESTAMP="137131200",
            REQUEST_TOKEN_OAUTH_NONCE="wIjqoS",
            REQUEST_TOKEN_OAUTH_SIGNATURE="74KNZJeDHnMBp0EMJ9ZHt/XKycU=",
            REQUEST_TOKEN_OAUTH_CALLBACK="http://printer.example.com/ready",
        )
    }
    def test_valid_signature(self):
        ex = self._EXAMPLES['ex1.2']
        expected_oauth_signature=ex['REQUEST_TOKEN_OAUTH_SIGNATURE']
        oauth_params = dict(
                realm=ex["REQUEST_TOKEN_REALM"],
                oauth_consumer_key=ex["OAUTH_CONSUMER_KEY"],
                oauth_signature_method=ex["OAUTH_SIGNATURE_METHOD"],
                oauth_timestamp=ex["REQUEST_TOKEN_OAUTH_TIMESTAMP"],
                oauth_nonce=ex["REQUEST_TOKEN_OAUTH_NONCE"],
                oauth_callback=ex["REQUEST_TOKEN_OAUTH_CALLBACK"],
                oauth_signature=ex["REQUEST_TOKEN_OAUTH_SIGNATURE"],
            )
        assert_equal(oauth_get_hmac_sha1_signature(
            consumer_secret=ex["OAUTH_CONSUMER_SECRET"],
            method=ex["REQUEST_TOKEN_METHOD"],
            url=ex["REQUEST_TOKEN_URL"],
            oauth_params=oauth_params,
            token_secret=None),
            expected_oauth_signature
        )

    # TODO: Move these to the query string function.
    def test_signature_and_realm_are_ignored_from_query_params(self):
        ex = self._EXAMPLES['ex1.2']
        oauth_params_without_realm_and_signature = dict(
                oauth_consumer_key=ex["OAUTH_CONSUMER_KEY"],
                oauth_signature_method=ex["OAUTH_SIGNATURE_METHOD"],
                oauth_timestamp=ex["REQUEST_TOKEN_OAUTH_TIMESTAMP"],
                oauth_nonce=ex["REQUEST_TOKEN_OAUTH_NONCE"],
                oauth_callback=ex["REQUEST_TOKEN_OAUTH_CALLBACK"],
            )
        oauth_params = dict(
            realm=ex["REQUEST_TOKEN_REALM"],
            oauth_signature=ex["REQUEST_TOKEN_OAUTH_SIGNATURE"],
        )
        oauth_params.update(oauth_params_without_realm_and_signature)

        consumer_secret = ex["OAUTH_CONSUMER_SECRET"]
        method = ex["REQUEST_TOKEN_METHOD"]
        url = ex["REQUEST_TOKEN_URL"]
        token_secret = None
        assert_equal(oauth_get_hmac_sha1_signature(
            consumer_secret=consumer_secret,
            method=method,
            url=url,
            oauth_params=oauth_params,
            token_secret=token_secret
        ), oauth_get_hmac_sha1_signature(
            consumer_secret=consumer_secret,
            method=method,
            url=url,
            oauth_params=oauth_params_without_realm_and_signature,
            token_secret=token_secret
        ))

    # TODO: Move these to the query string function.
    def test_signature_and_realm_are_ignored_from_url_query_params(self):
        ex = self._EXAMPLES['ex1.2']
        oauth_params_without_realm_and_signature = dict(
                oauth_consumer_key=ex["OAUTH_CONSUMER_KEY"],
                oauth_signature_method=ex["OAUTH_SIGNATURE_METHOD"],
                oauth_timestamp=ex["REQUEST_TOKEN_OAUTH_TIMESTAMP"],
                oauth_nonce=ex["REQUEST_TOKEN_OAUTH_NONCE"],
                oauth_callback=ex["REQUEST_TOKEN_OAUTH_CALLBACK"],
            )

        consumer_secret = ex["OAUTH_CONSUMER_SECRET"]
        method = ex["REQUEST_TOKEN_METHOD"]
        url = ex["REQUEST_TOKEN_URL"] + "?oauth_signature=something&realm=whatever"
        token_secret = None
        sig = oauth_get_hmac_sha1_signature(
            consumer_secret=consumer_secret,
            method=method,
            url=url,
            oauth_params=oauth_params_without_realm_and_signature,
            token_secret=token_secret
        )
        assert_equal(sig, ex["REQUEST_TOKEN_OAUTH_SIGNATURE"])


class Test_oauth_get_and_check_rsa_sha1_signature(object):
    # Taken from https://github.com/rick446/python-oauth2/commit/a8bee2ad1a993faa1e13a04f14f1754489ad35bd
    def setUp(self):
        from Crypto.PublicKey import RSA

        self.RSA = RSA
        self.oauth_signature_method = "RSA-SHA1"
        self.oauth_token_key = "tok-test-key"
        self.oauth_token_secret = "tok-test-secret"
        self.oauth_consumer_key = "con-test-key"
        self.oauth_consumer_secret = '''-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAM7B+5TJsc93ymBSFtC5DE1qDlqvwio0xDfS6bZQTfFiHLm8pHXg
Atkm7QB6gvyRKm+a/G3qEbmBdz21Fw0RLJsCAwEAAQJAS68qnr5uPlnFVRj3jRQP
8s6dzoiD9Ns38I9eSgR/Y5ozl8r/cClLeGWvDKfXvrxlsaMuqWLZ5KMtamaRS9Fl
sQIhAPmOY+s5ZxsYtem+Uc2IUGexNoP/Ng7MPS3C+Q3L6K4nAiEA1Biv6i7TqAbx
oHulPIXb2Z9JmO46aT81n9WnD1qyim0CIF9eN/cLf8iOH+7MqYxHHJsT0QaOgEUV
bgfP68eG9kufAiEAtUSAHGp29HUyzxC9sNNKiVysnuqDu22NXBRSmjnOu6UCIEFZ
nqb0GVzfF6wbsf40mkp1kdHq/fNiFRrLYWWJSpGY
-----END RSA PRIVATE KEY-----'''
        self.http_method = "GET"
        self.url = "http://sp.example.com/"
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
        self.oauth_signature = "D2rdx9TiFajZbXChqMca6eaal8FxZhLMU1bdNX0glIN+BT4nrYGJqmIW92kWZYEYKHsVz7e67oDBEYlIIQMKWg=="

    def test_get_signature(self):
        # consumer_secret is a string.
        assert_equal(oauth_get_rsa_sha1_signature(
            consumer_secret=self.oauth_consumer_secret,
            method=self.http_method,
            url=self.url,
            oauth_params=self.oauth_params,
            token_secret=self.oauth_token_secret
        ), self.oauth_signature)

        # consumer_secret is an RSA instance.
        assert_equal(oauth_get_rsa_sha1_signature(
            consumer_secret=self.RSA.importKey(self.oauth_consumer_secret),
            method=self.http_method,
            url=self.url,
            oauth_params=self.oauth_params,
            token_secret=self.oauth_token_secret
        ), self.oauth_signature)


    def test_check_signature(self):
        # consumer_secret is a string.
        assert_true(oauth_check_rsa_sha1_signature(
            signature=self.oauth_signature,
            consumer_secret=self.oauth_consumer_secret,
            method=self.http_method,
            url=self.url,
            oauth_params=self.oauth_params,
            token_secret=self.oauth_token_secret
        ))

        # consumer_secret is an RSA instance.
        assert_true(oauth_check_rsa_sha1_signature(
            signature=self.oauth_signature,
            consumer_secret=self.RSA.importKey(self.oauth_consumer_secret),
            method=self.http_method,
            url=self.url,
            oauth_params=self.oauth_params,
            token_secret=self.oauth_token_secret
        ))


class Test_oauth_get_plaintext_signature(object):
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
        assert_equal(oauth_get_plaintext_signature(
            consumer_secret=self.oauth_consumer_secret,
            method="POST",
            url="http://example.com/",
            oauth_params=self.oauth_params,
            token_secret=self.oauth_token_secret,
        ), "consumer%20test%20secret&token%20test%20secret")

    def test_when_consumer_secret_present(self):
        assert_equal(oauth_get_plaintext_signature(
            consumer_secret=self.oauth_consumer_secret,
            method="POST",
            url="http://example.com/",
            oauth_params=self.oauth_params,
            token_secret=None
        ), "consumer%20test%20secret&")

    def test_when_token_secret_present(self):
        assert_equal(oauth_get_plaintext_signature(
            consumer_secret="",
            method="POST",
            url="http://example.com/",
            oauth_params=self.oauth_params,
            token_secret=self.oauth_token_secret
        ), "&token%20test%20secret")

    def test_when_neither_secret_present(self):
        assert_equal(oauth_get_plaintext_signature(
            consumer_secret="",
            method="POST",
            url="http://example.com/",
            oauth_params=self.oauth_params,
            token_secret=None
        ), "&")


class Test_oauth_get_signature_base_string(object):
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
        base_string = oauth_get_signature_base_string( "POST",
                "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b&c2&a3=2+q",
                self.oauth_params)
        assert_equal(base_string, "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk9d7dh3k39sjv7")

    def test_ValueError_when_invalid_http_method(self):
        assert_raises(ValueError, oauth_get_signature_base_string, "TypO", "http://example.com/request", {})

    def test_ValueError_when_url_blank_or_None(self):
        assert_raises(ValueError, oauth_get_signature_base_string, "POST", "", {})

    def test_ValueError_when_query_params_is_not_dict(self):
        assert_raises(ValueError, oauth_get_signature_base_string, "POST", "http://www.google.com/", None)

    def test_base_string_does_not_contain_realm_or_oauth_signature(self):
        # Ensure both are present in the query params as well as the URL.
        args = {
            "realm": "http://example.com",
        }
        args.update(self.oauth_params)
        url = "http://example.com/request?oauth_signature=foobar&realm=something"
        base_string = oauth_get_signature_base_string("POST", url, args)
        assert_true("realm=" not in base_string)
        assert_true("oauth_signature=" not in base_string)


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
