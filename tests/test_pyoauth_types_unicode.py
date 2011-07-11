#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nose.tools import assert_equal, assert_false, assert_true, assert_raises
from nose import SkipTest
from mom.builtins import \
    to_utf8_if_unicode, to_unicode_if_bytes, bytes_to_unicode, unicode_to_utf8
from mom.security.random import generate_random_bytes

random_bytes = generate_random_bytes(100)
utf8_bytes = '\xc2\xae'
unicode_string = u'\u00ae'


class Test_to_utf8_if_unicode(object):
    def test_valid(self):
        assert_equal(to_utf8_if_unicode(unicode_string), utf8_bytes)
        assert_equal(to_utf8_if_unicode(utf8_bytes), utf8_bytes)
        assert_equal(to_utf8_if_unicode(None), None)
        assert_equal(to_utf8_if_unicode(False), False)
        assert_equal(to_utf8_if_unicode(5), 5)
        assert_equal(to_utf8_if_unicode([]), [])
        assert_equal(to_utf8_if_unicode(()), ())
        assert_equal(to_utf8_if_unicode({}), {})
        assert_equal(to_utf8_if_unicode(object), object)

class Test_to_unicode_if_bytes(object):
    def test_valid(self):
        assert_equal(to_unicode_if_bytes(unicode_string), unicode_string)
        assert_equal(to_unicode_if_bytes(utf8_bytes), unicode_string)
        assert_equal(to_unicode_if_bytes(None), None)
        assert_equal(to_unicode_if_bytes(False), False)
        assert_equal(to_unicode_if_bytes(5), 5)
        assert_equal(to_unicode_if_bytes([]), [])
        assert_equal(to_unicode_if_bytes(()), ())
        assert_equal(to_unicode_if_bytes({}), {})
        assert_equal(to_unicode_if_bytes(object), object)


class Test_to_unicode(object):
    def test_returns_unicode_and_None_unchanged_and_converts_bytes(self):
        assert_equal(bytes_to_unicode(utf8_bytes), unicode_string)
        assert_equal(bytes_to_unicode(unicode_string), unicode_string)
        assert_equal(bytes_to_unicode(None), None)
        assert_raises(AssertionError, bytes_to_unicode, 5)
        assert_raises(AssertionError, bytes_to_unicode, False)
        assert_raises(AssertionError, bytes_to_unicode, True)
        assert_raises(AssertionError, bytes_to_unicode, [])
        assert_raises(AssertionError, bytes_to_unicode, ())
        assert_raises(AssertionError, bytes_to_unicode, {})
        assert_raises(AssertionError, bytes_to_unicode, object)

class Test_to_utf8(object):
    def test_returns_bytes_and_None_unchanged_and_converts_unicode(self):
        assert_equal(unicode_to_utf8(unicode_string), utf8_bytes)
        assert_equal(unicode_to_utf8(None), None)
        assert_equal(unicode_to_utf8(utf8_bytes), utf8_bytes)
        assert_raises(AssertionError, unicode_to_utf8, 5)
        assert_raises(AssertionError, unicode_to_utf8, False)
        assert_raises(AssertionError, unicode_to_utf8, True)
        assert_raises(AssertionError, unicode_to_utf8, [])
        assert_raises(AssertionError, unicode_to_utf8, ())
        assert_raises(AssertionError, unicode_to_utf8, {})
        assert_raises(AssertionError, unicode_to_utf8, object)
