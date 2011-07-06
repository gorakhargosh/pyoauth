#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nose.tools import assert_equal, assert_false, assert_true, assert_raises
from nose import SkipTest
from pyoauth.types.unicode import\
    to_utf8_if_unicode, to_unicode_if_bytes, to_unicode, to_utf8

import uuid

random_bytes = uuid.uuid4().bytes
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
        assert_equal(to_unicode(utf8_bytes), unicode_string)
        assert_equal(to_unicode(unicode_string), unicode_string)
        assert_equal(to_unicode(None), None)
        assert_raises(AssertionError, to_unicode, 5)
        assert_raises(AssertionError, to_unicode, False)
        assert_raises(AssertionError, to_unicode, True)
        assert_raises(AssertionError, to_unicode, [])
        assert_raises(AssertionError, to_unicode, ())
        assert_raises(AssertionError, to_unicode, {})
        assert_raises(AssertionError, to_unicode, object)

class Test_to_utf8(object):
    def test_returns_bytes_and_None_unchanged_and_converts_unicode(self):
        assert_equal(to_utf8(unicode_string), utf8_bytes)
        assert_equal(to_utf8(None), None)
        assert_equal(to_utf8(utf8_bytes), utf8_bytes)
        assert_raises(AssertionError, to_utf8, 5)
        assert_raises(AssertionError, to_utf8, False)
        assert_raises(AssertionError, to_utf8, True)
        assert_raises(AssertionError, to_utf8, [])
        assert_raises(AssertionError, to_utf8, ())
        assert_raises(AssertionError, to_utf8, {})
        assert_raises(AssertionError, to_utf8, object)
