#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nose.tools import assert_equal, assert_false, assert_true, assert_raises
from nose import SkipTest

from mom.builtins import is_unicode, is_bytes, is_bytes_or_unicode
from mom.security.random import generate_random_bytes


random_bytes = generate_random_bytes(100)
utf8_bytes = '\xc2\xae'
unicode_string = u'\u00ae'


class Test_is_bytes(object):
    def test_valid(self):
        assert_true(is_bytes(random_bytes))
        assert_false(is_bytes(unicode_string))
        assert_false(is_bytes(False))
        assert_false(is_bytes(5))
        assert_false(is_bytes(None))
        assert_false(is_bytes([]))
        assert_false(is_bytes(()))
        assert_false(is_bytes([]))
        assert_false(is_bytes(object))


class Test_is_unicode(object):
    def test_valid(self):
        assert_false(is_unicode(random_bytes))
        assert_true(is_unicode(unicode_string))
        assert_false(is_unicode(False))
        assert_false(is_unicode(5))
        assert_false(is_unicode(None))
        assert_false(is_unicode([]))
        assert_false(is_unicode(()))
        assert_false(is_unicode({}))
        assert_false(is_unicode(object))

class Test_is_bytes_or_unicode(object):
    def test_valid(self):
        assert_true(is_bytes_or_unicode(random_bytes))
        assert_true(is_bytes_or_unicode(unicode_string))
        assert_false(is_bytes_or_unicode(False))
        assert_false(is_bytes_or_unicode(5))
        assert_false(is_bytes_or_unicode(None))
        assert_false(is_bytes_or_unicode([]))
        assert_false(is_bytes_or_unicode(()))
        assert_false(is_bytes_or_unicode({}))
        assert_false(is_bytes_or_unicode(object))
