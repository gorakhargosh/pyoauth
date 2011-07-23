#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2009 Facebook
# Copyright (C) 2010, 2011 Tipfy.org
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
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

"""
:module: pyoauth.appengine
:synopsis: OAuth 1.0 support for App Engine.
"""

from __future__ import absolute_import, with_statement

try:
    from webapp2 import cached_property
    cached_property = cached_property
except ImportError:
    import threading

    class cached_property(object):
        """A decorator that converts a function into a lazy property.

        The function wrapped is called the first time to retrieve the result
        and then that calculated result is used the next time you access
        the value::

        class Foo(object):

        @cached_property
        def foo(self):
        # calculate something important here
        return 42

        The class has to have a `__dict__` in order for this property to
        work.

        .. note:: Implementation detail: this property is implemented as
        non-data descriptor. non-data descriptors are only invoked if there is
        no entry with the same name in the instance's __dict__.
        this allows us to completely get rid of the access function call
        overhead. If one choses to invoke __get__ by hand the property
        will still work as expected because the lookup logic is replicated
        in __get__ for manual invocation.

        This class was ported from `Werkzeug`_ and `Flask`_.
        """

    _default_value = object()

    def __init__(self, func, name=None, doc=None):
        self.__name__ = name or func.__name__
        self.__module__ = func.__module__
        self.__doc__ = doc or func.__doc__
        self.func = func
        self.lock = threading.RLock()

    def __get__(self, obj, type=None):
        if obj is None:
            return self

        with self.lock:
            value = obj.__dict__.get(self.__name__, self._default_value)
            if value is self._default_value:
                value = self.func(obj)
                obj.__dict__[self.__name__] = value

            return value
