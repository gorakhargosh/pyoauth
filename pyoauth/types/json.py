#!/usr/bin/env python
# -*- coding: utf-8 -*-
# JSON utilities.
#
# Copyright (C) 2009 Facebook.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""
:module: pyoauth.types.json
:synopsis: JSON codec.

.. autofunction:: json_decode
.. autofunction:: json_encode
"""

from pyoauth.types.unicode import bytes_to_unicode, to_unicode_recursively

try:
    # Built-in JSON library.
    import json
    assert hasattr(json, "loads") and hasattr(json, "dumps")
    _json_decode = json.loads
    _json_encode = json.dumps
except Exception:
    try:
        # Try to use the simplejson library.
        import simplejson as json
        _json_decode = lambda s: json.loads(bytes_to_unicode(s))
        _json_encode = lambda v: json.dumps(v)
    except ImportError:
        try:
            # For Google App Engine.
            from django.utils import simplejson as json
            _json_decode = lambda s: json.loads(bytes_to_unicode(s))
            _json_encode = lambda v: json.dumps(v)
        except ImportError:
            def _json_decode(s):
                raise NotImplementedError(
                    "A JSON parser is required, e.g., simplejson at "
                    "http://pypi.python.org/pypi/simplejson/")
            _json_encode = _json_decode


def json_encode(value):
    """
    Encodes a Python value into its equivalent JSON string.

    JSON permits but does not require forward slashes to be escaped.
    This is useful when json data is emitted in a <script> tag
    in HTML, as it prevents </script> tags from prematurely terminating
    the javscript. Some json libraries do this escaping by default,
    although python's standard library does not, so we do it here.

    :see: http://stackoverflow.com/questions/1580647/json-why-are-forward-slashes-escaped
    :param value:
        Python value.
    :returns:
        JSON string.
    """
    return _json_encode(to_unicode_recursively(value)).replace("</", "<\\/")


def json_decode(value):
    """
    Decodes a JSON string into its equivalent Python value.

    :param value:
        JSON string.
    :returns:
        Decoded Python value.
    """
    return _json_decode(value)

