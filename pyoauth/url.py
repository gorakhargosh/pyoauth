# -*- coding: utf-8 -*-
# URL utility functions.
#
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
#
# MIT License
# -----------
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


import urlparse
import urllib

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs



def url_equals(url1, url2):
    """
    Compares two URLs and determines whether they are the equal.

    :param url1:
        First URL.
    :param url2:
        Second URL.
    :returns:
        ``True`` if equal; ``False`` otherwise.

    Usage::

        >>> url_equals("http://www.google.com/a", "http://www.google.com/a")
        True
        >>> url_equals("https://www.google.com/a", "http://www.google.com/a")
        False
        >>> url_equals("http://www.google.com/", "http://www.example.com/")
        False
        >>> url_equals("http://example.com:80/", "http://example.com:8000/")
        False
        >>> url_equals("http://user@example.com/", "http://user2@example.com.com/")
        False
        >>> url_equals("http://user@example.com/request?a=b&b=c&b=d#fragment", "http://user@example.com/request?b=c&b=d&a=b#fragment")
        True
        >>> url_equals("http://user@example.com/request?a=b&b=c&b=d#fragment", "http://user@example.com/request?b=c&b=d&a=b#fragment2")
        False
        >>> url_equals("http://www.google.com/request?a=b", "http://www.google.com/request?b=c")
        False
    """
    u1 = urlparse.urlparse(url1)
    u2 = urlparse.urlparse(url2)
    return u1.scheme == u2.scheme and \
        u1.path == u2.path and \
        u1.netloc == u2.netloc and \
        u1.fragment == u2.fragment and \
        parse_qs(u1.query, keep_blank_values=True) == parse_qs(u2.query, keep_blank_values=True)


def url_concat(url, **query_params):
    """
    Concatenate URL and query parameters regardless of whether
    the URL has existing query parameters.

    DO NOT use this to construct OAuth URLs.

    :param url:
        The URL to add the query parameters to.
    :param query_params:
        Query parameter dictionary.

    >>> url = url_concat("http://www.example.com/foo?a=b", c="d")
    >>> url_equals("http://www.example.com/foo?a=b&c=d", url)
    True

    >>> url = url_concat("http://www.example.com/", c="d")
    >>> url_equals("http://www.example.com/?c=d", url)
    True

    >>> url = url_concat("http://www.example.com/", c="d")
    >>> url_equals("http://www.example.com/?c=d", url)
    True

    >>> url = url_concat("http://www.example.com/foo?a=b", a="d")
    >>> url_equals("http://www.example.com/foo?a=b&a=d", url)
    True

    >>> url = url_concat("http://www.example.com/")
    >>> url_equals("http://www.example.com/", url)
    True
    """
    if not query_params:
        return url
    if url[-1] not in ("?", "&"):
        url += "&" if ("?" in url) else "?"
    return url + urllib.urlencode(query_params)
