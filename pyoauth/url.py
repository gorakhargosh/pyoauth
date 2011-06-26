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
from pyoauth.unicode import is_unicode_string, to_utf8, is_byte_string

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

def oauth_parse_qs(query_string):
    """
    Parses a query parameter string according to the OAuth spec.

    Use only with OAuth query strings.

    See Parameter Sources (http://tools.ietf.org/html/rfc5849#section-3.4.1.3.1)
    """
    query_string = query_string or ""
    return parse_qs(query_string.encode("utf-8"), keep_blank_values=True)


def oauth_escape(oauth_value):
    """
    Percent-encodes according to the OAuth spec.

    Used ONLY in constructing the signature base string and the "Authorization"
    header field.

    :param oauth_value:
        Query string parameter value to escape. If the value is a Unicode
        string, it will be encoded to UTF-8. A byte string is considered
        exactly that, a byte string and will not be UTF-8 encoded—however, it
        will be percent-encoded.
    :returns:
        String representing escaped value as follows::

            Percent Encoding (http://tools.ietf.org/html/rfc5849#section-3.6)
            -----------------------------------------------------------------
            Existing percent-encoding methods do not guarantee a consistent
            construction of the signature base string.  The following percent-
            encoding method is not defined to replace the existing encoding
            methods defined by [RFC3986] and [W3C.REC-html40-19980424].  It is
            used only in the construction of the signature base string and the
            "Authorization" header field.

            This specification defines the following method for percent-encoding
            strings:

            1.  Text values are first encoded as UTF-8 octets per [RFC3629] if
               they are not already.  This does not include binary values that
               are not intended for human consumption.

            2.  The values are then escaped using the [RFC3986] percent-encoding
               (%XX) mechanism as follows:

               *  Characters in the unreserved character set as defined by
                  [RFC3986], Section 2.3 (ALPHA, DIGIT, "-", ".", "_", "~") MUST
                  NOT be encoded.

               *  All other characters MUST be encoded.

               *  The two hexadecimal characters used to represent encoded
                  characters MUST be uppercase.

            This method is different from the encoding scheme used by the
            "application/x-www-form-urlencoded" content-type (for example, it
            encodes space characters as "%20" and not using the "+" character).
            It MAY be different from the percent-encoding functions provided by
            web-development frameworks (e.g., encode different characters, use
            lowercase hexadecimal characters).
    """
    if is_unicode_string(oauth_value):
        oauth_value = oauth_value.encode("utf-8")
    elif is_byte_string(oauth_value):
        pass
    else:
        oauth_value = str(oauth_value)
    return urllib.quote(oauth_value, safe="~")


def oauth_unescape(oauth_value):
    """
    Percent-decodes according to the OAuth spec.

    See Percent Encoding (http://tools.ietf.org/html/rfc5849#section-3.6)

    :param oauth_value:
        Value to percent-decode. Value will be UTF-8 encoded if it is a Unicode string.
    :returns:
        Percent-decoded value.
    """
    if is_unicode_string(oauth_value):
        oauth_value = oauth_value.encode("utf-8")
    return urllib.unquote(oauth_value.replace('+', ' '))


def oauth_urlencode(query_params, allow_func=None):
    """
    URL encodes a dictionary of query parameters into a string of query
    parameters, "name=value" pairs, sorted first by name then by value based on
    the OAuth percent-encoding rules and specification.

    :param query_params:
        Dictionary of query parameters.
    :param allow_func:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def allow_func(name, value):
                return is_name_allowed(name) and is_value_allowed(value):
    :returns:
        A string of query parameters, "name=value" pairs, sorted first by name
        and then by value based on the OAuth percent-encoding rules and
        specification.
    """
    return "&".join([k + "=" + v for k, v in
                     oauth_urlencode_sl(query_params, allow_func=allow_func)])


def oauth_urlencode_sl(query_params, allow_func=None):
    """
    URL encodes a dictionary of query parameters into a list of query
    parameters, (name, value) pairs, sorted first by name then by value based on
    the OAuth percent-encoding rules and specification.

    :param query_params:
        Dictionary of query parameters.
    :param allow_func:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def allow_func(name, value):
                return is_name_allowed(name) and is_value_allowed(value):
    :returns:
        A list of query parameters, (name, value) pairs, sorted first by name
        and then by value based on the OAuth percent-encoding rules and
        specification.
    """
    query_params = query_params or {}
    encoded_pairs = []
    for k, v in query_params.iteritems():
        # Keys are also percent-encoded according to OAuth spec.
        k = oauth_escape(to_utf8(k))
        if allow_func and not allow_func(k, v):
            continue
        elif isinstance(v, basestring):
            encoded_pairs.append((k, oauth_escape(v),))
        else:
            try:
                v = list(v)
            except TypeError, e:
                assert "is not iterable" in str(e)
                encoded_pairs.append((k, oauth_escape(v),))
            else:
                # Loop over the sequence.
                for i in v:
                    encoded_pairs.append((k, oauth_escape(i), ))
    # Sort after encoding according to the OAuth spec.
    return sorted(encoded_pairs)


def oauth_url_add_query_params(url, query_params):
    if not url:
        raise ValueError("URL not specified.")

    scheme, netloc, path, params, query_string, fragment = urlparse.urlparse(url)[:6]
    fragment = ("#" + fragment) if fragment else ""
    params = ";" + params if params else ""

    normalized_url = scheme.lower() + "://" + netloc + path + params

    url_query_params = oauth_parse_qs(query_string)
    d = {}
    d.update(url_query_params)
    for name, value in query_params.iteritems():
        if name in d:
            d[name].append(value)
        else:
            d[name] = [value]

    qs = oauth_urlencode(d)
    qs = ("?" + qs) if qs else ""

    return normalized_url + qs + fragment


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
