# -*- coding: utf-8 -*-
# URL utility functions.
#
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
:module: pyoauth.url
:synopsis: URL utility functions.

Functions
---------
Percent-encoding
~~~~~~~~~~~~~~~~
.. autofunction:: oauth_escape
.. autofunction:: oauth_unescape

Query string parsing and construction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: oauth_parse_qs
.. autofunction:: oauth_urlencode_s
.. autofunction:: oauth_urlencode_sl

URL parsing and convenience utilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: oauth_urlparse_normalized
.. autofunction:: oauth_url_append_query_params
.. autofunction:: oauth_url_sanitize

Query parameters
~~~~~~~~~~~~~~~~
.. autofunction:: oauth_url_query_params_add
.. autofunction:: oauth_url_query_params_merge
.. autofunction:: oauth_url_query_params_update
.. autofunction:: oauth_url_query_params_filter
.. autofunction:: oauth_url_query_params_dict

Parameter sanitization
~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: oauth_protocol_params_sanitize
.. autofunction:: oauth_url_query_params_sanitize

"""
import logging

try:
    # Python 3.
    from urllib.parse import urlparse, urlunparse, parse_qs, quote, unquote_plus
except ImportError:
    # Python 2.5+
    from urlparse import urlparse, urlunparse
    from urllib import quote, unquote_plus
    try:
        # Python 2.6+
        from urlparse import parse_qs
    except ImportError:
        from cgi import parse_qs

try:
    bytes
except Exception:
    bytes = str

from pyoauth.unicode import to_utf8_if_unicode, to_utf8, is_bytes_or_unicode


def oauth_parse_qs(query_string):
    """
    Parses a query parameter string according to the OAuth spec.

    Use only with OAuth query strings.

    :see: Parameter Sources (http://tools.ietf.org/html/rfc5849#section-3.4.1.3.1)
    :param query_string:
        Query string to parse. If ``query_string`` starts with a ``?`` character
        it will be ignored for convenience.
    """
    query_string = to_utf8_if_unicode(query_string) or ""
    if query_string.startswith("?"):
        query_string = query_string[1:]
    return parse_qs(query_string, keep_blank_values=True)


def oauth_escape(oauth_value):
    """
    Percent-encodes according to the OAuth spec.

    Used in constructing the signature base string and the "Authorization"
    header field.

    :see: Percent Encoding (http://tools.ietf.org/html/rfc5849#section-3.6)
    :param oauth_value:
        Query string parameter value to escape. If the value is a Unicode
        string, it will be encoded to UTF-8. A byte string is considered
        exactly that, a byte string and will not be UTF-8 encoded—however, it
        will be percent-encoded.
    :returns:
        Percent-encoded string.
   """
    oauth_value = bytes(to_utf8_if_unicode(oauth_value))
    return quote(oauth_value, safe="~")


def oauth_unescape(oauth_value):
    """
    Percent-decodes according to the OAuth spec.

    :see: Percent Encoding (http://tools.ietf.org/html/rfc5849#section-3.6)
    :param oauth_value:
        Value to percent-decode. Value will be UTF-8 encoded if
        it is a Unicode string. '+' is treated as a ' ' character.
    :returns:
        Percent-decoded value.
    """
    return unquote_plus(to_utf8(oauth_value))


def oauth_urlencode_s(query_params, allow_func=None):
    """
    Serializes a dictionary of query parameters into a string of query
    parameters, ``name=value`` pairs separated by ``&``, sorted first by
    ``name`` then by ``value`` based on the OAuth percent-encoding
    rules and specification.

    Behaves like :func:`urllib.urlencode` with ``doseq=1``.

    :param query_params:
        Dictionary of query parameters.
    :param allow_func:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def allow_func(name, value):
                return is_name_allowed(name) and is_value_allowed(value)
    :returns:
        A string of query parameters, ``name=value`` pairs separated by ``&``,
        sorted first by ``name`` and then by ``value`` based on the OAuth
        percent-encoding rules and specification.
    """
    return "&".join([k + "=" + v for k, v in
                     oauth_urlencode_sl(query_params, allow_func=allow_func)])


def oauth_urlencode_sl(query_params, allow_func=None):
    """
    Serializes a dictionary of query parameters into a list of query
    parameters, ``(name, value)`` pairs, sorted first by ``name`` then by
    ``value`` based on the OAuth percent-encoding rules and specification.

    Behaves like :func:`urllib.urlencode` with ``doseq=1``.

    :param query_params:
        Dictionary of query parameters.
    :param allow_func:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def allow_func(name, value):
                return is_name_allowed(name) and is_value_allowed(value)
    :returns:
        A list of query parameters, ``(name, value)`` pairs, sorted first by
        ``name`` and then by ``value`` based on the OAuth percent-encoding rules
        and specification.
    """
    query_params = query_params or {}
    encoded_pairs = []
    for k, v in query_params.items():
        # Keys are also percent-encoded according to OAuth spec.
        k = oauth_escape(to_utf8(k))
        if allow_func and not allow_func(k, v):
            continue
        elif is_bytes_or_unicode(v):
            encoded_pairs.append((k, oauth_escape(v),))
        else:
            try:
                v = list(v)
            except TypeError, e:
                assert "is not iterable" in bytes(e)
                encoded_pairs.append((k, oauth_escape(v),))
            else:
                # Loop over the sequence.
                if len(v) > 0:
                    for i in v:
                        encoded_pairs.append((k, oauth_escape(i), ))
                # ``urllib.urlencode()`` doesn't preserve blank lists.
                # Therefore, we're discarding them.
                #else:
                #    # Preserve blank list values.
                #    encoded_pairs.append((k, "", ))
    # Sort after encoding according to the OAuth spec.
    return sorted(encoded_pairs)


#TODO: Add test for oauth_url_query_params_add uses OAuth param sort order.
def oauth_url_query_params_add(url, extra_query_params, allow_func=None):
    """
    Adds additional query parameters to a URL while preserving existing ones.

    The URL will be normalized according to the OAuth specification with the
    exception that the URL fragment is preserved.

    :param url:
        The URL to add the additional query parameters to.
    :param extra_query_params:
        The additional query parameters as a dictionary object or a query
        string.
    :param allow_func:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def allow_func(name, value):
                return is_name_allowed(name) and is_value_allowed(value)
    :returns:
        A normalized URL with the fragment and existing query parameters
        preserved and with the extra query parameters added.
    """
    scheme, netloc, path, params, query, fragment = oauth_urlparse_normalized(url)

    d = oauth_url_query_params_merge(query, extra_query_params)
    qs = oauth_urlencode_s(d, allow_func=allow_func)
    return urlunparse((scheme, netloc, path, params, qs, fragment))


def oauth_url_query_params_merge(query_params, *extra_query_params):
    """
    Merges multiple query parameter dictionaries or strings.

    :param query_params:
        Query string or a dictionary of query parameters.
    :param extra_query_params:
        One or more query string or a dictionary of query parameters.
    :returns:
        A dictionary of merged query parameters.
    """
    query_params = oauth_url_query_params_dict(query_params)
    d = {}
    d.update(query_params)
    for qp in extra_query_params:
        qp = oauth_url_query_params_dict(qp)
        for name, value in qp.items():
            if name in d:
                d[name].extend(value)
            else:
                d[name] = value
    return d


def oauth_url_query_params_update(query_params, *extra_query_params):
    """
    Updates a dictionary of query parameters or a query string with
    replacement parameter values from the specified additional
    query parameter dictionaries or query strings.

    The parameters specified toward the end of the arguments to this function
    take precedence over all previous parameters.

    .. WARNING:
        This is a dangerous routine. Be careful with this routine.
        It may bite.

    :param query_params:
        Initial query parameter dictionary or query string.
    :param extra_query_params:
        A list query parameter dictionaries or query strings.
    :returns:
        A dictionary of updated query parameters.
    """
    query_params = oauth_url_query_params_dict(query_params)
    d = {}
    d.update(query_params)
    for qp in extra_query_params.items():
        qp = oauth_url_query_params_dict(qp)
        d.update(qp)
    return d


def oauth_url_query_params_filter(query_params, allow_func=None):
    """
    Filters query parameters out of a query parameter dictionary or
    query string.

    Example::

        def allow_only_parameter_names_starting_with_oauth(name, value):
            return name.startswith("oauth")

        oauth_url_query_params_filter(query_params,
            allow_func=allow_only_parameter_names_starting_with_oauth)

    :param query_params:
        Query parameter dictionary or query string.
    :param allow_func:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def allow_func(name, value):
                return is_name_allowed(name) and is_value_allowed(value)
    :returns:
        A filtered dictionary of query parameters.
    """
    query_params = oauth_url_query_params_dict(query_params)
    d = {}
    for name, value in query_params.items():
        if allow_func and not allow_func(name, value):
            continue
        else:
            d[name] = value
    return d


def oauth_url_query_params_dict(query_params):
    """
    Given a query string parses it into an un-flattened query parameter
    dictionary or given a parameter dictionary, un-flattens it.

    Example::

        dict(a=1, b=[1, 2], c="")   ->   dict(a[1], b=[1, 2], c=[""])
        a=1&b=1&b=2&c=              ->   dict(a[1], b=[1, 2], c=[""])

    :param query_params:
        A query parameter dictionary or a query string.
        If this argument is ``None`` an empty dictionary will be returned.
        Any other value will raise a ``ValueError`` exception.
    :returns:
        An un-flattened query parameter dictionary.
    """
    if is_bytes_or_unicode(query_params):
        return oauth_parse_qs(query_params)
    elif isinstance(query_params, dict):
        # Un-flatten the dictionary.
        d = {}
        for n, v in query_params.items():
            if not isinstance(v, list) and not isinstance(v, tuple):
                d[n] = [v]
            else:
                d[n] = list(v)
        return d
        # Alternative, but slower:
        #return oauth_parse_qs(oauth_urlencode_s(query_params))
    elif query_params is None:
        return {}
    else:
        raise ValueError("Query parameters must be passed as a dictionary or a query string.")


def oauth_urlparse_normalized(url):
    """
    Like :func:`urlparse.urlparse` but also normalizes scheme, netloc, port,
    and the path.

    Use with OAuth URLs.

    :see: Base String URI (http://tools.ietf.org/html/rfc5849#section-3.4.1.2)
    :param url:
        The URL to split and normalize.
    :returns:
        Tuple that contains these elements:
        ``(scheme, netloc, path, params, query, fragment)``
    """
    if not url:
        raise ValueError("Invalid URL.")

    parts = urlparse(url)

    scheme      = parts.scheme.lower()
    # Netloc.
    username    = parts.username or ""
    password    = (":" + parts.password) if parts.password else ""
    credentials = username + password
    credentials = (credentials + "@") if credentials else ""

    # Exclude default port numbers.
    # See:
    if parts.port:
        if (scheme == "http" and parts.port == 80) or (scheme == "https" and parts.port == 443):
            port = ""
        else:
            port = (":" + bytes(parts.port)) if parts.port else ""
    else:
        port = ""

    netloc        = credentials + parts.hostname.lower() + port
    # http://tools.ietf.org/html/rfc3986#section-3
    # and http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.2.2
    path          = parts.path or "/"
    matrix_params = parts.params or ""
    fragment      = parts.fragment or ""
    query         = parts.query or ""

    return scheme, netloc, path, matrix_params, query, fragment


def oauth_protocol_params_sanitize(query_params):
    """
    Removes non-oauth parameters from the query parameters.

    Used only in base string construction, Authorization headers construction
    and parsing, and OAuth requests.

    :param query_params:
        Query string or query parameter dictionary.
    :returns:
        Filtered protocol parameters dictionary.
    """
    def allow_func(n, v):
        if n.startswith("oauth_"):
            # This gets rid of "realm" or any non-OAuth param.
            if len(v) > 1:
                raise ValueError("Duplicate OAuth parameters found %r: %r" % (n, v))
            else:
                return True
        else:
            logging.warning("Invalid protocol parameter ignored: `%r`", n)
            return False
    return oauth_url_query_params_filter(query_params, allow_func=allow_func)


def oauth_url_query_params_sanitize(query_params):
    """
    Removes protocol parameters from the query parameters.

    Used only in base string construction, Authorization headers construction
    and parsing, and OAuth requests.

    :param query_params:
        Query string or query parameter dictionary.
    :returns:
        Filtered URL query parameter dictionary.
    """
    def allow_func(n, v):
        # This gets rid of any params beginning with "oauth_"
        if not n.startswith("oauth_"):
            return True
        else:
            logging.warning("Protocol parameter ignored from URL query parameters: `%r`", n)
            return False
    return oauth_url_query_params_filter(query_params, allow_func=allow_func)


def oauth_url_sanitize(url):
    """
    Normalizes an OAuth URL and cleans up protocol-specific parameters
    from the query string.

    Used only in base string construction, Authorization headers construction
    and parsing, and OAuth requests.

    :param url:
        The OAuth URL to sanitize.
    :returns:
        Normalized sanitized URL.
    """
    scheme, netloc, path, params, query, fragment = oauth_urlparse_normalized(url)
    query = oauth_urlencode_s(oauth_url_query_params_sanitize(query))
    return urlunparse((scheme, netloc, path, params, query, None))


def oauth_url_append_query_params(url, query_params):
    """
    Appends query params to any existing query string in the URL
    and returns a properly formatted URL. URL fragments are preserved.

    This is the equivalent of doing::

        sorted(URL query parameters) + "&" + sorted(query_params)

    :param url:
        The URL into which the query parameters will be concatenated.
    :param query_params:
        A dictionary of query parameters or a query string.
    :returns:
        A URL with the query parameters concatenated.

    Usage::

        >>> oauth_url_append_query_params("http://example.com/foo?a=b#fragment", dict(c="d"))
        'http://example.com/foo?a=b&c=d#fragment'
    """
    scheme, netloc, path, params, query, fragment = oauth_urlparse_normalized(url)
    query_string = "&".join([
        query,
        oauth_urlencode_s(oauth_url_query_params_dict(query_params)),
    ])
    return urlunparse((scheme, netloc, path, params, query_string, fragment))

