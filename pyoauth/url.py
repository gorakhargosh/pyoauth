#!/usr/bin/env python
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
.. autofunction:: percent_encode
.. autofunction:: percent_decode

Query string parsing and construction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: parse_qs
.. autofunction:: urlencode_s
.. autofunction:: urlencode_sl

URL parsing and convenience utilities
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: urlparse_normalized
.. autofunction:: url_append_query
.. autofunction:: url_add_query
.. autofunction:: oauth_url_sanitize

Query parameters
~~~~~~~~~~~~~~~~
.. autofunction:: query_add
.. autofunction:: query_filter
.. autofunction:: query_unflatten

Parameter sanitization
~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: request_protocol_params_sanitize
.. autofunction:: query_params_sanitize

"""
import logging

try:
    # Python 3.
    from urllib.parse import urlparse, urlunparse, parse_qs as _parse_qs, quote, unquote_plus
except ImportError:
    # Python 2.5+
    from urlparse import urlparse, urlunparse
    from urllib import quote, unquote_plus
    try:
        # Python 2.6+
        from urlparse import parse_qs as _parse_qs
    except ImportError:
        from cgi import parse_qs as _parse_qs

try:
    bytes
except Exception:
    bytes = str

from pyoauth.unicode import to_utf8_if_unicode, to_utf8, is_bytes_or_unicode


def parse_qs(query_string):
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
        logging.warning("Ignoring `?` query string prefix -- `%r`" % query_string)
        query_string = query_string[1:]
    return _parse_qs(query_string, keep_blank_values=True)


def percent_encode(value):
    """
    Percent-encodes according to the OAuth spec.

    Used in constructing the signature base string and the "Authorization"
    header field.

    :see: Percent Encoding (http://tools.ietf.org/html/rfc5849#section-3.6)
    :param value:
        Query string parameter value to escape. If the value is a Unicode
        string, it will be encoded to UTF-8. A byte string is considered
        exactly that, a byte string and will not be UTF-8 encoded—however, it
        will be percent-encoded.
    :returns:
        Percent-encoded string.
   """
    value = bytes(to_utf8_if_unicode(value))
    return quote(value, safe="~")


def percent_decode(value):
    """
    Percent-decodes according to the OAuth spec.

    :see: Percent Encoding (http://tools.ietf.org/html/rfc5849#section-3.6)
    :param value:
        Value to percent-decode. Value will be UTF-8 encoded if
        it is a Unicode string. '+' is treated as a ' ' character.
    :returns:
        Percent-decoded value.
    """
    return unquote_plus(to_utf8(value))


def urlencode_s(query_params, allow_func=None):
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
                     urlencode_sl(query_params, allow_func=allow_func)])


def urlencode_sl(query_params, allow_func=None):
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
        k = percent_encode(to_utf8(k))
        if allow_func and not allow_func(k, v):
            continue
        elif is_bytes_or_unicode(v):
            encoded_pairs.append((k, percent_encode(v),))
        else:
            try:
                v = list(v)
            except TypeError, e:
                assert "is not iterable" in bytes(e)
                encoded_pairs.append((k, percent_encode(v),))
            else:
                # Loop over the sequence.
                if len(v) > 0:
                    for i in v:
                        encoded_pairs.append((k, percent_encode(i), ))
                # ``urllib.urlencode()`` doesn't preserve blank lists.
                # Therefore, we're discarding them.
                #else:
                #    # Preserve blank list values.
                #    encoded_pairs.append((k, "", ))
    # Sort after encoding according to the OAuth spec.
    return sorted(encoded_pairs)

def urlparse_normalized(url):
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


#TODO: Add test for url_add_query uses OAuth param sort order.
def url_add_query(url, extra_query_params, allow_func=None):
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
    scheme, netloc, path, params, query, fragment = urlparse_normalized(url)

    d = query_add(query, extra_query_params)
    qs = urlencode_s(d, allow_func=allow_func)
    return urlunparse((scheme, netloc, path, params, qs, fragment))


def url_append_query(url, query_params):
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

        >>> url_append_query("http://example.com/foo?a=b#fragment", dict(c="d"))
        'http://example.com/foo?a=b&c=d#fragment'
    """
    if not query_params:
        return url
    scheme, netloc, path, params, query, fragment = urlparse_normalized(url)
    query = (query + "&") if query else query
    query_string = query + urlencode_s(query_unflatten(query_params))
    return urlunparse((scheme, netloc, path, params, query_string, fragment))



def query_add(*query_params):
    """
    Merges multiple query parameter dictionaries or strings.

    :param query_params:
        One or more query string or a dictionary of query parameters.
    :returns:
        A dictionary of merged query parameters.
    """
    d = {}
    for qp in query_params:
        qp = query_unflatten(qp)
        for name, value in qp.items():
            if name in d:
                d[name].extend(value)
            else:
                d[name] = value
    return d


#def query_update(query_params, *extra_query_params):
#    """
#    Updates a dictionary of query parameters or a query string with
#    replacement parameter values from the specified additional
#    query parameter dictionaries or query strings.
#
#    The parameters specified toward the end of the arguments to this function
#    take precedence over all previous parameters.
#
#    .. WARNING:
#        This is a dangerous routine. Be careful with this routine.
#        It may bite.
#
#    :param query_params:
#        Initial query parameter dictionary or query string.
#    :param extra_query_params:
#        A list query parameter dictionaries or query strings.
#    :returns:
#        A dictionary of updated query parameters.
#    """
#    query_params = query_unflatten(query_params)
#    d = {}
#    d.update(query_params)
#    for qp in extra_query_params:
#        qp = query_unflatten(qp)
#        d.update(qp)
#    return d


def query_append(*query_params):
    """
    Appends additional query parameters to a query string. The additional
    query parameters appear after the initial query string.

    :param query_params:
        Additional query parameters dictionary or query string.
    :returns:
        Concatenated query string.
    """
    li = []
    for qp in query_params:
        qs = urlencode_s(query_unflatten(qp))
        if qs:
            li.append(qs)
    return "&".join(li)


def query_filter(query_params, allow_func=None):
    """
    Filters query parameters out of a query parameter dictionary or
    query string.

    Example::

        def allow_only_parameter_names_starting_with_oauth(name, value):
            return name.startswith("oauth")

        query_filter(query_params,
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
    query_params = query_unflatten(query_params)
    d = {}
    for name, value in query_params.items():
        if allow_func and not allow_func(name, value):
            continue
        else:
            d[name] = value
    return d


def query_unflatten(query_params):
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
        return parse_qs(query_params)
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
        #return parse_qs(urlencode_s(query_params))
    elif query_params is None:
        return {}
    else:
        raise ValueError("Query parameters must be passed as a dictionary or a query string.")



def request_protocol_params_sanitize(protocol_params):
    """
    Removes non-OAuth and non-transmittable OAuth parameters from the
    request query parameters.

    .. WARNING:: Do NOT use this function with responses. Use ONLY with requests.

        Specifically used ONLY in base string construction, Authorization
        headers construction and parsing, and OAuth requests.


    :param protocol_params:
        Query string or query parameter dictionary. Does not filter out
        ``oauth_signature``, but DOES filter out ``oauth_consumer_secret`` and
        ``oauth_token_secret``. These secret parameters must never be
        transmitted.
    :returns:
        Filtered protocol parameters dictionary.
    """
    def allow_func(n, v):
        if n.startswith("oauth_"):
            # This gets rid of "realm" or any non-OAuth param.
            if len(v) > 1:
                # Multiple values for a protocol parameter are not allowed.
                # We don't silently discard values because failing fast
                # is better than simply logging and waiting for the user
                # to figure it out all by herself.
                #
                # See Making Requests (http://tools.ietf.org/html/rfc5849#section-3.1)
                # Point 2. Each parameter MUST NOT appear more than once per
                # request, so we disallow multiple values for a protocol
                # parameter.
                raise ValueError("Multiple protocol parameter values found %r=%r" % (n, v))
            elif n in ("oauth_consumer_secret", "oauth_token_secret", ):
                raise ValueError("[SECURITY-ISSUE] Client attempting to transmit confidential protocol parameter `%r`. Communication is insecure if this is in your server logs." % (n, ))
            else:
                return True
        else:
            logging.warning("Invalid protocol parameter ignored: `%r`", n)
            return False
    return query_filter(protocol_params, allow_func=allow_func)


def query_params_sanitize(query_params):
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
    return query_filter(query_params, allow_func=allow_func)


def oauth_url_sanitize(url, force_secure=True):
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
    scheme, netloc, path, params, query, fragment = urlparse_normalized(url)
    query = urlencode_s(query_params_sanitize(query))
    if force_secure and scheme != "https":
        #logging.warning("RFC specification requires the use of SSL/TLS for inter-server communication.")
        raise ValueError("OAuth 1.0 specification requires the use of SSL/TLS for inter-server communication.")
    return urlunparse((scheme, netloc, path, params, query, None))


def is_valid_callback_url(url):
    """
    Determines whether a specified URl is a valid oauth_callback callback
    absolute URL as required by http://tools.ietf.org/html/rfc5849#section-2.1
    (Temporary Credentials) in the OAuth specification.

    :param url:
        The URL to validate.
    :returns:
        ``True`` if valid; ``False`` otherwise.
    """
    if not is_bytes_or_unicode(url):
        return False
    if url == "oob":
        return True
    else:
        scheme, netloc, _, _, _, _ = urlparse(url)
        if scheme.lower() in ("http", "https") and netloc:
            return True
        else:
            return False

