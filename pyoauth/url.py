#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
# Copyright 2012 Google, Inc.
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
:synopsis: Protocol-specific URL utility functions.

Percent-encoding
----------------
.. autofunction:: percent_encode
.. autofunction:: percent_decode

Query string parsing and construction
-------------------------------------
.. autofunction:: parse_qs
.. autofunction:: urlencode_s
.. autofunction:: urlencode_sl

URL parsing and convenience utilities
-------------------------------------
.. autofunction:: urlparse_normalized
.. autofunction:: url_append_query
.. autofunction:: url_add_query
.. autofunction:: oauth_url_sanitize

Query parameters
----------------
.. autofunction:: query_add
.. autofunction:: query_select
.. autofunction:: query_unflatten

Parameter sanitization
----------------------
.. autofunction:: request_query_remove_non_oauth
.. autofunction:: query_remove_oauth

"""

import logging

from mom.builtins import is_sequence, bytes, is_bytes_or_unicode, is_bytes
from mom.codec.text import utf8_encode_if_unicode, \
    utf8_encode, utf8_decode_if_bytes
from mom.functional import select_dict, map_dict

from mom.builtins import b
from pyoauth._compat import urlparse, urlunparse, parse_qs as _parse_qs, \
    quote, \
    unquote_plus
from pyoauth.constants import SYMBOL_QUESTION_MARK, \
    SYMBOL_AMPERSAND, SYMBOL_EQUAL, OAUTH_PARAM_PREFIX, \
    OAUTH_VALUE_CALLBACK_OOB, OAUTH_PARAM_CONSUMER_SECRET, \
    OAUTH_PARAM_TOKEN_SECRET, SYMBOL_EMPTY_BYTES
from pyoauth.error import InvalidQueryParametersError, \
    InsecureOAuthParametersError, \
    InvalidOAuthParametersError, \
    InsecureOAuthUrlError, \
    InvalidUrlError

# Redefine str to behave like in Python 3.

try:
    str = unicode
except NameError:
    pass

def parse_qs(query_string):
    """
    Parses a query parameter string according to the OAuth spec.

    Use only with OAuth query strings.

    :see: Parameter Sources
        (http://tools.ietf.org/html/rfc5849#section-3.4.1.3.1)
    :param query_string:
        Query string to parse. If ``query_string`` starts with a ``?`` character
        it will be ignored for convenience.
    """
    query_string = utf8_encode_if_unicode(query_string) or SYMBOL_EMPTY_BYTES
    if query_string.startswith(SYMBOL_QUESTION_MARK):
        logging.warning(
            "Ignoring `?` query string prefix -- `%r`", query_string)
        query_string = query_string[1:]
    return _parse_qs(query_string, keep_blank_values=True)


def percent_encode(value):
    """
    Percent-encodes according to the OAuth spec.

    Used in constructing the signature base string and the "Authorization"
    header field::

        percent_encode('c@') -> 'c%40'

    :see: Percent Encoding (http://tools.ietf.org/html/rfc5849#section-3.6)
    :param value:
        Query string parameter value to escape. If the value is a Unicode
        string, it will be encoded to UTF-8. A byte string is considered
        exactly that, a byte string and will not be UTF-8 encoded—however, it
        will be percent-encoded.
    :returns:
        Percent-encoded string.
   """
    # Escapes '/' too
    if not is_bytes(value):
        value = utf8_encode(str(value))
    return quote(value, safe="~").encode("ascii")


def percent_decode(value):
    """
    Percent-decodes according to the OAuth spec::

        percent_decode('c%40') -> 'c@'

    :see: Percent Encoding (http://tools.ietf.org/html/rfc5849#section-3.6)
    :param value:
        Value to percent-decode. '+' is treated as a ' ' character.
    :returns:
        Percent-decoded value.
    """
    return utf8_decode_if_bytes(unquote_plus(value))


def urlencode_s(query_params, predicate=None):
    """
    Serializes a dictionary of query parameters into a string of query
    parameters, ``name=value`` pairs separated by ``&``, sorted first by
    ``name`` then by ``value`` based on the OAuth percent-encoding
    rules and specification.

    Behaves like :func:`urllib.urlencode` with ``doseq=1``.

    :param query_params:
        Dictionary of query parameters.
    :param predicate:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def predicate(name, value):
                return is_name_allowed(name) and is_value_allowed(value)
    :returns:
        A string of query parameters, ``name=value`` pairs separated by ``&``,
        sorted first by ``name`` and then by ``value`` based on the OAuth
        percent-encoding rules and specification.
    """
    return SYMBOL_AMPERSAND.join(
        key + SYMBOL_EQUAL + value
        for key, value in urlencode_sl(query_params, predicate))


def urlencode_sl(query_params, predicate=None):
    """
    Serializes a dictionary of query parameters into a list of query
    parameters, ``(name, value)`` pairs, sorted first by ``name`` then by
    ``value`` based on the OAuth percent-encoding rules and specification.

    Behaves like :func:`urllib.urlencode` with ``doseq=1``.

    :param query_params:
        Dictionary of query parameters.
    :param predicate:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def predicate(name, value):
                return is_name_allowed(name) and is_value_allowed(value)
    :returns:
        A list of query parameters, ``(name, value)`` pairs, sorted first by
        ``name`` and then by ``value`` based on the OAuth percent-encoding rules
        and specification.
    """
    query_params = query_params or {}
    encoded_pairs = []
    for k, value in query_params.items():
        # Keys are also percent-encoded according to OAuth spec.
        key = percent_encode(k)
        if predicate and not predicate(k, value):
            continue
        elif is_bytes_or_unicode(value):
            encoded_pairs.append((key, percent_encode(value),))
        elif is_sequence(value):
            # Loop over the sequence.
            if len(value) > 0:
                for i in value:
                    encoded_pairs.append((key, percent_encode(i), ))
            # ``urllib.urlencode()`` doesn't preserve blank lists.
            # Therefore, we're discarding them.
            #else:
            #    # Preserve blank list values.
            #    encoded_pairs.append((k, "", ))
        else:
            encoded_pairs.append((key, percent_encode(value),))
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
        raise InvalidUrlError("Invalid URL `%r`" % (url,))

    parts = urlparse(url)

    scheme      = parts.scheme.lower()
    # Netloc.
    username    = parts.username or SYMBOL_EMPTY_BYTES
    password    = (b(":") + parts.password) if parts.password \
                  else SYMBOL_EMPTY_BYTES
    credentials = username + password
    credentials = (credentials + b("@")) if credentials else SYMBOL_EMPTY_BYTES
    hostname = utf8_encode_if_unicode(parts.hostname.lower())

    # Exclude default port numbers.
    # See:
    if parts.port:
        if (scheme == b("http") and parts.port == 80) \
        or (scheme == b("https") and parts.port == 443):
            port = SYMBOL_EMPTY_BYTES
        else:
            port = (b(":") + str(parts.port).encode("ascii")) if parts.port \
                   else SYMBOL_EMPTY_BYTES
    else:
        port = SYMBOL_EMPTY_BYTES

    netloc        = credentials + hostname + port
    # http://tools.ietf.org/html/rfc3986#section-3
    # and http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.2.2
    path          = parts.path or b("/")
    matrix_params = parts.params or SYMBOL_EMPTY_BYTES
    fragment      = parts.fragment or SYMBOL_EMPTY_BYTES
    query         = parts.query or SYMBOL_EMPTY_BYTES

    return scheme, netloc, path, matrix_params, query, fragment


#TODO: Add test to ensure url_add_query uses OAuth param sort order.
def url_add_query(url, query, predicate=None):
    """
    Adds additional query parameters to a URL while preserving existing ones.

    The URL will be normalized according to the OAuth specification with the
    exception that the URL fragment is preserved.

    :param url:
        The URL to add the additional query parameters to.
    :param query:
        The additional query parameters as a dictionary object or a query
        string.
    :param predicate:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def predicate(name, value):
                return is_name_allowed(name) and is_value_allowed(value)
    :returns:
        A normalized URL with the fragment and existing query parameters
        preserved and with the extra query parameters added.
    """
    scheme, netloc, path, params, query_s, fragment = urlparse_normalized(url)

    query_d = query_add(query_s, query)
    query_s = urlencode_s(query_d, predicate)
    return urlunparse((scheme, netloc, path, params, query_s, fragment))


def url_append_query(url, query):
    """
    Appends query params to any existing query string in the URL
    and returns a properly formatted URL. URL fragments are preserved.

    This is the equivalent of doing::

        sorted(URL query parameters) + "&" + sorted(query)

    :param url:
        The URL into which the query parameters will be concatenated.
    :param query:
        A dictionary of query parameters or a query string.
    :returns:
        A URL with the query parameters concatenated.

    Usage::

        >>> url_append_query("http://example.com/foo?a=b#fragment", dict(c="d"))
        'http://example.com/foo?a=b&c=d#fragment'
    """
    if not query:
        return url
    scheme, netloc, path, params, query_s, fragment = urlparse_normalized(url)
    query_s = (query_s + SYMBOL_AMPERSAND) if query_s else query_s
    query_s = query_s + urlencode_s(query_unflatten(query))
    return urlunparse((scheme, netloc, path, params, query_s, fragment))


def query_add(*queries):
    """
    Merges multiple query parameter dictionaries or strings.

    :param queries:
        One or more query string or a dictionary of query parameters.
    :returns:
        A dictionary of merged query parameters.
    """
    new_query_d = {}
    for query in queries:
        query_d = query_unflatten(query)
        for name, value in query_d.items():
            if name in new_query_d:
                new_query_d[name].extend(value)
            else:
                new_query_d[name] = value
    return new_query_d


def query_append(*queries):
    """
    Appends additional query parameters to a query string. The additional
    query parameters appear after the initial query string.

    :param queries:
        Additional query parameters dictionary or query string.
    :returns:
        Concatenated query string.
    """
    sub_queries = []
    for query in queries:
        query_s = urlencode_s(query_unflatten(query))
        if query_s:
            sub_queries.append(query_s)
    return SYMBOL_AMPERSAND.join(sub_queries)


def query_select(query, predicate):
    """
    Filters query parameters out of a query parameter dictionary or
    query string.

    Example::

        query_select(query, lambda k, v: k.startswith("oauth_"))

    :param query:
        Query parameter dictionary or query string.
    :param predicate:
        A callback that will be called for each query parameter and should
        return ``False`` or a falsy value if that parameter should not be
        included. By default, all query parameters are included. The function
        takes the following method signature::

            def predicate(name, value):
                return is_name_allowed(name) and is_value_allowed(value)
    :returns:
        A filtered dictionary of query parameters.
    """
    return select_dict(predicate, query_unflatten(query))


def query_unflatten(query):
    """
    Given a query string parses it into an un-flattened query parameter
    dictionary or given a parameter dictionary, un-flattens it.

    Example::

        dict(a=1, b=[1, 2], c="")   ->   dict(a[1], b=[1, 2], c=[""])
        a=1&b=1&b=2&c=              ->   dict(a[1], b=[1, 2], c=[""])

    :param query:
        A query parameter dictionary or a query string.
        If this argument is ``None`` an empty dictionary will be returned.
        Any other value will raise a
        :class:`pyoauth.errors.InvalidQueryParametersError` exception.
    :returns:
        An un-flattened query parameter dictionary.
    """
    if is_bytes_or_unicode(query):
        return parse_qs(query)
    elif isinstance(query, dict):
        # Un-flatten the dictionary.
        def _choose(key, value):
            if not isinstance(value, list) and not isinstance(value, tuple):
                return key, [value]
            else:
                return key, list(value)
        return map_dict(_choose, query)
        # Alternative, but slower:
        #return parse_qs(urlencode_s(query))
    elif query is None:
        return {}
    else:
        raise InvalidQueryParametersError(
            "Dictionary or query string required: got `%r` instead" \
            % (query, ))


def request_query_remove_non_oauth(query):
    """
    Removes non-OAuth and non-transmittable OAuth parameters from the
    request query parameters.

    .. WARNING:: Do NOT use this function with responses.

        Use ONLY with requests.

        Specifically used ONLY in base string construction, Authorization
        headers construction and parsing, and OAuth requests.

    :param query:
        Query string or query parameter dictionary. Does not filter out
        ``oauth_signature``, but DOES filter out ``oauth_consumer_secret`` and
        ``oauth_token_secret``. These secret parameters must never be
        transmitted.
    :returns:
        Filtered protocol parameters dictionary.
    """
    def predicate(name, value):
        """
        Allows only valid oauth parameters.

        Raises an error if multiple values are specified.

        :param name:
            Protocol parameter name.
        :param value:
            Protocol parameter value.
        :returns:
            ``True`` if the parameter should be included; ``False`` otherwise.
        """
        name = utf8_decode_if_bytes(name)
        if name.startswith(OAUTH_PARAM_PREFIX):
            # This gets rid of "realm" or any non-OAuth param.
            if len(value) > 1:
                # Multiple values for a protocol parameter are not allowed.
                # We don't silently discard values because failing fast
                # is better than simply logging and waiting for the user
                # to figure it out all by herself.
                #
                # See Making Requests
                # (http://tools.ietf.org/html/rfc5849#section-3.1)
                # Point 2. Each parameter MUST NOT appear more than once per
                # request, so we disallow multiple values for a protocol
                # parameter.
                raise InvalidOAuthParametersError(
                    "Multiple protocol parameter values found %r=%r" \
                    % (name, value))
            elif name in (OAUTH_PARAM_CONSUMER_SECRET,
                          OAUTH_PARAM_TOKEN_SECRET, ):
                raise InsecureOAuthParametersError(
                    "[SECURITY-ISSUE] Client attempting to transmit "\
                    "confidential protocol parameter `%r`. Communication "\
                    "is insecure if this is in your server logs." % (name, ))
            else:
                return True
        else:
            logging.warning("Invalid protocol parameter ignored: `%r`", name)
            return False
    return query_select(query, predicate)


def query_remove_oauth(query):
    """
    Removes protocol parameters from the query parameters.

    Used only in base string construction, Authorization headers construction
    and parsing, and OAuth requests.

    :param query:
        Query string or query parameter dictionary.
    :returns:
        Filtered URL query parameter dictionary.
    """
    def predicate(name, _):
        """
        Removes any parameters beginning with ``oauth_``.

        :param name:
            The parameter name.
        :returns:
            ``True`` if should be included; ``False`` otherwise.
        """
        # This gets rid of any params beginning with "oauth_"
        name = utf8_decode_if_bytes(name)
        if not name.startswith(OAUTH_PARAM_PREFIX):
            return True
        else:
            logging.warning(
                "Protocol parameter ignored from URL query parameters: `%r`",
                name)
            return False
    return query_select(query, predicate)


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
    scheme, netloc, path, params, query, _ = urlparse_normalized(url)
    query = urlencode_s(query_remove_oauth(query))
    if force_secure and scheme != b("https"):
        raise InsecureOAuthUrlError(
            "OAuth specification requires the use of SSL/TLS for "\
            "inter-server communication.")
    elif not force_secure and scheme != b("https"):
        logging.warning(
            "INSECURE URL: OAuth specification requires the use of SSL/TLS "\
            "for credential requests.")
    return urlunparse((scheme, netloc, path, params, query, None))


def is_valid_callback_url(url):
    """
    Determines whether a specified URL is a valid oauth_callback callback
    absolute URL as required by http://tools.ietf.org/html/rfc5849#section-2.1
    (Temporary Credentials) in the OAuth specification.

    :param url:
        The URL to validate.
    :returns:
        ``True`` if valid; ``False`` otherwise.
    """
    if not is_bytes(url):
        return False
    if url == OAUTH_VALUE_CALLBACK_OOB:
        return True
    else:
        scheme, netloc, _, _, _, _ = urlparse(url)
        return scheme.lower() in (b("http"), b("https")) and netloc
