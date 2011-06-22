#!/usr/bin/env python
# -*- coding: utf-8 -*-
# OAuth utility functions.
#
# Copyright (C) 2009 Facebook.
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>


import binascii
import time
import urlparse
import urllib
import uuid

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

from pyoauth.unicode import to_utf8

def url_equals(url1, url2):
    """
    Compares two URLs and determines whether they are the equal.

    :param url1:
        First URL.
    :param url2:
        Second URL.
    :returns:
        ``True`` if equal; ``False`` otherwise.
    """
    u1 = urlparse.urlparse(url1)
    u2 = urlparse.urlparse(url2)
    return u1.hostname == u2.hostname and \
        u1.password == u2.password and \
        u1.port == u2.port and \
        u1.username == u2.username and \
        u1.scheme == u2.scheme and \
        u1.path == u2.path and \
        u1.netloc == u2.netloc and \
        parse_qs(u1.query, keep_blank_values=True) == parse_qs(u2.query, keep_blank_values=True)


def url_concat(url, query_params=None):
    """
    Concatenate URL and query parameters regardless of whether
    the URL has existing query parameters.

    :param url:
        The URL to add the query parameters to.
    :param query_params:
        Query parameter dictionary.

    >>> url = url_concat("http://www.example.com/foo?a=b", dict(c="d"))
    >>> url_equals("http://www.example.com/foo?a=b&c=d", url)
    True

    >>> url = url_concat("http://www.example.com/", dict(c="d"))
    >>> url_equals("http://www.example.com/?c=d", url)
    True

    >>> url = url_concat("http://www.example.com/", dict(c="d"))
    >>> url_equals("http://www.example.com/?c=d", url)
    True

    >>> url = url_concat("http://www.example.com/foo?a=b", dict(a="d"))
    >>> url_equals("http://www.example.com/foo?a=b&a=d", url)
    True
    """
    if not query_params:
        return url
    if url[-1] not in ("?", "&"):
        url += "&" if ("?" in url) else "?"
    return url + urllib.urlencode(query_params)


def generate_nonce():
    """
    Calculates an OAuth nonce.

    :returns:
        A string representation of a randomly-generated hexadecimal OAuth nonce
        as follows::

            Nonce and Timestamp (http://tools.ietf.org/html/rfc5849#section-3.3)
            --------------------------------------------------------------------
            A nonce is a random string, uniquely generated by the client to allow
            the server to verify that a request has never been made before and
            helps prevent replay attacks when requests are made over a non-secure
            channel.  The nonce value MUST be unique across all requests with the
            same timestamp, client credentials, and token combinations.

    """
    return binascii.b2a_hex(uuid.uuid4().bytes)


def generate_timestamp():
    """
    Generates an OAuth timestamp.

    :returns:
        A string containing a positive integer representing time as follows::

            Nonce and Timestamp (http://tools.ietf.org/html/rfc5849#section-3.3)
            --------------------------------------------------------------------
            The timestamp value MUST be a positive integer.  Unless otherwise
            specified by the server's documentation, the timestamp is expressed
            in the number of seconds since January 1, 1970 00:00:00 GMT.

    """
    return str(int(time.time()))


def oauth_escape(val):
    """
    Escapes the value of a query string parameter according to the OAuth spec.

    :param val:
        Query string parameter value to escape.
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
    if isinstance(val, unicode):
        val = val.encode("utf-8")
    return urllib.quote(val, safe="~")


def oauth_get_signature_base_string(url, method, query_params):
    """
    Calculates a signature base string based on the URL, method, and
    query_parameters.

    :param url:
        The URL. If this includes a query string, query parameters are first
        extracted and encoded as well.
    :param method:
        HTTP request method.
    :param query_params:
        Query string parameters.
    :returns:
        Base string as per rfc5849#section-3.4.1 as follows::

            Signature base string (http://tools.ietf.org/html/rfc5849#section-3.4.1)
            ------------------------------------------------------------------------
            The signature base string is a consistent, reproducible concatenation
            of several of the HTTP request elements into a single string.  The
            string is used as an input to the "HMAC-SHA1" and "RSA-SHA1"
            signature methods.

            The signature base string includes the following components of the
            HTTP request:

            *  The HTTP request method (e.g., "GET", "POST", etc.).

            *  The authority as declared by the HTTP "Host" request header field.

            *  The path and query components of the request resource URI.

            *  The protocol parameters excluding the "oauth_signature".

            *  Parameters included in the request entity-body if they comply with
               the strict restrictions defined in Section 3.4.1.3.

            The signature base string does not cover the entire HTTP request.
            Most notably, it does not include the entity-body in most requests,
            nor does it include most HTTP entity-headers.  It is important to
            note that the server cannot verify the authenticity of the excluded
            request components without using additional protections such as SSL/
            TLS or other methods.
    """
    normalized_url, url_query_params = _oauth_get_normalized_url(url)
    url_query_params.update(query_params)
    query_string = oauth_get_normalized_query_string(url_query_params)
    base_elems = [method.upper(), normalized_url, query_string]
    base_string = "&".join(oauth_escape(e) for e in base_elems)
    return base_string


def oauth_get_normalized_query_string(query_params):
    """
    Normalizes a dictionary of query parameters according to OAuth spec.

    :param query_params:
        Query string parameters.
    :returns:
        Normalized string of query parameters as follows::

            Parameter Normalization (http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2)
            ------------------------------------------------------------------------------
            The parameters collected in Section 3.4.1.3 are normalized into a
            single string as follows:

            1.  First, the name and value of each parameter are encoded
               (Section 3.6).

            2.  The parameters are sorted by name, using ascending byte value
               ordering.  If two or more parameters share the same name, they
               are sorted by their value.

            3.  The name of each parameter is concatenated to its corresponding
               value using an "=" character (ASCII code 61) as a separator, even
               if the value is empty.

            4.  The sorted name/value pairs are concatenated together into a
               single string by using an "&" character (ASCII code 38) as
               separator.

            For example, the list of parameters from the previous section would
            be normalized as follows:

                                         Encoded:

                       +------------------------+------------------+
                       |          Name          |       Value      |
                       +------------------------+------------------+
                       |           b5           |     %3D%253D     |
                       |           a3           |         a        |
                       |          c%40          |                  |
                       |           a2           |       r%20b      |
                       |   oauth_consumer_key   | 9djdj82h48djs9d2 |
                       |       oauth_token      | kkk9d7dh3k39sjv7 |
                       | oauth_signature_method |     HMAC-SHA1    |
                       |     oauth_timestamp    |     137131201    |
                       |       oauth_nonce      |     7d8f3e4a     |
                       |           c2           |                  |
                       |           a3           |       2%20q      |
                       +------------------------+------------------+

                                          Sorted:

                       +------------------------+------------------+
                       |          Name          |       Value      |
                       +------------------------+------------------+
                       |           a2           |       r%20b      |
                       |           a3           |       2%20q      |
                       |           a3           |         a        |
                       |           b5           |     %3D%253D     |
                       |          c%40          |                  |
                       |           c2           |                  |
                       |   oauth_consumer_key   | 9djdj82h48djs9d2 |
                       |       oauth_nonce      |     7d8f3e4a     |
                       | oauth_signature_method |     HMAC-SHA1    |
                       |     oauth_timestamp    |     137131201    |
                       |       oauth_token      | kkk9d7dh3k39sjv7 |
                       +------------------------+------------------+

                                    Concatenated Pairs:

                          +-------------------------------------+
                          |              Name=Value             |
                          +-------------------------------------+
                          |               a2=r%20b              |
                          |               a3=2%20q              |
                          |                 a3=a                |
                          |             b5=%3D%253D             |
                          |                c%40=                |
                          |                 c2=                 |
                          | oauth_consumer_key=9djdj82h48djs9d2 |
                          |         oauth_nonce=7d8f3e4a        |
                          |   oauth_signature_method=HMAC-SHA1  |
                          |      oauth_timestamp=137131201      |
                          |     oauth_token=kkk9d7dh3k39sjv7    |
                          +-------------------------------------+

            and concatenated together into a single string (line breaks are for
            display purposes only)::

                 a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj
                 dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1
                 &oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7
    """
    if not query_params:
        return ""
    encoded = []
    for k, v in query_params.iteritems():
        k = to_utf8(k)
        if k == "oauth_signature":
            continue
        elif isinstance(v, basestring):
            encoded.append((oauth_escape(k), oauth_escape(v),))
        else:
            try:
                v = list(v)
            except TypeError, e:
                assert "is not iterable" in str(e)
                encoded.append((oauth_escape(k), oauth_escape(str(v)), ))
            else:
                encoded_k = oauth_escape(k)
                for i in v:
                    if isinstance(i, basestring):
                        encoded.append((encoded_k, oauth_escape(i), ))
                    else:
                        encoded.append((encoded_k, oauth_escape(str(i)), ))
    query_string = "&".join(["%s=%s" % (k, v) for k, v in sorted(encoded)])
    return query_string


def _oauth_get_normalized_url(url):
    """
    Normalizes a URL that will be used in the oauth signature.

    :param url:
        The URL to normalize.
    :returns:
        Normalized URL.
    """
    parts = urlparse.urlparse(url)
    scheme, netloc, path, _, query_string = parts[:5]
    normalized_url = scheme.lower() + "://" + netloc.lower() + path
    query_params = parse_qs(query_string.encode("utf-8"), keep_blank_values=True)
    return normalized_url, query_params