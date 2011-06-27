# -*- coding: utf-8 -*-
# Protocol-specific utility functions.
#
# Copyright (C) 2009 Facebook.
# Copyright (C) 2010 Rick Copeland <rcopeland@geek.net>
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
:module: pyoauth.utils
:synopsis: Protocol-specific utility functions.

Functions
---------
.. autofunction:: oauth_generate_nonce

.. autofunction:: oauth_generate_verification_code

.. autofunction:: oauth_generate_timestamp

.. autofunction:: oauth_get_hmac_sha1_signature

.. autofunction:: oauth_get_rsa_sha1_signature

.. autofunction:: oauth_check_rsa_sha1_signature

.. autofunction:: oauth_get_plaintext_signature

.. autofunction:: oauth_get_signature_base_string

.. autofunction:: oauth_get_normalized_query_string

.. autofunction:: oauth_get_normalized_authorization_header_value

.. autofunction:: oauth_parse_authorization_header_value

"""

import binascii
import hmac
import time
import uuid
import re


try:
    bytes
except:
    bytes = str

try:
    from urlparse import parse_qs
except ImportError:
    from cgi import parse_qs

try:
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import long_to_bytes, bytes_to_long
except ImportError:
    RSA = None
    def long_to_bytes(v):
        raise NotImplementedError()
    def bytes_to_long(v):
        raise NotImplementedError()

try:
    from hashlib import sha1
except ImportError:
    import sha as sha1  # Deprecated

from pyoauth.unicode import to_utf8
from pyoauth.url import oauth_escape, oauth_parse_qs, oauth_unescape, \
    oauth_urlencode_sl, oauth_urlencode, urlparse_normalized


def oauth_generate_nonce(length=-1):
    """
    Calculates an OAuth nonce.

    .. NOTE::
        I don't get it. Why did they have to name it "nonce"? Nonce feels like
        it's been borrowed from the Oxford Dictionary of Constipatese.

    :see: Nonce and Timestamp (http://tools.ietf.org/html/rfc5849#section-3.3)
    :param length:
        Length of the nonce to be returned.
        Default -1, which means the entire 31-character nonce is returned.
    :returns:
        A string representation of a randomly-generated hexadecimal OAuth nonce.
    """
    return binascii.b2a_hex(uuid.uuid4().bytes)[:length]


def oauth_generate_verification_code(length=8):
    """
    Calculates an OAuth verification code.

    The verification code will be displayed by the server if a callback URL
    is not provided by the client. The resource owner (the end-user) may
    need to enter this verification code on a limited device. Therefore,
    we limit the length of this code to 8 characters to keep it suitable
    for manual entry.

    .. NOTE:


    :see:
        Resource Owner Authorization
        (http://tools.ietf.org/html/rfc5849#section-2.2)
    :param length:
        Length of the verification code. Defaults to 8.
    :returns:
        A string representation of a randomly-generated hexadecimal OAuth
        verification code.
    """
    return oauth_generate_nonce(length=length)


def oauth_generate_timestamp():
    """
    Generates an OAuth timestamp.

    :see:
        Nonce and Timestamp (http://tools.ietf.org/html/rfc5849#section-3.3)
    :returns:
        A string containing a positive integer representing time.
    """
    return bytes(int(time.time()))


def oauth_get_hmac_sha1_signature(consumer_secret, method, url, oauth_params=None, token_secret=None):
    """
    Calculates an HMAC-SHA1 signature for a base string.

    :see: HMAC-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.2)
    :param consumer_secret:
        Client (consumer) secret
    :param method:
        Base string HTTP method.
    :param url:
        Base string URL that may include a query string.
    :param oauth_params:
        Base string protocol-specific query parameters.
    :param token_secret:
        Token secret if available.
    :returns:
        HMAC-SHA1 signature.
    """
    oauth_params = oauth_params or {}
    base_string = oauth_get_signature_base_string(method, url, oauth_params)
    key = _oauth_get_plaintext_signature(consumer_secret, token_secret=token_secret)
    hashed = hmac.new(key, base_string, sha1)
    return binascii.b2a_base64(hashed.digest())[:-1]


def oauth_get_rsa_sha1_signature(consumer_secret, method, url, oauth_params=None, token_secret=None):
    """
    Calculates an RSA-SHA1 OAuth signature.

    :see: RSA-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.3)
    :param consumer_secret:
        Client (consumer) secret
    :param method:
        Base string HTTP method.
    :param url:
        Base string URL that may include a query string.
    :param oauth_params:
        Base string protocol-specific query parameters.
    :param token_secret:
        Token secret if available.
    :returns:
        RSA-SHA1 signature.
    """
    oauth_params = oauth_params or {}

    if RSA is None:
        raise NotImplementedError()

    try:
        getattr(consumer_secret, "sign")
        key = consumer_secret
    except AttributeError:
        key = RSA.importKey(consumer_secret)

    base_string = oauth_get_signature_base_string(method, url, oauth_params)
    digest = sha1(base_string).digest()
    signature = key.sign(_pkcs1_v1_5_encode(key, digest), "")[0]
    signature_bytes = long_to_bytes(signature)

    return binascii.b2a_base64(signature_bytes)[:-1]


def oauth_check_rsa_sha1_signature(signature, consumer_secret, method, url, oauth_params=None, token_secret=None):
    """
    Verifies a RSA-SHA1 OAuth signature.

    :see: RSA-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.3)
    :author:
        Rick Copeland <rcopeland@geek.net>
    :param signature:
        RSA-SHA1 OAuth signature.
    :param consumer_secret:
        Client (consumer) secret
    :param method:
        Base string HTTP method.
    :param url:
        Base string URL that may include a query string.
    :param oauth_params:
        Base string protocol-specific query parameters.
    :param token_secret:
        Token secret if available.
    :returns:
        ``True`` if verified to be correct; ``False`` otherwise.
    """
    oauth_params = oauth_params or {}

    if RSA is None:
        raise NotImplementedError()

    try:
        getattr(consumer_secret, "publickey")
        key = consumer_secret
    except AttributeError:
        key = RSA.importKey(consumer_secret)

    base_string = oauth_get_signature_base_string(method, url, oauth_params)
    digest = sha1(base_string).digest()
    signature = bytes_to_long(binascii.a2b_base64(signature))
    data = _pkcs1_v1_5_encode(key, digest)

    return key.publickey().verify(data, (signature,))


def _pkcs1_v1_5_encode(rsa_key, sha1_digest):
    """
    Encodes a SHA1 digest using PKCS1's emsa-pkcs1-v1_5 encoding.

    Adapted from paramiko.

    :author:
        Rick Copeland <rcopeland@geek.net>

    :param rsa_key:
        RSA Key.
    :param sha1_digest:
        20-byte SHA1 digest.
    :returns:
        A blob of data as large as the key's N, using PKCS1's
        "emsa-pkcs1-v1_5" encoding.
    """
    SHA1_DIGESTINFO = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
    size = len(long_to_bytes(rsa_key.n))
    filler = '\xff' * (size - len(SHA1_DIGESTINFO) - len(sha1_digest) - 3)
    return '\x00\x01' + filler + '\x00' + SHA1_DIGESTINFO + sha1_digest


def oauth_get_plaintext_signature(consumer_secret, method, url, oauth_params=None, token_secret=None):
    """
    Calculates a PLAINTEXT signature for a base string.

    :see: PLAINTEXT (http://tools.ietf.org/html/rfc5849#section-3.4.4)
    :param consumer_secret:
        Client (consumer) shared secret
    :param method:
        Base string HTTP method.
    :param url:
        Base string URL that may include query string.
    :param oauth_params:
        Base string protocol-specific query parameters.
    :param token_secret:
        Token shared secret if available.
    :returns:
        PLAINTEXT signature.
    """
    return _oauth_get_plaintext_signature(consumer_secret, token_secret=token_secret)


def _oauth_get_plaintext_signature(consumer_secret, token_secret=None):
    """
    Calculates the PLAINTEXT signature.

    :param consumer_secret:
        Client (consumer) secret
    :param token_secret:
        Token secret if available.
    :returns:
        PLAINTEXT signature.
    """
    sig_elems = [oauth_escape(consumer_secret) if consumer_secret else ""]
    sig_elems.append(oauth_escape(token_secret) if token_secret else "")
    return "&".join(sig_elems)


def oauth_get_signature_base_string(method, url, oauth_params):
    """
    Calculates a signature base string based on the URL, method, and
    oauth arameters.

    Any query parameter by the name "oauth_signature" will be excluded
    from the base string.

    :see: Signature base string (http://tools.ietf.org/html/rfc5849#section-3.4.1)

    :param method:
        HTTP request method.
    :param url:
        The URL. If this includes a query string, query parameters are first
        extracted and encoded as well. Query parameters in the URL are
        overridden by those found in the ``query_params`` argument to this
        function.
    :param oauth_params:
        Protocol-specific parameters.
    :returns:
        Base string.
    """
    allowed_methods = ("POST", "PUT", "GET", "DELETE",
                       "OPTIONS", "TRACE", "HEAD", "CONNECT",
                       "PATCH")
    method_normalized = method.upper()
    if method_normalized not in allowed_methods:
        raise ValueError("Method must be one of the HTTP methods %s: got `%s` instead" % (allowed_methods, method))
    if not url:
        raise ValueError("URL must be specified.")
    if not isinstance(oauth_params, dict):
        raise ValueError("Query parameters must be specified as a dictionary.")

    base_url, _, _, path, _, query, _ = urlparse_normalized(url)
    query_string = oauth_get_normalized_query_string(oauth_parse_qs(query), oauth_params)
    normalized_url = base_url + path
    return "&".join(oauth_escape(e) for e in [method_normalized, normalized_url, query_string])


def oauth_get_normalized_query_string(url_query_params, oauth_params):
    """
    Normalizes a dictionary of query parameters according to OAuth spec.

    :see: Parameter Normalization (http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2)
    :param url_query_params:
        A dictionary of URL query parameters.
    :param oauth_params:
        A dictionary of protocol-specific query parameters. Any parameter
        names that do not begin with ``oauth_`` will be excluded from the
        normalized query string. ``oauth_signature`` is also specially excluded.
    :returns:
        Normalized string of query parameters.
    """
    url_query_params = url_query_params or {}
    oauth_params = oauth_params or {}

    # Clean up oauth params.
    # OAuth param names must begin with "oauth_".
    _oauth_params = {}
    for k, v in oauth_params.iteritems():
        if k.startswith("oauth_"):
            # This gets rid of "realm" or any non-OAuth param.
            _oauth_params[k] = v

    query_params = {}
    query_params.update(url_query_params)
    query_params.update(_oauth_params)

    # Now encode the parameters, while ignoring 'oauth_signature' from
    # the entire list of parameters.
    def allow_func(name, value):
        return name not in ('oauth_signature', )
    query_string = oauth_urlencode(query_params, allow_func=allow_func)
    return query_string


def oauth_get_normalized_authorization_header_value(oauth_params, realm=None):
    """
    Builds the Authorization header value.

    :see: Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1
    :param oauth_params:
        Protocol-specific parameters excluding the ``realm`` parameter.
    :param realm:
        If specified, the realm is included into the Authorization header.
        The realm is never percent-encoded according to the OAuth spec.
    :returns:
        A properly formatted Authorization header value.
    """
    indentation = " " * len("Authorization: ")
    if realm:
        s = 'OAuth realm="' + to_utf8(realm) + '",\n' + indentation
    else:
        s = 'OAuth '
    # Clean up oauth params.
    # OAuth param names must begin with "oauth_".
    _oauth_params = {}
    for k, v in oauth_params.iteritems():
        if k.startswith("oauth_"):
            # This gets rid of "realm" or any non-OAuth param.
            _oauth_params[k] = v
    normalized_param_pairs = oauth_urlencode_sl(_oauth_params)
    delimiter = ",\n" + indentation
    s += delimiter.join([k+'="'+v+ '"' for k, v in normalized_param_pairs])
    return s


def oauth_parse_authorization_header_value(header_value):
    """
    Parses the OAuth Authorization header.


    :see: Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1
    :param header_value:
        Header value.
    :returns:
        Dictionary of parameter name value pairs.
    """
    d = {}
    for name, value in _oauth_parse_authorization_header_value_l(header_value):
        if name in d:
            d[name].append(value)
        else:
            d[name] = [value]
    return d


def _oauth_parse_authorization_header_value_l(header_value):
    """
    Parses the OAuth Authorization header preserving the order of the
    parameters as in the header value.

    :see: Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1
    :param header_value:
        Header value.
    :returns:
        list of parameter name value pairs in the order in which they appeared::
    """
    # Remove the auth-scheme from the value.
    header_value = re.sub(r"(^OAuth[\s]+)", "", to_utf8(header_value).strip(), 1, re.IGNORECASE)

    pairs = [param_pair.strip() for param_pair in header_value.split(",")]
    decoded_pairs = []
    for param in pairs:
        if not param:
            continue
        nv = param.split("=", 1)
        if len(nv) != 2:
            raise ValueError("bad parameter field: %r" % (param, ))
        name, value = nv[0].strip(), nv[1].strip()
        if len(value) < 2:
            raise ValueError("bad parameter value: %r -- missing quotes?" % (param, ))
        if value[0] != '"' or value[-1] != '"':
            raise ValueError("missing quotes around parameter value: %r -- values must be quoted using (\")" % (param, ))

        # We only need to remove a single pair of quotes. Do not use str.strip('"').
        # We need to be able to detect problems with the values too.
        value = value[1:-1]
        name = oauth_unescape(name)
        if name.lower() != "realm":
            # "realm" is case-insensitive.
            # The realm parameter value is a simple quoted string.
            # It is neither percent-encoded nor percent-decoded in OAuth.
            value = oauth_unescape(value)
        decoded_pairs.append((name, value))
    return decoded_pairs
