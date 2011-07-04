#!/usr/bin/env python
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
.. autofunction:: generate_nonce
.. autofunction:: generate_verification_code
.. autofunction:: generate_timestamp

OAuth Signature and Base String
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
.. autofunction:: get_hmac_sha1_signature
.. autofunction:: get_rsa_sha1_signature
.. autofunction:: check_rsa_sha1_signature
.. autofunction:: get_plaintext_signature
.. autofunction:: get_signature_base_string

Authorization Header
~~~~~~~~~~~~~~~~~~~~
.. autofunction:: get_normalized_authorization_header_value
.. autofunction:: parse_authorization_header_value

"""

import binascii
import hmac
import os
import time
import uuid
import re
from pyoauth.error import InvalidHttpMethodError, \
    InvalidUrlError, \
    InvalidOAuthParametersError, \
    InvalidAuthorizationHeaderError


try:
    bytes
except Exception:
    bytes = str

try:
    # Python 3.
    from urllib.parse import urlunparse
except ImportError:
    # Python 2.5+
    from urlparse import urlunparse


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
from pyoauth.url import percent_encode, percent_decode, \
    urlencode_sl, urlencode_s, urlparse_normalized, \
    request_protocol_params_sanitize, query_params_sanitize


def generate_nonce(length=32):
    """
    Calculates an OAuth nonce.

    :see: Nonce and Timestamp (http://tools.ietf.org/html/rfc5849#section-3.3)
    :param length:
        Length of the nonce to be returned. Default 32.
        oThe length MUST be an even number.
    :returns:
        A string representation of a randomly-generated hexadecimal OAuth nonce.
    """
    if length % 2 or length <= 0:
        raise ValueError("This function expects an even positive length: got length `%r`." % (length, ))
    return binascii.b2a_hex(os.urandom(length/2))


def generate_verification_code(length=8):
    """
    Calculates an OAuth verification code.

    The verification code will be displayed by the server if a callback URL
    is not provided by the client. The resource owner (the end-user) may
    need to enter this verification code on a limited device. Therefore,
    we limit the length of this code to 8 characters to keep it suitable
    for manual entry.

    :see:
        Resource Owner Authorization
        (http://tools.ietf.org/html/rfc5849#section-2.2)
    :param length:
        Length of the nonce to be returned. Default 32.
        If 0, negative, or ``None``, a 32 character value will
        be returned as well. The length MUST be an even number.
    :returns:
        A string representation of a randomly-generated hexadecimal OAuth
        verification code.
    """
    return generate_nonce(length=length)


def generate_timestamp():
    """
    Generates an OAuth timestamp.

    :see:
        Nonce and Timestamp (http://tools.ietf.org/html/rfc5849#section-3.3)
    :returns:
        A string containing a positive integer representing time.
    """
    return bytes(int(time.time()))


def get_hmac_sha1_signature(client_shared_secret,
                            method, url, oauth_params=None,
                            token_or_temporary_shared_secret=None):
    """
    Calculates an HMAC-SHA1 signature for a base string.

    :see: HMAC-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.2)
    :param client_shared_secret:
        Client (consumer) shared secret.
    :param method:
        Base string HTTP method.
    :param url:
        Base string URL that may include a query string.
        All protocol-specific parameters will be ignored from the query string.
    :param oauth_params:
        Base string protocol-specific query parameters.
        All non-protocol parameters will be ignored.
    :param token_or_temporary_shared_secret:
        Token/temporary credentials shared secret if available.
    :returns:
        HMAC-SHA1 signature.
    """
    oauth_params = oauth_params or {}
    base_string = get_signature_base_string(method, url, oauth_params)
    key = _get_plaintext_signature(client_shared_secret,
                                   token_or_temporary_shared_secret)
    hashed = hmac.new(key, base_string, sha1)
    return binascii.b2a_base64(hashed.digest())[:-1]


def get_rsa_sha1_signature(client_shared_secret,
                           method, url, oauth_params=None,
                           token_or_temporary_shared_secret=None,
                           _test_rsa=RSA):
    """
    Calculates an RSA-SHA1 OAuth signature.

    :see: RSA-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.3)
    :param client_shared_secret:
        Client (consumer) shared secret.
    :param method:
        Base string HTTP method.
    :param url:
        Base string URL that may include a query string.
        All protocol-specific paramters will be ignored from the query string.
    :param oauth_params:
        Base string protocol-specific query parameters.
        All non-protocol parameters will be ignored.
    :param token_or_temporary_shared_secret:
        Token/temporary credentials shared secret if available.
    :returns:
        RSA-SHA1 signature.
    """
    oauth_params = oauth_params or {}

    if _test_rsa is None:
        raise NotImplementedError()

    try:
        getattr(client_shared_secret, "sign")
        key = client_shared_secret
    except AttributeError:
        key = _test_rsa.importKey(client_shared_secret)

    base_string = get_signature_base_string(method, url, oauth_params)
    digest = sha1(base_string).digest()
    signature = key.sign(_pkcs1_v1_5_encode(key, digest), "")[0]
    signature_bytes = long_to_bytes(signature)

    return binascii.b2a_base64(signature_bytes)[:-1]


def check_rsa_sha1_signature(signature, client_shared_secret,
                             method, url, oauth_params=None,
                             token_or_temporary_shared_secret=None,
                             _test_rsa=RSA):
    """
    Verifies a RSA-SHA1 OAuth signature.

    :see: RSA-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.3)
    :author:
        Rick Copeland <rcopeland@geek.net>
    :param signature:
        RSA-SHA1 OAuth signature.
    :param client_shared_secret:
        Client (consumer) shared secret.
    :param method:
        Base string HTTP method.
    :param url:
        Base string URL that may include a query string.
        All protocol-specific parameters will be ignored from the query string.
    :param oauth_params:
        Base string protocol-specific query parameters.
        All non-protocol parameters will be ignored.
    :param token_or_temporary_shared_secret:
        Token/temporary credentials shared secret if available.
    :returns:
        ``True`` if verified to be correct; ``False`` otherwise.
    """
    oauth_params = oauth_params or {}

    if _test_rsa is None:
        raise NotImplementedError()

    try:
        getattr(client_shared_secret, "publickey")
        key = client_shared_secret
    except AttributeError:
        key = _test_rsa.importKey(client_shared_secret)

    base_string = get_signature_base_string(method, url, oauth_params)
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


def get_plaintext_signature(client_shared_secret,
                            method, url, oauth_params=None,
                            token_or_temporary_shared_secret=None):
    """
    Calculates a PLAINTEXT signature for a base string.

    :see: PLAINTEXT (http://tools.ietf.org/html/rfc5849#section-3.4.4)
    :param client_shared_secret:
        Client (consumer) shared secret.
    :param method:
        (Not used). Base string HTTP method.
    :param url:
        (Not used). Base string URL that may include query string.
        All protocol-specific parameters will be ignored from the query string.
    :param oauth_params:
        (Not used). Base string protocol-specific query parameters.
        All non-protocol parameters will be ignored.
    :param token_or_temporary_shared_secret:
        Token/temporary credentials shared secret if available.
    :returns:
        PLAINTEXT signature.
    """
    return _get_plaintext_signature(client_shared_secret,
                                    token_or_temporary_shared_secret)


def _get_plaintext_signature(client_shared_secret,
                             token_or_temporary_shared_secret=None):
    """
    Calculates the PLAINTEXT signature.

    :param client_shared_secret:
        Client (consumer) shared secret.
    :param token_or_temporary_shared_secret:
        Token/temporary credentials shared secret if available.
    :returns:
        PLAINTEXT signature.
    """
    client_shared_secret = client_shared_secret or ""
    token_or_temporary_shared_secret = token_or_temporary_shared_secret or ""
    return "&".join([
        percent_encode(a) for a in [
            client_shared_secret, token_or_temporary_shared_secret]])


def get_signature_base_string(method, url, oauth_params):
    """
    Calculates a signature base string based on the URL, method, and
    oauth parameters.

    Any query parameter by the name "oauth_signature" will be excluded
    from the base string.

    :see: Signature base string (http://tools.ietf.org/html/rfc5849#section-3.4.1)

    :param method:
        HTTP request method.
    :param url:
        The URL. If this includes a query string, query parameters are first
        extracted and encoded as well. All protocol-specific parameters
        will be ignored from the query string.
    :param oauth_params:
        Protocol-specific parameters must be specified in this dictionary.
        All non-protocol parameters will be ignored.
    :returns:
        Base string.
    """
    allowed_methods = ("POST", "GET", "PUT", "DELETE",
                       "OPTIONS", "TRACE", "HEAD", "CONNECT",
                       "PATCH")
    method_normalized = method.upper()
    if method_normalized not in allowed_methods:
        raise InvalidHttpMethodError("Method must be one of the HTTP methods %s: got `%s` instead" % (allowed_methods, method))
    if not url:
        raise InvalidUrlError("URL must be specified: got `%r`" % (url, ))
    if not isinstance(oauth_params, dict):
        raise InvalidOAuthParametersError("Dictionary required: got `%r`" % (oauth_params, ))

    scheme, netloc, path, matrix_params, query, fragment = urlparse_normalized(url)
    query_string = _get_signature_base_string_query(query, oauth_params)
    normalized_url = urlunparse((scheme, netloc, path, matrix_params, None, None))
    return "&".join([
        percent_encode(e) for e in [
            method_normalized, normalized_url, query_string]])


def _get_signature_base_string_query(url_query_params, oauth_params):
    """
    Serializes URL query parameters and OAuth protocol parameters into a valid
    OAuth base string URI query string.

    :see: Parameter Normalization (http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2)
    :param url_query_params:
        A dictionary or string of URL query parameters. Any parameters starting
        with ``oauth_`` will be ignored.
    :param oauth_params:
        A dictionary or string of protocol-specific query parameters. Any parameter
        names that do not begin with ``oauth_`` will be excluded from the
        normalized query string. ``oauth_signature``, ``oauth_consumer_secret``,
        and ``oauth_token_secret`` are also specifically excluded.
    :returns:
        Normalized string of query parameters.
    """
    url_query_params = query_params_sanitize(url_query_params)
    oauth_params = request_protocol_params_sanitize(oauth_params)

    query_params = {}
    query_params.update(url_query_params)
    query_params.update(oauth_params)

    # Now encode the parameters, while ignoring 'oauth_signature' and obviously,
    # the secrets from the entire list of parameters.
    def allow_func(name, value):
        return name not in ("oauth_signature",
                            #"oauth_consumer_secret",    # Already filtered by protocol parameter sanitization above.
                            #"oauth_token_secret",       # Already filtered by protocol parameter sanitization above.
                            )
    query = urlencode_s(query_params, allow_func=allow_func)
    return query


def get_normalized_authorization_header_value(oauth_params,
                                              realm=None,
                                              param_delimiter=","):
    """
    Builds the Authorization header value.

    Please note that the generated authorization header value MUST be
    on a SINGLE line.

    :see: Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1
    :param oauth_params:
        Protocol-specific parameters excluding the ``realm`` parameter.
    :param realm:
        If specified, the realm is included into the Authorization header.
        The realm is never percent-encoded according to the OAuth spec.
    :param param_delimiter:
        The delimiter used to separate header value parameters.
        According to the Specification, this must be a comma ",". However,
        certain services like Yahoo! use "&" instead. Comma is default.

        See https://github.com/oauth/oauth-ruby/pull/12
    :returns:
        A properly formatted Authorization header value.
    """
    if realm:
        s = 'OAuth realm="' + to_utf8(realm) + '"' + param_delimiter
    else:
        s = 'OAuth '
    oauth_params = request_protocol_params_sanitize(oauth_params)
    normalized_param_pairs = urlencode_sl(oauth_params)
    s += param_delimiter.join([k + '="' + v + '"' for k, v in normalized_param_pairs])
    return s


def parse_authorization_header_value(header_value, param_delimiter=","):
    """
    Parses the OAuth Authorization header.

    :see: Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1
    :param header_value:
        Header value.
    :param param_delimiter:
        The delimiter used to separate header value parameters.
        According to the Specification, this must be a comma ",". However,
        certain services like Yahoo! use "&" instead. Comma is default.

        See https://github.com/oauth/oauth-ruby/pull/12
    :returns:
        Dictionary of parameter name value pairs.
    """
    d = {}
    param_list, realm = \
        _parse_authorization_header_value_l(header_value,
                                            param_delimiter=param_delimiter)
    for name, value in param_list:
        #d[name] = [value]
        # We do keep track of multiple values because they will be
        # detected by the sanitization below and flagged as an error
        # in the Authorization header value.
        if name in d:
            d[name].append(value)
        else:
            d[name] = [value]
    d = request_protocol_params_sanitize(d)
    return d, realm


def _parse_authorization_header_value_l(header_value, param_delimiter=","):
    """
    Parses the OAuth Authorization header preserving the order of the
    parameters as in the header value.

    :see: Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1
    :param header_value:
        Header value. Non protocol parameters will be ignored.
    :param param_delimiter:
        The delimiter used to separate header value parameters.
        According to the Specification, this must be a comma ",". However,
        certain services like Yahoo! use "&" instead. Comma is default.

        See https://github.com/oauth/oauth-ruby/pull/12
    :returns:
        Tuple:
        (list of parameter name value pairs in order or appearance, realm)

        realm will be ``None`` if the authorization header does not have
        a realm parameter.
    """
    # Remove the auth-scheme from the value.
    pattern = re.compile(r"(^OAuth[\s]+)", re.IGNORECASE)
    header_value = re.sub(pattern, "", to_utf8(header_value).strip(), 1)
    realm = None

    pairs = [param_pair.strip()
             for param_pair in header_value.split(param_delimiter)]
    decoded_pairs = []
    for param in pairs:
        if not param:
            if header_value.endswith(param_delimiter):
                raise InvalidAuthorizationHeaderError("Malformed `Authorization` header value -- found trailing `%r` character" % param_delimiter)
            #else:
            #    continue
        nv = param.split("=", 1)
        if len(nv) != 2:
            raise InvalidAuthorizationHeaderError("bad parameter field: `%r`" % (param, ))
        name, value = nv[0].strip(), nv[1].strip()
        if len(value) < 2:
            raise InvalidAuthorizationHeaderError("bad parameter value: `%r` -- missing quotes?" % (param, ))
        if value[0] != '"' or value[-1] != '"':
            raise InvalidAuthorizationHeaderError("missing quotes around parameter value: `%r` -- values must be quoted using (\")" % (param, ))

        # We only need to remove a single pair of quotes. Do not use str.strip('"').
        # We need to be able to detect problems with the values too.
        value = value[1:-1]
        name = percent_decode(name)
        if name.lower() == "realm":
            # "realm" is case-insensitive.
            # The realm parameter value is a simple quoted string.
            # It is neither percent-encoded nor percent-decoded in OAuth.
            # realm is ignored from the protocol parameters list.
            realm = value
        else:
            value = percent_decode(value)
        decoded_pairs.append((name, value))
    return decoded_pairs, realm
