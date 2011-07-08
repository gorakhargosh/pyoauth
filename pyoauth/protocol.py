#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Protocol-specific utility functions.
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
:module: pyoauth.protocol
:synopsis: Protocol-specific utility functions.

Nonce, verification code, and timestamp
---------------------------------------
.. autofunction:: generate_nonce
.. autofunction:: generate_verification_code
.. autofunction:: generate_timestamp
.. autofunction:: generate_client_secret

OAuth Signature and Base String
-------------------------------
.. autofunction:: generate_hmac_sha1_signature
.. autofunction:: generate_rsa_sha1_signature
.. autofunction:: verify_rsa_sha1_signature
.. autofunction:: generate_plaintext_signature
.. autofunction:: generate_signature_base_string

Authorization Header
--------------------
.. autofunction:: generate_normalized_authorization_header_value
.. autofunction:: parse_authorization_header_value

"""

import time
import re
from pyoauth.types.codec import base64_encode, base64_decode

try:
    # Python 3.
    from urllib.parse import urlunparse
except ImportError:
    # Python 2.5+
    from urlparse import urlunparse

from pyoauth.types.unicode import unicode_to_utf8
from pyoauth.types import bytes
from pyoauth.error import InvalidHttpMethodError, \
    InvalidUrlError, \
    InvalidOAuthParametersError, \
    InvalidAuthorizationHeaderError
from pyoauth.url import percent_encode, percent_decode, \
    urlencode_sl, urlencode_s, urlparse_normalized, \
    request_protocol_params_sanitize, query_params_sanitize
from pyoauth.crypto.hash import hmac_sha1_base64_digest, sha1_digest
from pyoauth.crypto.random import \
    generate_random_uint_string, \
    generate_random_hex_string


def generate_nonce(bit_strength=64, base=10):
    """
    Generates a random ASCII-encoded unsigned integral number in decimal
    hexadecimal, or base-64 representation.

    :see: Nonce and Timestamp (http://tools.ietf.org/html/rfc5849#section-3.3)
    :param bit_strength:
        Bit strength. Default 64.
    :param base:
        One of:
            1. 10 (default)
            2. 16
            3. 64
    :returns:
        A string representation of a randomly-generated ASCII-encoded
        hexadecimal/decimal/base64-representation unsigned integral number
        based on the bit strength specified.
    """
    return generate_random_uint_string(bit_strength=bit_strength, base=base)


def generate_client_secret(bit_strength=144):
    """
    Generates a random Base-64-encoded client secret to assign to a
    registered client application.

    Consumer secrets are base64-encoded but not URL-safe. This is done to
    force the user into properly percent-encoding values according to the
    OAuth percent-encoding rules.

    :param bit_strength:
        Bit strength. 144 is default.
    :returns:
        A base-64-encoded random unsigned-integral consumer secret based
        on the bit strength specified.
    """
    return generate_random_uint_string(bit_strength=bit_strength, base=64)


def generate_verification_code(length=8):
    """
    Generates an OAuth verification code.

    The verification code will be displayed by the server if a callback URL
    is not provided by the client. The resource owner (the end-user) may
    need to enter this verification code on a limited device. Therefore,
    we limit the length of this code to 8 characters to keep it suitable
    for manual entry.

    :see:
        Resource Owner Authorization
        (http://tools.ietf.org/html/rfc5849#section-2.2)
    :param length:
        Length of the verification code to be returned. Default 8.
        The length MUST be a positive even number.
    :returns:
        A string representation of a randomly-generated hexadecimal OAuth
        verification code.
    """
    return generate_random_hex_string(length)


def generate_timestamp():
    """
    Generates an OAuth timestamp.

    :see:
        Nonce and Timestamp (http://tools.ietf.org/html/rfc5849#section-3.3)
    :returns:
        A string containing a positive integer representing time.
    """
    return bytes(int(time.time()))


def generate_hmac_sha1_signature(client_shared_secret,
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
    base_string = generate_signature_base_string(method, url, oauth_params)
    key = _generate_plaintext_signature(client_shared_secret,
                                   token_or_temporary_shared_secret)
    return hmac_sha1_base64_digest(key, base_string)


def generate_rsa_sha1_signature(client_private_key,
                                method, url, oauth_params=None,
                                *args, **kwargs):
    """
    Calculates an RSA-SHA1 OAuth signature.

    :see: RSA-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.3)

    :param client_private_key:
        PEM-encoded RSA private key.
    :param method:
        Base string HTTP method.
    :param url:
        Base string URL that may include a query string.
        All protocol-specific paramters will be ignored from the query string.
    :param oauth_params:
        Base string protocol-specific query parameters.
        All non-protocol parameters will be ignored.
    :returns:
        RSA-SHA1 signature.
    """
    from pyoauth.crypto.rsa import create_private_key

    oauth_params = oauth_params or {}
    base_string = generate_signature_base_string(method, url, oauth_params)

    key = create_private_key(client_private_key)
    return base64_encode(key.pkcs1_v1_5_sign(sha1_digest(base_string)))


def verify_rsa_sha1_signature(client_certificate,
                              signature,
                              method, url, oauth_params=None,
                              *args, **kwargs):
    """
    Verifies a RSA-SHA1 OAuth signature.

    :see: RSA-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.3)

    :param client_certificate:
        PEM-encoded X.509 certificate or RSA public key.
    :param signature:
        RSA-SHA1 OAuth signature.
    :param method:
        Base string HTTP method.
    :param url:
        Base string URL that may include a query string.
        All protocol-specific parameters will be ignored from the query string.
    :param oauth_params:
        Base string protocol-specific query parameters.
        All non-protocol parameters will be ignored.
    :returns:
        ``True`` if verified to be correct; ``False`` otherwise.
    """
    from pyoauth.crypto.rsa import create_public_key

    oauth_params = oauth_params or {}
    base_string = generate_signature_base_string(method, url, oauth_params)

    key = create_public_key(client_certificate)
    return key.pkcs1_v1_5_verify(sha1_digest(base_string),
                                 base64_decode(signature))


def generate_plaintext_signature(client_shared_secret,
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
    return _generate_plaintext_signature(client_shared_secret,
                                    token_or_temporary_shared_secret)


def _generate_plaintext_signature(client_shared_secret,
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


def generate_signature_base_string(method, url, oauth_params):
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
    query_string = _generate_signature_base_string_query(query, oauth_params)
    normalized_url = urlunparse((scheme, netloc, path, matrix_params, None, None))
    return "&".join([
        percent_encode(e) for e in [
            method_normalized, normalized_url, query_string]])


def _generate_signature_base_string_query(url_query_params, oauth_params):
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


def generate_normalized_authorization_header_value(oauth_params,
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
        s = 'OAuth realm="' + unicode_to_utf8(realm) + '"' + param_delimiter
    else:
        s = 'OAuth '
    oauth_params = request_protocol_params_sanitize(oauth_params)
    normalized_param_pairs = urlencode_sl(oauth_params)
    s += param_delimiter.join([k + '="' + v + '"' for k, v in normalized_param_pairs])
    return s


def parse_authorization_header_value(header_value,
                                     param_delimiter=",",
                                     strict=True):
    """
    Parses the OAuth Authorization header.

    :see: Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1
    :param header_value:
        Header value.
    :param param_delimiter:
        The delimiter used to separate header value parameters.
        According to the Specification, this must be a comma ",". However,
        certain services like Yahoo! use "&" instead. Comma is default.

        If you want to use another delimiter character, the ``strict``
        argument to this function must also be set to ``False``.
        See https://github.com/oauth/oauth-ruby/pull/12
    :param strict:
        When ``True``, more strict checking will be performed.
        The authorization header value must be on a single line.
        The param delimiter MUST be a comma.
        When ``False``, the parser is a bit lenient.
    :returns:
        Dictionary of parameter name value pairs.
    """
    d = {}
    param_list, realm = \
        _parse_authorization_header_value_l(header_value,
                                            param_delimiter=param_delimiter,
                                            strict=strict)
    for name, value in param_list:
        # We do keep track of multiple values because they will be
        # detected by the sanitization below and flagged as an error
        # in the Authorization header value.
        #
        #d[name] = [value]
        if name in d:
            d[name].append(value)
        else:
            d[name] = [value]
    d = request_protocol_params_sanitize(d)
    return d, realm


def _parse_authorization_header_value_l(header_value,
                                        param_delimiter=",",
                                        strict=True):
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

        If you want to use another delimiter character, the ``strict``
        argument to this function must also be set to ``False``.
        See https://github.com/oauth/oauth-ruby/pull/12
    :param strict:
        When ``True`` (default), strict checking will be performed.
        The authorization header value must be on a single line.
        The param delimiter MUST be a comma.
        When ``False``, the parser is a bit lenient.
    :returns:
        Tuple:
        (list of parameter name value pairs in order or appearance, realm)

        realm will be ``None`` if the authorization header does not have
        a realm parameter.
    """
    # Remove the auth-scheme from the value.
    header_value = unicode_to_utf8(header_value)
    if strict:
        if "\n" in header_value:
            raise ValueError("Header value must be on a single line: got `%r`" % (header_value, ))
        if param_delimiter != ",":
            raise ValueError("The param delimiter must be a comma: got `%r`" % (param_delimiter, ))

    pattern = re.compile(r"(^OAuth[\s]+)", re.IGNORECASE)
    header_value = re.sub(pattern, "", header_value.strip(), 1)
    realm = None

    pairs = [param_pair.strip()
             for param_pair in header_value.split(param_delimiter)]
    decoded_pairs = []
    for param in pairs:
        if not param:
            if header_value.endswith(param_delimiter):
                raise InvalidAuthorizationHeaderError("Malformed `Authorization` header value -- found trailing `%r` character" % param_delimiter)
            else:
                # Blank param?
                continue
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
