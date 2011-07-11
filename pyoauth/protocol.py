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

OAuth signature and base string
-------------------------------
.. autofunction:: generate_hmac_sha1_signature
.. autofunction:: generate_rsa_sha1_signature
.. autofunction:: verify_rsa_sha1_signature
.. autofunction:: generate_plaintext_signature
.. autofunction:: generate_base_string

Authorization HTTP header creation and parsing
----------------------------------------------
.. autofunction:: generate_authorization_header
.. autofunction:: parse_authorization_header

"""

import time
import re
try:
    # Python 3.
    from urllib.parse import urlunparse
except ImportError:
    # Python 2.5+
    from urlparse import urlunparse

from mom.codec import base64_encode, base64_decode
from mom.builtins import unicode_to_utf8, bytes
from mom.security.hash import hmac_sha1_base64_digest, sha1_digest
from mom.security.random import \
    generate_random_uint_string, \
    generate_random_hex_string

from pyoauth.error import InvalidHttpMethodError, \
    InvalidUrlError, \
    InvalidOAuthParametersError, \
    InvalidAuthorizationHeaderError
from pyoauth.url import percent_encode, percent_decode, \
    urlencode_sl, urlencode_s, urlparse_normalized, \
    request_query_remove_non_oauth, query_remove_oauth


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
    force the user into properly percent-encoding the secrets before generating
    OAuth signatures for base strings.

    As a side note, Google OAuth generates client secrets with similar encoding
    and this problem is a little hard to trace for the client, but it is a
    problem that should be fixed by the client after all. OAuth protocol
    version 1.0a requires percent-encoding the secrets before generating
    signatures. (See, :func:``generate_plaintext_signature``).

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


def generate_hmac_sha1_signature(base_string,
                                 client_shared_secret,
                                 token_shared_secret=None):
    """
    Calculates an HMAC-SHA1 signature for a base string.

    :see: HMAC-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.2)
    :param base_string:
        Base string.
    :param client_shared_secret:
        Client (consumer) shared secret.
    :param token_shared_secret:
        Token/temporary credentials shared secret if available.
    :returns:
        HMAC-SHA1 signature.
    """
    key = _generate_plaintext_signature(client_shared_secret,
                                        token_shared_secret)
    return hmac_sha1_base64_digest(key, base_string)


def verify_hmac_sha1_signature(signature,
                               base_string,
                               client_shared_secret,
                               token_shared_secret=None,
                               debug=False):
    """
    Verifies an HMAC-SHA1 signature for a base string.

    :see: HMAC-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.2)
    :param signature:
        The signature to verify.
    :param base_string:
        The base string.
    :param client_shared_secret:
        Client (consumer) shared secret.
    :param token_shared_secret:
        Token/temporary credentials shared secret if available.
    :param debug:
        Default ``False``.

        ``True`` to turn on debugging mode, which attempts to find out
        why signature verification fails, if it does; ``False`` otherwise.
    :returns:
        A tuple of
            (whether signature matches (boolean),
            error message (None if it succeeded)).
    """
    key = _generate_plaintext_signature(client_shared_secret,
                                        token_shared_secret)
    check_ok = (signature == hmac_sha1_base64_digest(key, base_string))
    if check_ok:
        err = None
    else:
        err = "Invalid signature"

    if not check_ok and debug:
        # Try to find out why it didn't match.
        # We need to help the poor human souls on the other
        # side of this mess who are trying to debug their OAuth clients.
        # This is not going to detect 100% of the cases, because it is
        # too easy to screw up on the client side. Anything could be wrong.
        # We're just trying to find out some common problems.

        # Assume correct base string but detect incorrect signature encoding.
        key = _generate_plaintext_signature(client_shared_secret,
                                            token_shared_secret,
                                            _percent_encode=False)
        if signature == hmac_sha1_base64_digest(key, base_string):
            return check_ok, "Invalid signature: signature elements " \
                       "are not percent-encoded properly"

        # Assume correct base string but detect missing ampersands in signature.
        if client_shared_secret and not token_shared_secret:
            key = percent_encode(client_shared_secret) + "&"
            if signature == hmac_sha1_base64_digest(key, base_string):
                return check_ok, "Invalid signature: missing ampersand `&` " \
                           "after client shared secret in signature"
        elif not client_shared_secret and token_shared_secret:
            key = "&" + percent_encode(token_shared_secret)
            if signature == hmac_sha1_base64_digest(key, base_string):
                return check_ok, "Invalid signature: missing ampersand `&` "\
                           "before token secret in signature"
        elif not client_shared_secret and not token_shared_secret:
            key = "&"
            if signature == hmac_sha1_base64_digest(key, base_string):
                return check_ok, "Invalid signature: missing ampersand `&` "\
                           "without secrets in signature"
        elif client_shared_secret and token_shared_secret:
            key = percent_encode(client_shared_secret) + \
                  "&" + percent_encode(token_shared_secret)
            if signature == hmac_sha1_base64_digest(key, base_string):
                return check_ok, "Invalid signature: missing ampersand `&` "\
                           "between signature secrets"

        # Assume incorrect base string
        return check_ok, "Invalid signature: check base string?"

    return check_ok, err


def generate_rsa_sha1_signature(base_string,
                                client_private_key,
                                *args, **kwargs):
    """
    Calculates an RSA-SHA1 OAuth signature.

    :see: RSA-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.3)

    :param base_string:
        Base string.
    :param client_private_key:
        PEM-encoded RSA private key.
    :returns:
        RSA-SHA1 signature.
    """
    from mom.security.rsa import parse_private_key

    key = parse_private_key(client_private_key)
    return base64_encode(key.pkcs1_v1_5_sign(sha1_digest(base_string)))


def verify_rsa_sha1_signature(signature,
                              base_string,
                              client_certificate,
                              *args, **kwargs):
    """
    Verifies a RSA-SHA1 OAuth signature.

    :see: RSA-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.3)

    :param base_string:
        Base string.
    :param signature:
        RSA-SHA1 OAuth signature.
    :param client_certificate:
        PEM-encoded X.509 certificate or RSA public key.
    :returns:
        ``True`` if verified to be correct; ``False`` otherwise.
    """
    from mom.security.rsa import parse_public_key

    key = parse_public_key(client_certificate)
    return key.pkcs1_v1_5_verify(sha1_digest(base_string),
                                 base64_decode(signature))


def generate_plaintext_signature(base_string,
                                 client_shared_secret,
                                 token_shared_secret=None):
    """
    Calculates a PLAINTEXT signature for a base string.

    :see: PLAINTEXT (http://tools.ietf.org/html/rfc5849#section-3.4.4)
    :param base_string:
        (Unused) base string.
    :param client_shared_secret:
        Client (consumer) shared secret.
    :param token_shared_secret:
        Token/temporary credentials shared secret if available.
    :returns:
        PLAINTEXT signature.
    """
    return _generate_plaintext_signature(client_shared_secret,
                                    token_shared_secret)


def _generate_plaintext_signature(client_shared_secret,
                                  token_shared_secret=None,
                                  _percent_encode=True):
    """
    Calculates the PLAINTEXT signature.

    :param client_shared_secret:
        Client (consumer) shared secret.
    :param token_shared_secret:
        Token/temporary credentials shared secret if available.
    :param _percent_encode:
        (DEBUG)

        Must be ``True`` to be compatible with OAuth 1.0 RFC5849 & OAuth 1.0a;
        We have added this parameter to enable better debugging by the
        signature verification routines. If this is set to ``False``, the
        signature elements will not be percent-encoded before the plaintext
        signature is generated.
    :returns:
        PLAINTEXT signature.
    """
    client_shared_secret = client_shared_secret or ""
    token_shared_secret = token_shared_secret or ""
    if _percent_encode:
        return "&".join([percent_encode(a) for a in [
                client_shared_secret, token_shared_secret]])
    else:
        # User clients can forget to do this and this has been fixed
        # by OAuth 1.0a, so we use this piece of code to detect whether
        # the user's OAuth client library complies with the specification
        # when in debugging mode.
        return "&".join([client_shared_secret,
                         token_shared_secret])


def generate_base_string(method, url, oauth_params):
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
        raise InvalidHttpMethodError(
            "Method must be one of the HTTP methods %s: "\
            "got `%s` instead" % (allowed_methods, method))
    if not url:
        raise InvalidUrlError("URL must be specified: got `%r`" % (url, ))
    if not isinstance(oauth_params, dict):
        raise InvalidOAuthParametersError(
            "Dictionary required: got `%r`" % (oauth_params, ))

    scheme, netloc, path, matrix_params, query, _ = urlparse_normalized(url)
    query_string = generate_base_string_query(query, oauth_params)
    normalized_url = urlunparse((
        scheme,
        netloc,
        path,
        matrix_params,
        None,
        None
    ))
    return "&".join([
        percent_encode(e) for e in [
            method_normalized, normalized_url, query_string]])


def generate_base_string_query(url_query, oauth_params):
    """
    Serializes URL query parameters and OAuth protocol parameters into a valid
    OAuth base string URI query string.

    :see: Parameter Normalization (http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2)
    :param url_query:
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
    url_query = query_remove_oauth(url_query)
    oauth_params = request_query_remove_non_oauth(oauth_params)

    query_d = {}
    query_d.update(url_query)
    query_d.update(oauth_params)

    # Now encode the parameters, while ignoring 'oauth_signature' and obviously,
    # the secrets from the entire list of parameters.
    def allow_func(name, _):
        """Allows only protocol parameters that must be included into
        the signature.

        :param name:
            The name of the parameter.
        :returns:
            ``True`` if the parameter can be included; ``False`` otherwise.
        """
        return name not in ("oauth_signature",
                            #"oauth_consumer_secret", # Sanitized above.
                            #"oauth_token_secret",    # Sanitized above.
                            )
    query = urlencode_s(query_d, allow_func=allow_func)
    return query


def generate_authorization_header(oauth_params,
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
        value = 'OAuth realm="' + unicode_to_utf8(realm) + '"' + param_delimiter
    else:
        value = 'OAuth '
    oauth_params = request_query_remove_non_oauth(oauth_params)
    normalized_param_pairs = urlencode_sl(oauth_params)
    value += param_delimiter.join([k + '="' + v + '"'
                               for k, v in normalized_param_pairs])
    return value


def parse_authorization_header(header_value,
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
    params = {}
    param_list, realm = \
        parse_authorization_header_l(header_value,
                                            param_delimiter=param_delimiter,
                                            strict=strict)
    for name, value in param_list:
        # We do keep track of multiple values because they will be
        # detected by the sanitization below and flagged as an error
        # in the Authorization header value.
        #
        #params[name] = [value]
        if name in params:
            params[name].append(value)
        else:
            params[name] = [value]
    params = request_query_remove_non_oauth(params)
    return params, realm


def parse_authorization_header_l(header_value,
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
            raise ValueError("Header value must be on a single line: got `%r`" \
                             % (header_value, ))
        if param_delimiter != ",":
            raise ValueError("The param delimiter must be a comma: got `%r`" \
                             % (param_delimiter, ))

    pattern = re.compile(r"(^OAuth[\s]+)", re.IGNORECASE)
    header_value = re.sub(pattern, "", header_value.strip(), 1)
    realm = None

    pairs = [param_pair.strip()
             for param_pair in header_value.split(param_delimiter)]
    decoded_pairs = []
    for param in pairs:
        if not param:
            if header_value.endswith(param_delimiter):
                raise InvalidAuthorizationHeaderError(
                    "Malformed `Authorization` header value -- "\
                    "found trailing `%r` character" % param_delimiter)
            else:
                # Blank param?
                continue
        name_value = param.split("=", 1)
        if len(name_value) != 2:
            raise InvalidAuthorizationHeaderError("bad parameter field: `%r`" \
                                                  % (param, ))
        name, value = name_value[0].strip(), name_value[1].strip()
        if len(value) < 2:
            raise InvalidAuthorizationHeaderError(
                "bad parameter value: `%r` -- missing quotes?" % (param, ))
        if value[0] != '"' or value[-1] != '"':
            raise InvalidAuthorizationHeaderError(
                "missing quotes around parameter value: `%r` "\
                "-- values must be quoted using (\")" % (param, ))

        # We only need to remove a single pair of quotes.
        # Do not use str.strip('"').
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
