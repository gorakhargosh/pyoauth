# -*- coding: utf-8 -*-
# OAuth utility functions.
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

    :rfc: 5849#section-3.3

    :param length:
        Length of the nonce to be returned.
        Default -1, which means the entire nonce is returned.
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

    :see:
        Resource Owner Authorization
        http://tools.ietf.org/html/rfc5849#section-2.2
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
        A string containing a positive integer representing time as follows::
    """
    return bytes(int(time.time()))


def oauth_get_hmac_sha1_signature(consumer_secret, method, url, oauth_params=None, token_secret=None):
    """
    Calculates an HMAC-SHA1 signature for a base string.

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
        Signature as follows::

            HMAC-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.2)
            ------------------------------------------------------------
            The "HMAC-SHA1" signature method uses the HMAC-SHA1 signature
            algorithm as defined in [RFC2104]:

             digest = HMAC-SHA1 (key, text)

            The HMAC-SHA1 function variables are used in following way:

            text    is set to the value of the signature base string from
                   Section 3.4.1.1.

            key     is set to the concatenated values of:

                   1.  The client shared-secret, after being encoded
                       (Section 3.6).

                   2.  An "&" character (ASCII code 38), which MUST be included
                       even when either secret is empty.

                   3.  The token shared-secret, after being encoded
                       (Section 3.6).

            digest  is used to set the value of the "oauth_signature" protocol
                   parameter, after the result octet string is base64-encoded
                   per [RFC2045], Section 6.8.
    """
    oauth_params = oauth_params or {}
    base_string = oauth_get_signature_base_string(method, url, oauth_params)
    key = _oauth_get_plaintext_signature(consumer_secret, token_secret=token_secret)
    hashed = hmac.new(key, base_string, sha1)
    return binascii.b2a_base64(hashed.digest())[:-1]


def oauth_get_rsa_sha1_signature(consumer_secret, method, url, oauth_params=None, token_secret=None):
    """
    Calculates an RSA-SHA1 OAuth signature.

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
        Signature as follows::

            RSA-SHA1 (http://tools.ietf.org/html/rfc5849#section-3.4.3)
            -----------------------------------------------------------
            The "RSA-SHA1" signature method uses the RSASSA-PKCS1-v1_5 signature
            algorithm as defined in [RFC3447], Section 8.2 (also known as
            PKCS#1), using SHA-1 as the hash function for EMSA-PKCS1-v1_5.  To
            use this method, the client MUST have established client credentials
            with the server that included its RSA public key (in a manner that is
            beyond the scope of this specification).

            The signature base string is signed using the client's RSA private
            key per [RFC3447], Section 8.2.1:

             S = RSASSA-PKCS1-V1_5-SIGN (K, M)

            Where:

            K     is set to the client's RSA private key,

            M     is set to the value of the signature base string from
                 Section 3.4.1.1, and

            S     is the result signature used to set the value of the
                 "oauth_signature" protocol parameter, after the result octet
                 string is base64-encoded per [RFC2045] section 6.8.

            The server verifies the signature per [RFC3447] section 8.2.2:

             RSASSA-PKCS1-V1_5-VERIFY ((n, e), M, S)

            Where:

            (n, e) is set to the client's RSA public key,

            M      is set to the value of the signature base string from
                  Section 3.4.1.1, and

            S      is set to the octet string value of the "oauth_signature"
                  protocol parameter received from the client.
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
        Signature as follows::

            PLAINTEXT (http://tools.ietf.org/html/rfc5849#section-3.4.4)
            ------------------------------------------------------------
            The "PLAINTEXT" method does not employ a signature algorithm.  It
            MUST be used with a transport-layer mechanism such as TLS or SSL (or
            sent over a secure channel with equivalent protections).  It does not
            utilize the signature base string or the "oauth_timestamp" and
            "oauth_nonce" parameters.

            The "oauth_signature" protocol parameter is set to the concatenated
            value of:

            1.  The client shared-secret, after being encoded (Section 3.6).

            2.  An "&" character (ASCII code 38), which MUST be included even
               when either secret is empty.

            3.  The token shared-secret, after being encoded (Section 3.6).
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
    query_parameters.

    Any query parameter by the name "oauth_signature" will be excluded
    from the base string.

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

            ...
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

    :param url_query_params:
        A dictionary of URL query parameters.
    :param oauth_params:
        A dictionary of protocol-specific query parameters. Any parameter
        names that do not begin with "oauth_" will be excluded from the
        normalized query string. 'oauth_signature' is also specially excluded.
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

    See Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1

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

    See Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1

    :param header_value:
        Header value.
    :returns:
        Dictionary of parameter name value pairs as follows::

            Authorization Header (http://tools.ietf.org/html/rfc5849#section-3.5.1)
            -----------------------------------------------------------------------
            Protocol parameters can be transmitted using the HTTP "Authorization"
            header field as defined by [RFC2617] with the auth-scheme name set to
            "OAuth" (case insensitive).

            For example:

             Authorization: OAuth realm="Example",
                oauth_consumer_key="0685bd9184jfhq22",
                oauth_token="ad180jjd733klru7",
                oauth_signature_method="HMAC-SHA1",
                oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
                oauth_timestamp="137131200",
                oauth_nonce="4572616e48616d6d65724c61686176",
                oauth_version="1.0"

            Protocol parameters SHALL be included in the "Authorization" header
            field as follows:

            1.  Parameter names and values are encoded per Parameter Encoding
               (Section 3.6).

            2.  Each parameter's name is immediately followed by an "=" character
               (ASCII code 61), a '"' character (ASCII code 34), the parameter
               value (MAY be empty), and another '"' character (ASCII code 34).

            3.  Parameters are separated by a "," character (ASCII code 44) and
               OPTIONAL linear whitespace per [RFC2617].

            4.  The OPTIONAL "realm" parameter MAY be added and interpreted per
               [RFC2617] section 1.2.

            Servers MAY indicate their support for the "OAuth" auth-scheme by
            returning the HTTP "WWW-Authenticate" response header field upon
            client requests for protected resources.  As per [RFC2617], such a
            response MAY include additional HTTP "WWW-Authenticate" header
            fields:

            For example:

             WWW-Authenticate: OAuth realm="http://server.example.com/"

            The realm parameter defines a protection realm per [RFC2617], Section
            1.2.
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

    See Authorization Header http://tools.ietf.org/html/rfc5849#section-3.5.1

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
