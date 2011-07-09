#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Cryptographic utility functions.
#
# ===================================================================
# The contents of this file are dedicated to the public domain. To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================


"""
:module: pyoauth.crypto.hash
:synopsis: Convenient hashing functions.

SHA-1 digests
-------------
.. autofunction:: sha1_digest
.. autofunction:: sha1_hex_digest
.. autofunction:: sha1_base64_digest

MD5 digests
-----------
.. autofunction:: md5_digest
.. autofunction:: md5_hex_digest

HMAC-SHA-1 digests
------------------
.. autofunction:: hmac_sha1_digest
.. autofunction:: hmac_sha1_base64_digest

"""

import hmac
from hashlib import sha1, md5
from pyoauth.types.codec import bytes_to_base64, bytes_to_hex


def sha1_digest(*inputs):
    """
    Calculates a SHA-1 digest of a variable number of inputs.

    :param inputs:
        A variable number of inputs for which the digest will be calculated.
    :returns:
        A byte string containing the SHA-1 message digest.
    """
    md = sha1()
    for i in inputs:
        md.update(i)
    return md.digest()


def sha1_hex_digest(*inputs):
    """
    Calculates hexadecimal representation of the SHA-1 digest of a variable
    number of inputs.

    :param inputs:
        A variable number of inputs for which the digest will be calculated.
    :returns:
        Hexadecimal representation of the SHA-1 digest.
    """
    return bytes_to_hex(sha1_digest(*inputs))


def sha1_base64_digest(value):
    """
    Calculates Base-64-encoded SHA-1 digest of a variable
    number of inputs.

    :param inputs:
        A variable number of inputs for which the digest will be calculated.
    :returns:
        Base-64-encoded SHA-1 digest.
    """
    return bytes_to_base64(sha1_digest(value))


def md5_digest(*inputs):
    """
    Calculates a MD5 digest of a variable number of inputs.

    :param inputs:
        A variable number of inputs for which the digest will be calculated.
    :returns:
        A byte string containing the MD5 message digest.
    """
    md = md5()
    for i in inputs:
        md.update(i)
    return md.digest()


def md5_hex_digest(*inputs):
    """
    Calculates hexadecimal representation of the MD5 digest of a variable
    number of inputs.

    :param inputs:
        A variable number of inputs for which the digest will be calculated.
    :returns:
        Hexadecimal representation of the MD5 digest.
    """
    return bytes_to_hex(md5_digest(*inputs))


def hmac_sha1_digest(key, data):
    """
    Calculates a HMAC SHA-1 digest.

    :param key:
        The key for the digest.
    :param data:
        The data for which the digest will be calculted.
    :returns:
        HMAC SHA-1 Digest.
    """
    return hmac.new(key, data, sha1).digest()


def hmac_sha1_base64_digest(key, data):
    """
    Calculates a base64-encoded HMAC SHA-1 signature.

    :param key:
        The key for the signature.
    :param data:
        The data to be signed.
    :returns:
        Base64-encoded HMAC SHA-1 signature.
    """
    return bytes_to_base64(hmac_sha1_digest(key, data))

