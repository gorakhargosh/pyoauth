#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
:module: pyoauth.crypto.rsa
:synopsis: Factory functions for RSA public and private keys.

Encoded key parsing
-------------------
.. autofunction:: parse_private_key
.. autofunction:: parse_public_key
"""

from pyoauth.crypto.codec import private_key_pem_decode, public_key_pem_decode

try:
    from pyoauth.crypto.rsa.pycrypto import PrivateKey, PublicKey
except ImportError:
    PrivateKey = None
    PublicKey = None
    raise NotImplementedError("RSA implementation not found.")


def parse_private_key(encoded_key, encoding="PEM"):
    encoding = encoding.upper()
    if encoding == "PEM":
        key_info = private_key_pem_decode(encoded_key)
    else:
        raise NotImplementedError("Key encoding not supported.")
    key = PrivateKey(key_info, encoded_key, encoding)
    return key


def parse_public_key(encoded_key, encoding="PEM"):
    encoding = encoding.upper()
    if encoding == "PEM":
        key_info = public_key_pem_decode(encoded_key)
    else:
        raise NotImplementedError("Key encoding not supported.")
    key = PublicKey(key_info, encoded_key, encoding)
    return key
