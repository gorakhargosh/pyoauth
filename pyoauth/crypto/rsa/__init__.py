#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Released into public domain.

"""
:module: pyoauth.crypto.rsa
:synopsis: Factory functions for RSA public and private keys.

Functions
---------
.. autofunction:: create_private_key
.. autofunction:: create_public_key
"""

from pyoauth.crypto.codec import private_key_pem_decode, public_key_pem_decode

try:
    from pyoauth.crypto.rsa.pycrypto import PrivateKey, PublicKey
except ImportError:
    PrivateKey = None
    PublicKey = None
    raise NotImplementedError("RSA implementation not found.")


def create_private_key(encoded_key, encoding="PEM"):
    encoding = encoding.upper()
    if encoding == "PEM":
        key_info = private_key_pem_decode(encoded_key)
    else:
        raise NotImplementedError("Key encoding not supported.")
    key = PrivateKey(key_info, encoded_key, encoding)
    return key


def create_public_key(encoded_key, encoding="PEM"):
    encoding = encoding.upper()
    if encoding == "PEM":
        key_info = public_key_pem_decode(encoded_key)
    else:
        raise NotImplementedError("Key encoding not supported.")
    key = PublicKey(key_info, encoded_key, encoding)
    return key
