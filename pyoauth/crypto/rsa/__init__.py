#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Released into public domain.

"""
:module: pyoauth.crypto.rsa
:synopsis: RSA convenience wrapper functions.

Functions
---------
.. autofunction:: sign
.. autofunction:: verify
"""
try:
    from pyoauth.crypto.rsa.pycrypto import PrivateKey, PublicKey
except ImportError:
    raise NotImplementedError("RSA implementation not found.")

def create_private_key(encoded_key, encoding="PEM"):
    key = PrivateKey(encoded_key, encoding=encoding)
    return key

def create_public_key(encoded_key, encoding="PEM"):
    key = PublicKey(encoded_key, encoding=encoding)
    return key
