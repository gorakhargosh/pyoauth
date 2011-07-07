#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Placed into public domain.

"""
:module: pyoauth.crypto.codec
:synopsis: Codecs to encode and decode keys and certificates in various formats.

Functions:
----------
.. autofunction:: pem_public_key_decode
.. autofunction:: pem_private_key_decode

"""

from pyoauth.crypto.codec.pem import \
    CERT_PEM_HEADER, PUBLIC_KEY_PEM_HEADER, \
    PRIVATE_KEY_PEM_HEADER, RSA_PRIVATE_KEY_PEM_HEADER
from pyoauth.crypto.codec.pem.x509 import X509Certificate
from pyoauth.crypto.codec.pem.rsa import RSAPrivateKey, RSAPublicKey


def public_key_pem_decode(pem_key):
    """
    Decodes a PEM-encoded public key/X.509 certificate string into internal representation.

    :param pem_key:
        The PEM-encoded key. Must be one of:
        1. RSA public key.
        2. X.509 certificate.
    :returns:
        A dictionary of key information.
    """
    pem_key = pem_key.strip()
    if pem_key.startswith(CERT_PEM_HEADER):
        key = X509Certificate(pem_key).public_key
    elif pem_key.startswith(PUBLIC_KEY_PEM_HEADER):
        key = RSAPublicKey(pem_key).public_key
    else:
        raise NotImplementedError("Only PEM-encoded X.509 certificates and public RSA keys can be read.")
    return key


def private_key_pem_decode(pem_key):
    """
    Decodes a PEM-encoded private key string into internal representation.

    :param pem_key:
        The PEM-encoded RSA private key.
    :returns:
        A dictionary of key information.
    """
    pem_key = pem_key.strip()
    if pem_key.startswith(PRIVATE_KEY_PEM_HEADER) or pem_key.startswith(RSA_PRIVATE_KEY_PEM_HEADER):
        key = RSAPrivateKey(pem_key).private_key
    else:
        raise NotImplementedError("Only PEM-encoded private RSA keys can be read.")
    return key
