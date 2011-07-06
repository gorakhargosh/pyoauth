#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Placed under public domain.

"""
:module: pyoauth.crypto.rsa
:synopsis: RSA convenience wrapper functions.

Functions
---------
.. autofunction:: sign
.. autofunction:: verify
"""

#import sys
#import os
#
#PARENT_DIR_PATH = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
#sys.path[0:0] = [
#    os.path.join(PARENT_DIR_PATH, "tlslite"),
#]

import binascii
from base64 import b64decode
from pyoauth.crypto import keyfactory
from pyoauth.crypto.X509 import X509


def sign(private_key, base_string):
    """
    Signs a base string using your RSA private key.

    :param private_key:
        Private key. Example private key from the OAuth test cases::

            -----BEGIN PRIVATE KEY-----
            MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
            A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
            7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
            hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
            X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
            uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
            rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
            zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
            qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
            WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
            cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
            3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
            AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
            Lw03eHTNQghS0A==
            -----END PRIVATE KEY-----

    :param base_string:
        The OAuth base string.
    :returns:
        Signature.
    """
    private_key = keyfactory.parsePrivateKey(private_key)
    signed = private_key.hashAndSign(base_string)
    return binascii.b2a_base64(signed)[:-1]


def verify(public_certificate, signature, base_string):
    """
    Verifies the signature against a given base string using your
    public key.

    :param public_certificate:
        Public certificate. Example certificate from the OAuth test cases::

            -----BEGIN CERTIFICATE-----
            MIIBpjCCAQ+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAZMRcwFQYDVQQDDA5UZXN0
            IFByaW5jaXBhbDAeFw03MDAxMDEwODAwMDBaFw0zODEyMzEwODAwMDBaMBkxFzAV
            BgNVBAMMDlRlc3QgUHJpbmNpcGFsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
            gQC0YjCwIfYoprq/FQO6lb3asXrxLlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlY
            zypSRjVxwxrsuRcP3e641SdASwfrmzyvIgP08N4S0IFzEURkV1wp/IpH7kH41Etb
            mUmrXSwfNZsnQRE5SYSOhh+LcK2wyQkdgcMv11l4KoBkcwIDAQABMA0GCSqGSIb3
            DQEBBQUAA4GBAGZLPEuJ5SiJ2ryq+CmEGOXfvlTtEL2nuGtr9PewxkgnOjZpUy+d
            4TvuXJbNQc8f4AMWL/tO9w0Fk80rWKp9ea8/df4qMq5qlFWlx6yOLQxumNOmECKb
            WpkUQDIDJEoFUzKMVuJf4KO/FJ345+BNLGgbJ6WujreoM1X/gYfdnJ/J
            -----END CERTIFICATE-----

    :param base_string:
        The OAuth base string.
    :returns:
        ``True`` if signature matches; ``False`` if verification fails.
    """
    decoded_signature = b64decode(signature)

    cert_parser = X509()
    cert_parser.parse(public_certificate)
    public_key = cert_parser.publicKey

    #public_key = keyfactory.parsePEMKey(public_certificate, public=True)
    return public_key.hashAndVerify(decoded_signature, base_string)
