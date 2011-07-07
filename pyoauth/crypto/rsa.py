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
#from pyoauth.crypto.RSAKey import factory

from pyoauth.types.number import long_to_bytes
from pyoauth.types.codec import base64_encode, base64_decode
from pyoauth.crypto.hash import sha1_digest
from pyoauth.crypto.codec import public_key_pem_decode, private_key_pem_decode
from Crypto.PublicKey import RSA


def pkcs1_v1_5_encode(key, data):
    """
    Encodes a key using PKCS1's emsa-pkcs1-v1_5 encoding.

    Adapted from paramiko.

    :author:
        Rick Copeland <rcopeland@geek.net>

    :param key:
        RSA Key.
    :param data:
        Data
    :returns:
        A blob of data as large as the key's N, using PKCS1's
        "emsa-pkcs1-v1_5" encoding.
    """
    SHA1_DIGESTINFO = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
    size = len(long_to_bytes(key.n))
    filler = '\xff' * (size - len(SHA1_DIGESTINFO) - len(data) - 3)
    return '\x00\x01' + filler + '\x00' + SHA1_DIGESTINFO + data


class PrivateKey(object):
    def __init__(self, pem_key):
        """
        RSAPrivateKey ::= SEQUENCE {
          version Version,
          modulus INTEGER, -- n
          publicExponent INTEGER, -- e
          privateExponent INTEGER, -- d
          prime1 INTEGER, -- p
          prime2 INTEGER, -- q
          exponent1 INTEGER, -- d mod (p-1)
          exponent2 INTEGER, -- d mod (q-1)
          coefficient INTEGER -- (inverse of q) mod p }

        """
        ki = private_key_pem_decode(pem_key)
        ki_tuple = (
            ki["modulus"],
            ki["publicExponent"],
            ki["privateExponent"],
            ki["prime1"],
            ki["prime2"],
            #ki["exponent1"],
            #ki["exponent2"],
            #ki["coefficient"],
        )
        self._key = RSA.construct(ki_tuple)

    def sign(self, data, encoder=pkcs1_v1_5_encode):
        signature = self._key.sign(
            encoder(
                self._key,
                sha1_digest(data)
            ), ""
        )[0]
        signature_bytes = long_to_bytes(signature)
        return base64_encode(signature_bytes)

    def verify(self, signature, data, encoder=pkcs1_v1_5_encode):
        pass


class PublicKey(object):
    def __init__(self, pem_key):
        self._key_info = public_key_pem_decode(pem_key)
        self._rsa = RSA.construct((0, ))

    def sign(self, data, encoder=pkcs1_v1_5_encode):
        pass

    def verify(self, signature, data, encoder=pkcs1_v1_5_encode):
        pass


def pkcs1_v1_5_sign(private_pem_key, data):
    """
    Signs a base string using your RSA private key.

    :param private_pem_key:
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

    :param data:
        Data byte string.
    :returns:
        Signature.
    """
    #private_key = factory.parsePrivateKey(private_key)
    #signed = private_key.hashAndSign(base_string)
    #return base64_encode(signed)
    private_key = PrivateKey(private_pem_key)
    return private_key.sign(data)


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
    decoded_signature = base64_decode(signature)
    return False
    #cert_parser = X509()
    #cert_parser.parse(public_certificate)
    #public_key = cert_parser.publicKey

    ##public_key = factory.parsePEMKey(public_certificate, public=True)
    #return public_key.hashAndVerify(decoded_signature, base_string)
