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

from pyoauth.types.number import long_to_bytes, bytes_to_long
from pyoauth.crypto.codec import public_key_pem_decode, private_key_pem_decode
from Crypto.PublicKey import RSA


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
    private_key = PrivateKey(private_pem_key)
    return private_key.sign(data)


def pkcs1_v1_5_verify(public_key_or_certificate, signature_bytes, data):
    """
    Verifies the signature against a given base string using your
    public key.

    :param public_key_or_certificate:
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

    :param data:
        The data to be signed.
    :returns:
        ``True`` if signature matches; ``False`` if verification fails.
    """
    public_key = PublicKey(public_key_or_certificate)
    return public_key.verify(signature_bytes, data)


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


class Key(object):
    @property
    def key(self):
        raise NotImplementedError("This property must be overridden by the subclass.")


    def sign(self, digest, encoder=pkcs1_v1_5_encode):
        """
        Signs a digest with the key.

        :param digest:
            The SHA-1 digest of the data.
        :param encoder:
            The encoding method to use. Default EMSA-PKCS1-v1.5
        :returns:
            Signature byte string.
        """
        signature = self.key.sign(encoder(self.key, digest), "")[0]
        signature_bytes = long_to_bytes(signature)
        return signature_bytes


    def verify(self, signature_bytes, digest, encoder=pkcs1_v1_5_encode):
        """
        Verifies a signature against that computed by signing the provided
        data.

        :param signature_bytes:
            The signature raw byte string.
        :param digest:
            The SHA-1 digest of the data.
        :param encoder:
            The encoding method to use. Default EMSA-PKCS1-v1.5
        :returns:
            ``True`` if the signature matches; ``False`` otherwise.
        """
        signature_long = bytes_to_long(signature_bytes)
        digest = encoder(self.key, digest)
        public_key = self.key.publickey()
        return public_key.verify(digest, (signature_long,))


class PrivateKey(Key):
    """
    Represents a RSA private key.

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

    :param pem_key:
        The PEM-encoded key string.
    """
    def __init__(self, pem_key):
        """
        """
        key_info = private_key_pem_decode(pem_key)
        key_info_args = (
            key_info["modulus"],
            key_info["publicExponent"],
            key_info["privateExponent"],
            key_info["prime1"],
            key_info["prime2"],
            #key_info["exponent1"],
            #key_info["exponent2"],
            #key_info["coefficient"],
        )
        self._key = RSA.construct(key_info_args)

    @property
    def key(self):
        return self._key


class PublicKey(Key):
    """
    Represents a RSA public key.

    :param pem_key:
        The PEM-encoded key string.
    """
    def __init__(self, pem_key):
        key_info = public_key_pem_decode(pem_key)
        key_info_args = (
            key_info["modulus"],
            key_info["exponent"],
        )
        self._key = RSA.construct(key_info_args)

    @property
    def key(self):
        return self._key
