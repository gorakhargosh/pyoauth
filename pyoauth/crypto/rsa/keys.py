#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pyoauth.types.number import long_to_bytes, bytes_to_long


def pkcs1_v1_5_encode(key_size, data):
    """
    Encodes a key using PKCS1's emsa-pkcs1-v1_5 encoding.

    Adapted from paramiko.

    :author:
        Rick Copeland <rcopeland@geek.net>

    :param key_size:
        RSA key size.
    :param data:
        Data
    :returns:
        A blob of data as large as the key's N, using PKCS1's
        "emsa-pkcs1-v1_5" encoding.
    """
    SHA1_DIGESTINFO = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
    size = len(long_to_bytes(key_size))
    filler = '\xff' * (size - len(SHA1_DIGESTINFO) - len(data) - 3)
    return '\x00\x01' + filler + '\x00' + SHA1_DIGESTINFO + data


class Key(object):
    """
    Abstract class representing an encryption key.
    """
    def __init__(self, key_info, encoded_key, encoding, *args, **kwargs):
        self._key_info = key_info
        self._encoded_key = encoded_key
        self._encoding = encoding

    @property
    def encoded_key(self):
        """
        Returns the original encoded key string.
        """
        return self._encoded_key

    @property
    def encoding(self):
        """
        Returns the original encoding method name of the key.
        """
        return self._encoding

    @property
    def key(self):
        """
        Returns the internal key.
        """
        raise NotImplementedError("Override this property.")

    @property
    def size(self):
        """
        Returns the size of the key (n).
        """
        raise NotImplementedError("Override this property.")

    @property
    def key_info(self):
        """
        Returns the key information parsed from the provided encoded key.
        """
        return self._key_info

    def sign(self, digest):
        """
        Signs a digest with the key.

        :param digest:
            The SHA-1 digest of the data.
        :param encoder:
            The encoding method to use. Default EMSA-PKCS1-v1.5
        :returns:
            Signature byte string.
        """
        return long_to_bytes(self._sign(digest))

    def verify(self, digest, signature_bytes):
        """
        Verifies a signature against that computed by signing the provided
        data.

        :param digest:
            The SHA-1 digest of the data.
        :param signature_bytes:
            The signature raw byte string.
        :param encoder:
            The encoding method to use. Default EMSA-PKCS1-v1.5
        :returns:
            ``True`` if the signature matches; ``False`` otherwise.
        """
        return self._verify(digest, bytes_to_long(signature_bytes))

    def pkcs1_v1_5_sign(self, data):
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
        digest = pkcs1_v1_5_encode(self.size, data)
        return self.sign(digest)

    def pkcs1_v1_5_verify(self, data, signature_bytes):
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
        digest = pkcs1_v1_5_encode(self.size, data)
        return self.verify(digest, signature_bytes)

    def _sign(self, digest):
        raise NotImplementedError("Override this method.")

    def _verify(self, signature, digest):
        raise NotImplementedError("Override this method.")


class PrivateKey(Key):
    """
    Abstract private key class.

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
    pass


class PublicKey(Key):
    """
    Abstract public key class.
    """
    pass
