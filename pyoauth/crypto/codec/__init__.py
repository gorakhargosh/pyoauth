#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2009 Google Inc.
# Copyright (C) 2011 Yesudeep Mangalapilly
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
:module: pyoauth.crypto.codec
:synopsis: RSA keys and X.509 certificates parsing.
:author: Arne Roomann-Kurrik <kurrik@gmail.com>
:author: Yesudeep Mangalapilly <yesudeep@gmail.com>
:see: http://code.google.com/p/kurrik-resources/source/browse/trunk/src/x509/x509.py?r=14

Classes:
--------
.. autoclass:: RSAPublicKey
.. autoclass:: RSAPrivateKey
.. autoclass:: X509Certificate
"""
import logging

from pyasn1.type import univ
from pyasn1.codec.der import decoder, encoder
from pyoauth.crypto.codec.pemder import \
    pem_to_der_public_key, \
    der_to_pem_public_key, \
    der_to_pem_rsa_private_key, \
    pem_to_der_rsa_private_key, \
    pem_to_der_private_key, \
    pem_to_der_certificate, \
    der_to_pem_certificate
from pyoauth.crypto.codec.x509 import Certificate, SubjectPublicKeyInfo
from pyoauth.crypto.codec import rsadsa
from pyoauth.crypto.utils.bitstring import bits_to_long


class RSAPrivateKey(object):
    """
    ASN.1 Syntax::

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

        Version ::= INTEGER
    """
    # http://tools.ietf.org/html/rfc3279 - Section 2.3.1
    _RSA_OID = univ.ObjectIdentifier('1.2.840.113549.1.1.1')

    def __init__(self, key):
        self._key = key
        self._key_asn1, self._private_key_asn1 = self.decode_from_pem_key(key)

    def encode(self):
        return self.encode_to_pem_private_key(self._key_asn1)

    @property
    def private_key(self):
        asn = self._private_key_asn1
        return dict(
            version          = long(asn.getComponentByName('version')),
            modulus          = long(asn.getComponentByName('modulus')),
            publicExponent   = long(asn.getComponentByName('publicExponent')),
            privateExponent  = long(asn.getComponentByName('privateExponent')),
            prime1           = long(asn.getComponentByName('prime1')),
            prime2           = long(asn.getComponentByName('prime2')),
            exponent1        = long(asn.getComponentByName('exponent1')),
            exponent2        = long(asn.getComponentByName('exponent2')),
            coefficient      = long(asn.getComponentByName('coefficient')),
        )


    @classmethod
    def decode_from_pem_key(cls, key):
        keyType = rsadsa.RSAPrivateKey()
        try:
            der = pem_to_der_rsa_private_key(key)
        except Exception, e:
            logging.exception(e)
            der = pem_to_der_private_key(key)

        cover_asn1 = decoder.decode(der)[0]
        if len(cover_asn1) < 1:
            raise ValueError("No RSA private key found after ASN.1 decoding.")

        algorithm = cover_asn1[1][0]
        if algorithm != cls._RSA_OID:
            raise ValueError("Only RSA encryption is currently supported: got algorithm `%r`" % algorithm)
        key_der = bytes(cover_asn1[2])
        key_asn1 = decoder.decode(key_der, asn1Spec=keyType)[0]
        return cover_asn1, key_asn1

    @classmethod
    def encode_to_pem_private_key(cls, key_asn1):
        return der_to_pem_rsa_private_key(encoder.encode(key_asn1))

TEST_RSA_PRIVATE_KEYS = (
    '''
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
-----END PRIVATE KEY-----''',
)
TEST_PRIVATE_KEYS = (0
    ,
)

class RSAPublicKey(object):
    """
    ASN.1 Syntax::

        SubjectPublicKeyInfo  ::=  SEQUENCE  {
            algorithm            AlgorithmIdentifier,
            subjectPublicKey     BIT STRING  }
    """
    # http://tools.ietf.org/html/rfc3279 - Section 2.3.1
    _RSA_OID = univ.ObjectIdentifier('1.2.840.113549.1.1.1')

    def __init__(self, key):
        self._key = key
        self._key_asn1 = self.decode_from_pem_key(key)

    def encode(self):
        return self.encode_to_pem_key(self._key_asn1)

    @property
    def public_key(self):
        algorithm = self._key_asn1.getComponentByName('algorithm')[0]
        if algorithm != self._RSA_OID:
            raise NotImplementedError("Only RSA encryption is currently supported: got algorithm `%r`" % algorithm)
        modulus, exponent = self.parse_public_rsa_key_bits(self._key_asn1.getComponentByName('subjectPublicKey'))
        return dict(
            modulus=modulus,
            exponent=exponent,
        )

    @classmethod
    def parse_public_rsa_key_bits(cls, public_key_bitstring):
        """
        Extracts the RSA modulus and exponent from a RSA public key bit string.

        :param public_key_bitstring:
            ASN.1 public key bit string.
        :returns:
            Tuple of (modulus, exponent)
        """
        return X509Certificate.parse_public_rsa_key_bits(public_key_bitstring)

    @classmethod
    def decode_from_pem_key(cls, key):
        keyType = SubjectPublicKeyInfo()
        der = pem_to_der_public_key(key)
        key_asn1 = decoder.decode(der, asn1Spec=keyType)[0]
        if len(key_asn1) < 1:
            raise ValueError("No RSA public key found after ASN.1 decoding.")
        return key_asn1

    @classmethod
    def encode_to_pem_key(cls, key_asn1):
        return der_to_pem_public_key(encoder.encode(key_asn1))


TEST_PUBLIC_PEM_KEYS = ("""
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0YjCwIfYoprq/FQO6lb3asXrx
LlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlYzypSRjVxwxrsuRcP3e641SdASwfr
mzyvIgP08N4S0IFzEURkV1wp/IpH7kH41EtbmUmrXSwfNZsnQRE5SYSOhh+LcK2w
yQkdgcMv11l4KoBkcwIDAQAB
-----END PUBLIC KEY-----
""",
    )

TEST_PUBLIC_KEYS = (
    (126669640320683290646795148731116725859129871317489646670977486626744987251277308188134951784112892388851824395559423655294483477900467304936849324412630428474313221323982004833431306952809970692055204065814102382627007630050419900189287007179961309761697749877767089292033899335453619375029318017462636143731L,
 65537L),
)


class X509Certificate(object):
    # http://tools.ietf.org/html/rfc3279 - Section 2.3.1
    _RSA_OID = univ.ObjectIdentifier('1.2.840.113549.1.1.1')

    def __init__(self, certificate):
        self._certificate = certificate
        self._certificate_asn1 = self.decode_from_pem_certificate(certificate)

    def encode(self):
        return self.encode_to_pem_certificate(self._certificate_asn1)

    @property
    def public_key(self):
        algorithm = self.subject_public_key_info.getComponentByName('algorithm')[0]
        if algorithm != self._RSA_OID:
            raise NotImplementedError("Only RSA encryption is currently supported: got algorithm `%r`" % algorithm)
        modulus, exponent = self.parse_public_rsa_key_bits(self.subject_public_key_info.getComponentByName('subjectPublicKey'))
        return dict(
            modulus=modulus,
            exponent=exponent,
        )

    @property
    def tbs_certificate(self):
        return self._certificate_asn1.getComponentByName('tbsCertificate')

    @property
    def subject_public_key_info(self):
        return self.tbs_certificate.getComponentByName('subjectPublicKeyInfo')

    @classmethod
    def parse_public_rsa_key_bits(cls, public_key_bitstring):
        """
        Extracts the RSA modulus and exponent from a RSA public key bit string.

        :param public_key_bitstring:
            ASN.1 public key bit string.
        :returns:
            Tuple of (modulus, exponent)
        """
        public_key_long = bits_to_long(public_key_bitstring)
        public_key_hex = hex(public_key_long)[2:-1]
        public_key_asn1 = decoder.decode(public_key_hex.decode('hex'))

        if len(public_key_asn1) < 1:
            raise ValueError("Problem ASN.1 decoding public key bytes")

        if len(public_key_asn1[0]) < 2:
            raise ValueError("Couldn't obtain RSA modulus and exponent from public key.")

        return long(public_key_asn1[0][0]), long(public_key_asn1[0][1])

    @classmethod
    def decode_from_pem_certificate(cls, certificate):
        certType = Certificate()
        der = pem_to_der_certificate(certificate)
        cert_asn1 = decoder.decode(der, asn1Spec=certType)[0]
        if len(cert_asn1) < 1:
            raise ValueError("No X.509 certificate found after ASN.1 decoding.")
        return cert_asn1

    @classmethod
    def encode_to_pem_certificate(cls, certificate_asn1):
        return der_to_pem_certificate(encoder.encode(certificate_asn1))


TEST_CERTIFICATES = ("""
-----BEGIN CERTIFICATE-----
MIIDHzCCAoigAwIBAgIQZMuxK+KKS5wF/rjXp3z/KTANBgkqhkiG9w0BAQUFADCB
hzELMAkGA1UEBhMCWkExIjAgBgNVBAgTGUZPUiBURVNUSU5HIFBVUlBPU0VTIE9O
TFkxHTAbBgNVBAoTFFRoYXd0ZSBDZXJ0aWZpY2F0aW9uMRcwFQYDVQQLEw5URVNU
IFRFU1QgVEVTVDEcMBoGA1UEAxMTVGhhd3RlIFRlc3QgQ0EgUm9vdDAeFw0wODAz
MjYwMDEyMDdaFw0wODA0MTYwMDEyMDdaMIGuMRcwFQYDVQQKEw5oaTVtb2R1bGVz
LmNvbTEZMBcGA1UECxMQRG9tYWluIFZhbGlkYXRlZDE7MDkGA1UECxMyR28gdG8g
aHR0cHM6Ly93d3cudGhhd3RlLmNvbS9yZXBvc2l0b3J5L2luZGV4Lmh0bWwxIjAg
BgNVBAsTGVRoYXd0ZSBTU0wxMjMgY2VydGlmaWNhdGUxFzAVBgNVBAMTDmhpNW1v
ZHVsZXMuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZgdrYsECeGO/Y
srDfaO/vIyMq7+DYdAmImzwg35wnti3Dr3B6kS6OeRiBAIUTvdZXX3XitJFxVlDF
H/PbRimm0d3eQvSfW3+0xIhF9C3E9QFj6LWBz6bBlh5p0pSXygAZ9AXR1OMM2lDR
R9hwQp1YVjzJk3hYW2qD591auROQvwIDAQABo2MwYTAMBgNVHRMBAf8EAjAAMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAyBggrBgEFBQcBAQQmMCQwIgYI
KwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0ZS5jb20wDQYJKoZIhvcNAQEFBQAD
gYEABdPtdX56mPwSfPMzgSLH7RueLZi5HXqW2krojWsOv3VFnayQKuzXdy5DZrMY
/tI2AUPXicvBW3GjTfSKmUNvsOXUIC8az3K3iTs1KKekUaidLRlaRZIO0FVEJH5u
gO9HqAcXxrx99/3agvAVTKAFBFJtiWD1i1LkYeqKrPQOPo8=
-----END CERTIFICATE-----""",
    # OAuth 1.0 test case.
    """
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
-----END CERTIFICATE-----"""
    )

TEST_PUBLIC_KEYS = (
    (126669640320683290646795148731116725859129871317489646670977486626744987251277308188134951784112892388851824395559423655294483477900467304936849324412630428474313221323982004833431306952809970692055204065814102382627007630050419900189287007179961309761697749877767089292033899335453619375029318017462636143731L,
 65537L),
    (107796453724127466436509607023300853823148671381186269695418299876688451275586863210602390910751033980089586659623213376886118860658943925516474941572267483546063696504972995209865305723609365133051508378295496906014585319487318439832859683449024036092870160203868280352941275868168286901714810544167406768319L,
 65537L),
)
