#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Placed into the public domain.

from pyasn1.type import univ
from pyasn1.codec.der import decoder, encoder
from pyoauth.crypto.codec.x509 import Certificate
from pyoauth.crypto.codec.pemder import pem_to_der_certificate, der_to_pem_certificate
from pyoauth.crypto.utils.bitstring import bits_to_long


class X509Certificate(object):
    # http://tools.ietf.org/html/rfc3279 - Section 2.3.1
    _RSA_OID = univ.ObjectIdentifier('1.2.840.113549.1.1.1')

    def __init__(self, certificate):
        self._certificate = certificate
        self._certificate_asn1 = self.decode_from_pem_certificate(certificate)

    def encode(self):
        self.encode_to_pem_certificate(self._certificate_asn1)

    @property
    def public_key(self):
        algorithm = self.subject_public_key_info.getComponentByName('algorithm')[0]
        if algorithm != self._RSA_OID:
            raise NotImplementedError("Only RSA encryption is currently supported: got algorithm `%r`" % algorithm)
        return self.parse_public_rsa_key_bits(self.subject_public_key_info.getComponentByName('subjectPublicKey'))

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
        return der_to_pem_certificate(encoder.encoder(certificate_asn1))
