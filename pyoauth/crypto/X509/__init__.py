#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Class representing an X.509 certificate."""

import array

from pyoauth.crypto.utils import sha1_hexdigest
from pyoauth.crypto.utils.bytearray import \
    bytearray_create, bytearray_from_bytes
from pyoauth.crypto.utils.ASN1Parser import ASN1Parser
from pyoauth.crypto.RSAKey.factory import _createPublicRSAKey
from pyoauth.crypto.utils.cryptomath import bytearray_b64decode, bytearray_to_long


class X509(object):
    """This class represents an X.509 certificate.

    @type bytes: L{array.array} of unsigned bytes
    @ivar bytes: The DER-encoded ASN.1 certificate

    @type publicKey: L{tlslite.utils.RSAKey.RSAKey}
    @ivar publicKey: The subject public key from the certificate.
    """

    def __init__(self):
        self.bytes = bytearray_create([])
        self.publicKey = None

    def parse(self, s):
        """Parse a PEM-encoded X.509 certificate.

        @type s: str
        @param s: A PEM-encoded X.509 certificate (i.e. a base64-encoded
        certificate wrapped with "-----BEGIN CERTIFICATE-----" and
        "-----END CERTIFICATE-----" tags).
        """

        start = s.find("-----BEGIN CERTIFICATE-----")
        end = s.find("-----END CERTIFICATE-----")
        if start == -1:
            raise SyntaxError("Missing PEM prefix")
        if end == -1:
            raise SyntaxError("Missing PEM postfix")
        s = s[start+len("-----BEGIN CERTIFICATE-----") : end]

        bytes = bytearray_b64decode(s)
        self.parseBinary(bytes)
        return self

    def parseBinary(self, bytes):
        """Parse a DER-encoded X.509 certificate.

        @type bytes: str or L{array.array} of unsigned bytes
        @param bytes: A DER-encoded X.509 certificate.
        """

        if isinstance(bytes, type("")):
            bytes = bytearray_from_bytes(bytes)

        self.bytes = bytes
        p = ASN1Parser(bytes)

        #Get the tbsCertificate
        tbsCertificateP = p.getChild(0)

        #Is the optional version field present?
        #This determines which index the key is at.
        if tbsCertificateP.value[0]==0xA0:
            subjectPublicKeyInfoIndex = 6
        else:
            subjectPublicKeyInfoIndex = 5

        #Get the subjectPublicKeyInfo
        subjectPublicKeyInfoP = tbsCertificateP.getChild(\
                                    subjectPublicKeyInfoIndex)

        #Get the algorithm
        algorithmP = subjectPublicKeyInfoP.getChild(0)
        rsaOID = algorithmP.value
        if list(rsaOID) != [6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0]:
            raise SyntaxError("Unrecognized AlgorithmIdentifier")

        #Get the subjectPublicKey
        subjectPublicKeyP = subjectPublicKeyInfoP.getChild(1)

        #Adjust for BIT STRING encapsulation
        if (subjectPublicKeyP.value[0] !=0):
            raise SyntaxError()
        subjectPublicKeyP = ASN1Parser(subjectPublicKeyP.value[1:])

        #Get the modulus and exponent
        modulusP = subjectPublicKeyP.getChild(0)
        publicExponentP = subjectPublicKeyP.getChild(1)

        #Decode them into numbers
        n = bytearray_to_long(modulusP.value)
        e = bytearray_to_long(publicExponentP.value)

        #Create a public key instance
        self.publicKey = _createPublicRSAKey(n, e)

    def getFingerprint(self):
        """Get the hex-encoded fingerprint of this certificate.

        @rtype: str
        @return: A hex-encoded fingerprint.
        """
        return sha1_hexdigest(self.bytes)

    def getCommonName(self):
        """Get the Subject's Common Name from the certificate.

        The cryptlib_py module must be installed in order to use this
        function.

        @rtype: str or None
        @return: The CN component of the certificate's subject DN, if
        present.
        """
        import cryptlib_py
        c = cryptlib_py.cryptImportCert(self.bytes, cryptlib_py.CRYPT_UNUSED)
        name = cryptlib_py.CRYPT_CERTINFO_COMMONNAME
        try:
            try:
                length = cryptlib_py.cryptGetAttributeString(c, name, None)
                returnVal = array.array('B', [0] * length)
                cryptlib_py.cryptGetAttributeString(c, name, returnVal)
                returnVal = returnVal.tostring()
            except cryptlib_py.CryptException, e:
                if e[0] == cryptlib_py.CRYPT_ERROR_NOTFOUND:
                    returnVal = None
            return returnVal
        finally:
            cryptlib_py.cryptDestroyCert(c)

    def writeBytes(self):
        return self.bytes


