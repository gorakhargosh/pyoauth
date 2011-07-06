#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""PyCrypto RSA implementation."""

from pyoauth.crypto.utils.bytearray import bytearray_to_bytes, bytearray_random
from pyoauth.crypto.utils.cryptomath import *
from pyoauth.crypto.utils import byte_count, bytes_to_long, long_to_bytes

from pyoauth.crypto.RSAKey import RSAKey
from pyoauth.crypto.RSAKey.pure import Python_RSAKey

if pycryptoLoaded:

    from Crypto.PublicKey import RSA

    class PyCrypto_RSAKey(RSAKey):
        def __init__(self, n=0, e=0, d=0, p=0, q=0, dP=0, dQ=0, qInv=0):
            if not d:
                self.rsa = RSA.construct( (n, e) )
            else:
                self.rsa = RSA.construct( (n, e, d, p, q) )

        def __getattr__(self, name):
            return getattr(self.rsa, name)

        def hasPrivateKey(self):
            return self.rsa.has_private()

        def hash(self):
            return Python_RSAKey(self.n, self.e).hash()

        def _rawPrivateKeyOp(self, m):
            s = long_to_bytes(m)
            byteLength = byte_count(self.n)
            if len(s)== byteLength:
                pass
            elif len(s) == byteLength-1:
                s = '\0' + s
            else:
                raise AssertionError()
            c = bytes_to_long(self.rsa.decrypt((s,)))
            return c

        def _rawPublicKeyOp(self, c):
            s = long_to_bytes(c)
            byteLength = byte_count(self.n)
            if len(s)== byteLength:
                pass
            elif len(s) == byteLength-1:
                s = '\0' + s
            else:
                raise AssertionError()
            m = bytes_to_long(self.rsa.encrypt(s, None)[0])
            return m

        def writeXMLPublicKey(self, indent=''):
            return Python_RSAKey(self.n, self.e).write(indent)

        def generate(bits):
            key = PyCrypto_RSAKey()
            def f(numBytes):
                return bytearray_to_bytes(bytearray_random(numBytes))
            key.rsa = RSA.generate(bits, f)
            return key
        generate = staticmethod(generate)
