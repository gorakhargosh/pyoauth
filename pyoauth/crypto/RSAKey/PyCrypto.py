#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Released into public domain.

"""
:module: pyoauth.crypto.RSAKey.PyCrypto
:synopsis:PyCrypto RSA key adapter.
"""

from pyoauth.types import byte_count
from pyoauth.types.number import bytes_to_long, long_to_bytes
from pyoauth.crypto.utils.compat import is_pycrypto_available
from pyoauth.crypto.random import generate_random_bytes
from pyoauth.crypto.RSAKey import RSAKey
from pyoauth.crypto.RSAKey.pure import Python_RSAKey

if is_pycrypto_available():

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
            num_bytes = byte_count(self.n)
            if len(s)== num_bytes:
                pass
            elif len(s) == num_bytes - 1:
                s = '\0' + s
            else:
                raise AssertionError()
            c = bytes_to_long(self.rsa.decrypt((s,)))
            return c

        def _rawPublicKeyOp(self, c):
            s = long_to_bytes(c)
            num_bytes = byte_count(self.n)
            if len(s) == num_bytes:
                pass
            elif len(s) == num_bytes-1:
                s = '\0' + s
            else:
                raise AssertionError()
            m = bytes_to_long(self.rsa.encrypt(s, None)[0])
            return m

        def writeXMLPublicKey(self, indent=''):
            return Python_RSAKey(self.n, self.e).write(indent)

        @staticmethod
        def generate(bits):
            key = PyCrypto_RSAKey()
            #def f(num_bytes):
            #    return bytearray_to_bytes(generate_random_bytearray(num_bytes))
            key.rsa = RSA.generate(bits, generate_random_bytes)
            return key
