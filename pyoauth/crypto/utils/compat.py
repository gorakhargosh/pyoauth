#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Released into public domain.

# TODO: Remove this after we're done refactoring.

try:
    from M2Crypto import m2
    def is_m2crypto_available():
        return True
except ImportError:
    def is_m2crypto_available():
        return False

try:
    import Crypto.Cipher.AES
    def is_pycrypto_available():
        return True
except ImportError:
    def is_pycrypto_available():
        return False
