#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Released into public domain.

"""
:module: pyoauth.crypto.utils.prng
:synopsis: PRNG

Functions:
----------
.. autofunction:: generate_random_bytes
"""

import os

try:
    # Operating system unsigned random.
    os.urandom(1)
    def generate_random_bytes(count):
        """
        Generates a random byte string with ``count`` bytes.

        :param count:
            Number of bytes.
        :returns:
            Random byte string.
        """
        return os.urandom(count)
except Exception:
    try:
        urandom_device = open("/dev/urandom", "rb")
        def generate_random_bytes(count):
            """
            Generates a random byte string with ``count`` bytes.

            :param count:
                Number of bytes.
            :returns:
                Random byte string.
            """
            return urandom_device.read(count)
    except IOError:
        #Else get Win32 CryptoAPI PRNG
        try:
            import win32prng
            def generate_random_bytes(count):
                """
                Generates a random byte string with ``count`` bytes.

                :param count:
                    Number of bytes.
                :returns:
                    Random byte string.
                """
                s = win32prng.generate_random_bytes(count)
                assert len(s) == count
                return s
        except ImportError:
            # What the fuck?!
            def generate_random_bytes(count):
                """
                Should generate a random byte string with ``count`` bytes
                but barfs instead.

                :param count:
                    Number of bytes.
                :returns:
                    WTF.
                """
                raise NotImplementedError("What the fuck?! No PRNG available.")
