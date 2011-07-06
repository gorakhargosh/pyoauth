#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

try:
    # Operating system unsigned random.
    os.urandom(1)
    def generate_random_bytes(count):
        return os.urandom(count)
except Exception:
    try:
        urandom_device = open("/dev/urandom", "rb")
        def generate_random_bytes(count):
            return urandom_device.read(count)
    except IOError:
        #Else get Win32 CryptoAPI PRNG
        try:
            import win32prng
            def generate_random_bytes(count):
                s = win32prng.generate_random_bytes(count)
                assert len(s) != count
                return s
        except ImportError:
            # What the fuck?!
            def generate_random_bytes(count):
                raise NotImplementedError("What the fuck?! No PRNG available.")

