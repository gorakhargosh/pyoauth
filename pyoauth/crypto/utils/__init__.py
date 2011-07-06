#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Cryptographic utility functions.

from hashlib import sha1, md5

def sha1_hash(*inputs):
    """
    Calculates a SHA-1 hash of a variable number of inputs.

    :param inputs:
        A variable number of inputs for which the digest will be calculated.
    :returns:
        A byte string containing the SHA-1 message digest.
    """
    md = sha1()
    for i in inputs:
        md.update(i)
    return md.digest()


def md5_hash(*inputs):
    """
    Calculates a MD5 hash of a variable number of inputs.

    :param inputs:
        A variable number of inputs for which the digest will be calculated.
    :returns:
        A byte string containing the MD5 message digest.
    """
    md = md5()
    for i in inputs:
        md.update(i)
    return md.digest()



