#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Miscellaneous functions to mask Python version differences."""

import sys
import array
import math
import traceback

def bytearray_create(seq):
    return array.array('B', seq)

def bytearray_create_zeros(howMany):
    return array.array('B', [0] * howMany)

def concatArrays(a1, a2):
    return a1+a2

def bytesToString(bytes):
    return bytes.tostring()

def stringToBytes(s):
    bytes = bytearray_create_zeros(0)
    bytes.fromstring(s)
    return bytes

def bit_count(n):
    if n==0:
        return 0
    s = "%x" % n
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    return int(math.floor(math.log(n, 2))+1)

BaseException = Exception
def formatExceptionTrace(e):
    newStr = "".join(traceback.format_exception(sys.exc_type, sys.exc_value, sys.exc_traceback))
    return newStr
