#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
:module: pyoauth.crypto.utils.number
:synopsis: Cryptography number routines.

Functions:
----------
.. autofunction:: bytes_to_long
.. autofunction:: bytes_to_long_slow
.. autofunction:: long_to_bytes
.. autofunction:: long_to_bytes_slow

"""


import math
import struct

from pyoauth.crypto.utils.random import generate_random_number
from pyoauth.crypto.utils import bit_count, byte_count
from pyoauth.crypto.utils.bytearray import \
    bytearray_concat, \
    bytearray_create_zeros, \
    bytearray_from_bytes, \
    bytearray_to_bytes, \
    bytearray_from_long, \
    bytearray_to_long, \
    bytearray_b64decode, \
    bytearray_b64encode

# Improved conversion functions contributed by Barry Warsaw, after
# careful benchmarking
def long_to_bytes(n, blocksize=0):
    """
    Convert a long integer to a byte string::

        long_to_bytes(n:long, blocksize:int) : string

    :param n:
        Long value
    :param blocksize:
        If optional blocksize is given and greater than zero, pad the front of the
        byte string with binary zeros so that the length is a multiple of
        blocksize.
    :returns:
        Byte string.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    n = long(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != '\000':
            break
    else:
        # only happens when n == 0
        s = '\000'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * '\000' + s
    return s


def bytes_to_long(s):
    """
    Convert a byte string to a long integer::

        bytes_to_long(bytestring) : long

    This is (essentially) the inverse of long_to_bytes().

    :param bytestring:
        A byte string.
    :returns:
        Long.
    """
    acc = 0L
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = '\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc


def long_to_bytes_slow(s):
    """
    Convert a long integer to a byte string::

        long_to_bytes(n:long) : string

    :param n:
        Long value
    :returns:
        Byte string.
    """
    byte_array = bytearray_from_long(s)
    return bytearray_to_bytes(byte_array)


def bytes_to_long_slow(s):
    """
    Convert a byte string to a long integer::

        bytes_to_long(bytestring) : long

    This is (essentially) the inverse of long_to_bytes().

    :param bytestring:
        A byte string.
    :returns:
        Long.
    """
    byte_array = bytearray_from_bytes(s)
    return bytearray_to_long(byte_array)



def numberToBase64(n):
    byte_array = bytearray_from_long(n)
    return bytearray_b64encode(byte_array)

def base64ToNumber(s):
    byte_array = bytearray_b64decode(s)
    return bytearray_to_long(byte_array)

def mpiToNumber(mpi): #mpi is an openssl-format bignum string
    if (ord(mpi[4]) & 0x80) !=0: #Make sure this is a positive number
        raise AssertionError()
    byte_array = bytearray_from_bytes(mpi[4:])
    return bytearray_to_long(byte_array)

def numberToMPI(n):
    byte_array = bytearray_from_long(n)
    ext = 0
    #If the high-order bit is going to be set,
    #add an extra byte of zeros
    if (bit_count(n) & 0x7)==0:
        ext = 1
    length = byte_count(n) + ext
    byte_array = bytearray_concat(bytearray_create_zeros(4+ext), byte_array)
    byte_array[0] = (length >> 24) & 0xFF
    byte_array[1] = (length >> 16) & 0xFF
    byte_array[2] = (length >> 8) & 0xFF
    byte_array[3] = length & 0xFF
    return bytearray_to_bytes(byte_array)


# **************************************************************************
# Big Number Math
# **************************************************************************

def gcd(a,b):
    a, b = max(a,b), min(a,b)
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    #This will break when python division changes, but we can't use // cause
    #of Jython
    return (a * b) / gcd(a, b)

#Returns inverse of a mod b, zero if none
#Uses Extended Euclidean Algorithm
def invMod(a, b):
    c, d = a, b
    uc, ud = 1, 0
    while c != 0:
        #This will break when python division changes, but we can't use //
        #cause of Jython
        q = d / c
        c, d = d-(q*c), c
        uc, ud = ud - (q * uc), uc
    if d == 1:
        return ud % b
    return 0


try:
    import gmpy
    def powMod(base, power, modulus):
        base = gmpy.mpz(base)
        power = gmpy.mpz(power)
        modulus = gmpy.mpz(modulus)
        result = pow(base, power, modulus)
        return long(result)

except ImportError:
    #Copied from Bryan G. Olson's post to comp.lang.python
    #Does left-to-right instead of pow()'s right-to-left,
    #thus about 30% faster than the python built-in with small bases
    def powMod(base, power, modulus):
        nBitScan = 5

        """ Return base**power mod modulus, using multi bit scanning
        with nBitScan bits at a time."""

        #TREV - Added support for negative exponents
        negativeResult = False
        if (power < 0):
            power *= -1
            negativeResult = True

        exp2 = 2**nBitScan
        mask = exp2 - 1

        # Break power into a list of digits of nBitScan bits.
        # The list is recursive so easy to read in reverse direction.
        nibbles = None
        while power:
            nibbles = int(power & mask), nibbles
            power = power >> nBitScan

        # Make a table of powers of base up to 2**nBitScan - 1
        lowPowers = [1]
        for i in xrange(1, exp2):
            lowPowers.append((lowPowers[i-1] * base) % modulus)

        # To exponentiate by the first nibble, look it up in the table
        nib, nibbles = nibbles
        prod = lowPowers[nib]

        # For the rest, square nBitScan times, then multiply by
        # base^nibble
        while nibbles:
            nib, nibbles = nibbles
            for i in xrange(nBitScan):
                prod = (prod * prod) % modulus
            if nib: prod = (prod * lowPowers[nib]) % modulus

        #TREV - Added support for negative exponents
        if negativeResult:
            prodInv = invMod(prod, modulus)
            #Check to make sure the inverse is correct
            if (prod * prodInv) % modulus != 1:
                raise AssertionError()
            return prodInv
        return prod


#Pre-calculate a sieve of the ~100 primes < 1000:
def makeSieve(n):
    sieve = range(n)
    for count in range(2, int(math.sqrt(n))):
        if sieve[count] == 0:
            continue
        x = sieve[count] * 2
        while x < len(sieve):
            sieve[x] = 0
            x += sieve[count]
    sieve = [x for x in sieve[2:] if x]
    return sieve

sieve = makeSieve(1000)

def isPrime(n, iterations=5, display=False):
    #Trial division with sieve
    for x in sieve:
        if x >= n: return True
        if n % x == 0: return False
    #Passed trial division, proceed to Rabin-Miller
    #Rabin-Miller implemented per Ferguson & Schneier
    #Compute s, t for Rabin-Miller
    if display: print "*",
    s, t = n-1, 0
    while s % 2 == 0:
        s, t = s/2, t+1
    #Repeat Rabin-Miller x times
    a = 2 #Use 2 as a base for first iteration speedup, per HAC
    for count in range(iterations):
        v = powMod(a, s, n)
        if v==1:
            continue
        i = 0
        while v != n-1:
            if i == t-1:
                return False
            else:
                v, i = powMod(v, 2, n), i+1
        a = generate_random_number(2, n)
    return True

def getRandomPrime(bits, display=False):
    if bits < 10:
        raise AssertionError()
    #The 1.5 ensures the 2 MSBs are set
    #Thus, when used for p,q in RSA, n will have its MSB set
    #
    #Since 30 is lcm(2,3,5), we'll set our test numbers to
    #29 % 30 and keep them there
    low = (2L ** (bits-1)) * 3/2
    high = 2L ** bits - 30
    p = generate_random_number(low, high)
    p += 29 - (p % 30)
    while 1:
        if display: print ".",
        p += 30
        if p >= high:
            p = generate_random_number(low, high)
            p += 29 - (p % 30)
        if isPrime(p, display=display):
            return p

#Unused at the moment...
def getRandomSafePrime(bits, display=False):
    if bits < 10:
        raise AssertionError()
    #The 1.5 ensures the 2 MSBs are set
    #Thus, when used for p,q in RSA, n will have its MSB set
    #
    #Since 30 is lcm(2,3,5), we'll set our test numbers to
    #29 % 30 and keep them there
    low = (2 ** (bits-2)) * 3/2
    high = (2 ** (bits-1)) - 30
    q = generate_random_number(low, high)
    q += 29 - (q % 30)
    while 1:
        if display: print ".",
        q += 30
        if (q >= high):
            q = generate_random_number(low, high)
            q += 29 - (q % 30)
        #Ideas from Tom Wu's SRP code
        #Do trial division on p and q before Rabin-Miller
        if isPrime(q, 0, display=display):
            p = (2 * q) + 1
            if isPrime(p, display=display):
                if isPrime(q, display=display):
                    return p
