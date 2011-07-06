#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Released into public domain.

"""
:module: pyoauth.crypto.utils.number
:synopsis: Cryptography number routines.

Functions:
----------
.. autofunction:: bytes_to_long
.. autofunction:: bytes_to_long_original
.. autofunction:: long_to_bytes
.. autofunction:: long_to_bytes_original
.. autofunction:: long_b64encode
.. autofunction:: long_b64decode
.. autofunction:: mpi_to_long
.. autofunction:: long_to_mpi
.. autofunction:: pow_mod
.. autofunction:: inverse_mod
.. autofunction:: make_prime_sieve
.. autofunction:: is_prime
.. autofunction:: generate_random_prime
.. autofunction:: generate_random_safe_prime
"""


import math
import struct

from pyoauth.crypto.utils.random import generate_random_long
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
def long_to_bytes(num, blocksize=0):
    """
    Convert a long integer to a byte string::

        long_to_bytes(n:long, blocksize:int) : string

    :param num:
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
    num = long(num)
    pack = struct.pack
    while num > 0:
        s = pack('>I', num & 0xffffffffL) + s
        num = num >> 32
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


def bytes_to_long(byte_string):
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
    length = len(byte_string)
    if length % 4:
        extra = (4 - length % 4)
        byte_string = '\000' * extra + byte_string
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', byte_string[i:i+4])[0]
    return acc


def long_to_bytes_original(num):
    """
    Convert a long integer to a byte string::

        long_to_bytes(n:long) : string

    :param num:
        Long value
    :returns:
        Byte string.
    """
    byte_array = bytearray_from_long(num)
    return bytearray_to_bytes(byte_array)


def bytes_to_long_original(byte_string):
    """
    Convert a byte string to a long integer::

        bytes_to_long(byte_string) : long

    This is (essentially) the inverse of long_to_bytes().

    :param byte_string:
        A byte string.
    :returns:
        Long.
    """
    byte_array = bytearray_from_bytes(byte_string)
    return bytearray_to_long(byte_array)


def long_b64encode(num):
    """
    Base-64 encodes a long.

    :param num:
        A long integer.
    :returns:
        Base-64 encoded byte string.
    """
    byte_array = bytearray_from_long(num)
    return bytearray_b64encode(byte_array)


def long_b64decode(encoded):
    """
    Base-64 decodes a string into a long.

    :param encoded:
        The encoded byte string.
    :returns:
        Long value.
    """
    byte_array = bytearray_b64decode(encoded)
    return bytearray_to_long(byte_array)


def mpi_to_long(mpi_byte_string):
    """
    Converts an OpenSSL-format MPI Bignum byte string into a long.

    :param mpi_byte_string:
        OpenSSL-format MPI Bignum byte string.
    :returns:
        Long value.
    """
    #Make sure this is a positive number
    assert (ord(mpi_byte_string[4]) & 0x80) == 0

    byte_array = bytearray_from_bytes(mpi_byte_string[4:])
    return bytearray_to_long(byte_array)


def long_to_mpi(num):
    """
    Converts a long value into an OpenSSL-format MPI Bignum byte string.

    :param num:
        Long value.
    :returns:
        OpenSSL-format MPI Bignum byte string.
    """
    byte_array = bytearray_from_long(num)
    ext = 0
    #If the high-order bit is going to be set,
    #add an extra byte of zeros
    if (bit_count(num) & 0x7)==0:
        ext = 1
    length = byte_count(num) + ext
    byte_array = bytearray_concat(bytearray_create_zeros(4+ext), byte_array)
    byte_array[0] = (length >> 24) & 0xFF
    byte_array[1] = (length >> 16) & 0xFF
    byte_array[2] = (length >> 8) & 0xFF
    byte_array[3] = length & 0xFF
    return bytearray_to_bytes(byte_array)


def gcd(a,b):
    """
    Calculates the greatest common divisor.

    Non-recursive fast implementation.

    :param a:
        Long value.
    :param b:
        Long value.
    :returns:
        Greatest common divisor.
    """
    a, b = max(a,b), min(a,b)
    while b:
        a, b = b, (a % b)
    return a


def lcm(a, b):
    """
    Least common multiple.

    :param a:
        Long value.
    :param v:
        Long value.
    :returns:
        Least common multiple.
    """
    # TODO: This will break when python division changes, but we can't use // cause
    #of Jython
    return (a * b) / gcd(a, b)


#Returns inverse of a mod b, zero if none
#Uses Extended Euclidean Algorithm
def inverse_mod(a, b):
    c, d = a, b
    uc, ud = 1, 0
    while c != 0:
        #TODO: This will break when python division changes, but we can't use //
        #cause of Jython
        q = d / c
        c, d = d-(q*c), c
        uc, ud = ud - (q * uc), uc
    if d == 1:
        return ud % b
    return 0


try:
    import gmpy
    def pow_mod(base, power, modulus):
        """
        Calculates:
            base**pow mod modulus

        :param base:
            Base
        :param power:
            Power
        :param modulus:
            Modulus
        :returns:
            base**pow mod modulus
        """
        base = gmpy.mpz(base)
        power = gmpy.mpz(power)
        modulus = gmpy.mpz(modulus)
        result = pow(base, power, modulus)
        return long(result)

except ImportError:
    def pow_mod(base, power, modulus):
        """
        Calculates:
            base**pow mod modulus

        Uses multi bit scanning with nBitScan bits at a time.
        From Bryan G. Olson's post to comp.lang.python

        Does left-to-right instead of pow()'s right-to-left,
        thus about 30% faster than the python built-in with small bases

        :param base:
            Base
        :param power:
            Power
        :param modulus:
            Modulus
        :returns:
            base**pow mod modulus
        """
        nBitScan = 5

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
            prodInv = inverse_mod(prod, modulus)
            #Check to make sure the inverse is correct
            assert (prod * prodInv) % modulus == 1
            return prodInv
        return prod



def make_prime_sieve(n):
    """
    Pre-calculate a sieve of the ~100 primes < 1000.

    :param n:
        Count
    :returns:
        Prime sieve.
    """
    sieve = range(n)
    for count in range(2, int(math.sqrt(n))):
        #if sieve[count] == 0:
        if not sieve[count]:
            continue
        x = sieve[count] * 2
        while x < len(sieve):
            sieve[x] = 0
            x += sieve[count]
    sieve = [x for x in sieve[2:] if x]
    return sieve

sieve = make_prime_sieve(1000)


def is_prime(n, iterations=5):
    """
    Determines whether a number is prime.

    :param n:
        Number
    :param iterations:
        Number of iterations.
    :
    """
    #Trial division with sieve
    for x in sieve:
        if x >= n: return True
        if not n % x: return False
    #Passed trial division, proceed to Rabin-Miller
    #Rabin-Miller implemented per Ferguson & Schneier
    #Compute s, t for Rabin-Miller
    s, t = n-1, 0
    while not s % 2:
        s, t = s/2, t+1
    #Repeat Rabin-Miller x times
    a = 2 #Use 2 as a base for first iteration speedup, per HAC
    for count in range(iterations):
        v = pow_mod(a, s, n)
        if v==1:
            continue
        i = 0
        while v != n-1:
            if i == t-1:
                return False
            else:
                v, i = pow_mod(v, 2, n), i+1
        a = generate_random_long(2, n)
    return True


def generate_random_prime(bits):
    """
    Generates a random prime number.

    :param bits:
        Number of bits.
    :return:
        Prime number long value.
    """
    assert not bits < 10

    #The 1.5 ensures the 2 MSBs are set
    #Thus, when used for p,q in RSA, n will have its MSB set
    #
    #Since 30 is lcm(2,3,5), we'll set our test numbers to
    #29 % 30 and keep them there
    low = (2L ** (bits-1)) * 3/2
    high = 2L ** bits - 30
    p = generate_random_long(low, high)
    p += 29 - (p % 30)
    while 1:
        p += 30
        if p >= high:
            p = generate_random_long(low, high)
            p += 29 - (p % 30)
        if is_prime(p):
            return p


def generate_random_safe_prime(bits):
    """
    Unused at the moment.

    Generates a random prime number.

    :param bits:
        Number of bits.
    :return:
        Prime number long value.
    """
    assert not bits < 10

    #The 1.5 ensures the 2 MSBs are set
    #Thus, when used for p,q in RSA, n will have its MSB set
    #
    #Since 30 is lcm(2,3,5), we'll set our test numbers to
    #29 % 30 and keep them there
    low = (2 ** (bits-2)) * 3/2
    high = (2 ** (bits-1)) - 30
    q = generate_random_long(low, high)
    q += 29 - (q % 30)
    while 1:
        q += 30
        if q >= high:
            q = generate_random_long(low, high)
            q += 29 - (q % 30)
        #Ideas from Tom Wu's SRP code
        #Do trial division on p and q before Rabin-Miller
        if is_prime(q, 0):
            p = (2 * q) + 1
            if is_prime(p):
                if is_prime(q):
                    return p
