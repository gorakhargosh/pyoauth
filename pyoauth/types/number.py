#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# ===================================================================
# The contents of this file are dedicated to the public domain. To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================


"""
:module: pyoauth.types.number
:synopsis: Number routines.

Type conversion
---------------
.. autofunction:: bytes_to_long
.. autofunction:: long_to_bytes

BigNum
------
.. autofunction:: mpi_to_long
.. autofunction:: long_to_mpi

Math
----
.. autofunction:: pow_mod
.. autofunction:: inverse_mod
"""


import struct
from pyoauth.types import bit_count, byte_count

from pyoauth.types.bytearray import \
    bytearray_concat, \
    bytearray_create_zeros, \
    bytes_to_bytearray, \
    bytearray_to_bytes, \
    long_to_bytearray, \
    bytearray_to_long

# Taken from PyCrypto "as is".
# Improved conversion functions contributed by Barry Warsaw, after
# careful benchmarking

def long_to_bytes(num, blocksize=0):
    """
    Convert a long integer to a byte string::

        long_to_bytes(n:long, blocksize:int) : string

    :param num:
        Long value
    :param blocksize:
        If optional blocksize is given and greater than zero, pad the front of
        the byte string with binary zeros so that the length is a multiple of
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
        num >>= 32
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

    :param byte_string:
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
    byte_array = long_to_bytearray(num)
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
    byte_array = bytes_to_bytearray(byte_string)
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

    byte_array = bytes_to_bytearray(mpi_byte_string[4:])
    return bytearray_to_long(byte_array)


def long_to_mpi(num):
    """
    Converts a long value into an OpenSSL-format MPI Bignum byte string.

    :param num:
        Long value.
    :returns:
        OpenSSL-format MPI Bignum byte string.
    """
    byte_array = long_to_bytearray(num)
    ext = 0
    #If the high-order bit is going to be set,
    #add an extra byte of zeros
    if not (bit_count(num) & 0x7):
        ext = 1
    length = byte_count(num) + ext
    byte_array = bytearray_concat(bytearray_create_zeros(4+ext), byte_array)
    byte_array[0] = (length >> 24) & 0xFF
    byte_array[1] = (length >> 16) & 0xFF
    byte_array[2] = (length >> 8) & 0xFF
    byte_array[3] = length & 0xFF
    return bytearray_to_bytes(byte_array)


def gcd(a, b):
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
    a, b = max(a, b), min(a, b)
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
    # TODO: This will break when python division changes, but we can't use //
    # because of Jython
    return (a * b) / gcd(a, b)


def inverse_mod(a, b):
    """
    Returns inverse of a mod b, zero if none

    Uses Extended Euclidean Algorithm

    :param a:
        Long value
    :param b:
        Long value
    :returns:
        Inverse of a mod b, zero if none.
    """
    c, d = a, b
    uc, ud = 1, 0
    while c:
        # TODO: This will break when python division changes, but we can't use
        # // because of Jython
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
        if power < 0:
            power *= -1
            negativeResult = True

        exp2 = 2**nBitScan
        mask = exp2 - 1

        # Break power into a list of digits of nBitScan bits.
        # The list is recursive so easy to read in reverse direction.
        nibbles = None
        while power:
            nibbles = int(power & mask), nibbles
            power >>= nBitScan

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

