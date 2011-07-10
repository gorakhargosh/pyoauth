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
:module: pyoauth.crypto.primes
:synopsis: Cryptographic prime number routines.

Verification
------------
.. autofunction:: is_prime

Random
------
.. autofunction:: generate_random_prime
.. autofunction:: generate_random_safe_prime
"""

import math
from pyoauth.crypto.random import generate_random_long
from pyoauth.types.number import pow_mod


def make_prime_sieve(size):
    """
    Pre-calculate a sieve of the ~100 primes < 1000.

    :param size:
        Count
    :returns:
        Prime sieve.
    """
    sieve = range(size)
    for count in range(2, int(math.sqrt(size))):
        if not sieve[count]:
            continue
        x = sieve[count] * 2
        while x < len(sieve):
            sieve[x] = 0
            x += sieve[count]
    sieve = [x for x in sieve[2:] if x]
    return sieve

sieve = make_prime_sieve(1000)


def is_prime(num, iterations=5):
    """
    Determines whether a number is prime.

    :param num:
        Number
    :param iterations:
        Number of iterations.
    :returns:
        ``True`` if prime; ``False`` otherwise.
    """
    #Trial division with sieve
    for x in sieve:
        if x >= num: return True
        if not num % x: return False
    #Passed trial division, proceed to Rabin-Miller
    #Rabin-Miller implemented per Ferguson & Schneier
    #Compute s, t for Rabin-Miller
    s, t = num-1, 0
    while not s % 2:
        s, t = s/2, t+1
    #Repeat Rabin-Miller x times
    a = 2 #Use 2 as a base for first iteration speedup, per HAC
    for count in range(iterations):
        v = pow_mod(a, s, num)
        if v==1:
            continue
        i = 0
        while v != num-1:
            if i == t-1:
                return False
            else:
                v, i = pow_mod(v, 2, num), i+1
        a = generate_random_long(2, num)
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
