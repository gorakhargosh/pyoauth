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
:module: pyoauth.crypto.rsa.PyCrypto
:synopsis: PyCrypto RSA implementation wrapper.

.. autoclass:: PrivateKey
.. autoclass:: PublicKey
"""

from Crypto.PublicKey import RSA
from pyoauth.crypto.rsa.keys import \
    PublicKey as _PublicKey, \
    PrivateKey as _PrivateKey


class PrivateKey(_PrivateKey):
    """
    Represents a RSA private key.

    :param encoded_key:
        The encoded key string.
    :param encoding:
        The encoding method of the key. Default PEM.
    """
    def __init__(self, key_info, encoded_key, encoding):
        super(PrivateKey, self).__init__(key_info, encoded_key, encoding)
        key_info_args = (
            self.key_info["modulus"],
            self.key_info["publicExponent"],
            self.key_info["privateExponent"],
            self.key_info["prime1"],
            self.key_info["prime2"],
            #self.key_info["exponent1"],
            #self.key_info["exponent2"],
            #self.key_info["coefficient"],
        )
        self._key = RSA.construct(key_info_args)

    def _sign(self, digest):
        """
        Sign the digest.
        """
        return self.key.sign(digest, "")[0]

    def _verify(self, digest, signature):
        """
        Verify signature against digest signed by public key.
        """
        #public_key = self.key.publickey()
        #return public_key.verify(digest, (signature, ))
        return self.key.verify(digest, (signature, ))

    @property
    def key(self):
        return self._key

    @property
    def size(self):
        return self.key.n


class PublicKey(_PublicKey):
    """
    Represents a RSA public key.

    :param encoded_key:
        The encoded key string.
    :param encoding:
        The encoding method of the key. Default PEM.
    """
    def __init__(self, key_info, encoded_key, encoding):
        super(PublicKey, self).__init__(key_info, encoded_key, encoding)
        key_info_args = (
            self.key_info["modulus"],
            self.key_info["exponent"],
        )
        self._key = RSA.construct(key_info_args)

    def _sign(self, digest):
        """
        Sign the digest.
        """
        return self.key.sign(digest, "")[0]

    def _verify(self, digest, signature):
        """
        Verify signature against digest signed by public key.
        """
        return self.key.verify(digest, (signature, ))

    @property
    def key(self):
        return self._key

    @property
    def size(self):
        return self.key.n
