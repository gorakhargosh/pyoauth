
.. include:: ../global.rst.inc

.. _using-rsa-sha1:


Using RSA-SHA1 signatures
=========================

::

    -----BEGIN RSA PRIVATE KEY-----
    MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
    A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
    7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
    hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
    X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
    uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
    rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
    zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
    qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
    WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
    cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
    3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
    AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
    Lw03eHTNQghS0A==
    -----END RSA PRIVATE KEY-----

    -----BEGIN PUBLIC KEY-----
     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0YjCwIfYoprq/FQO6lb3asXrx
     LlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlYzypSRjVxwxrsuRcP3e641SdASwfr
     mzyvIgP08N4S0IFzEURkV1wp/IpH7kH41EtbmUmrXSwfNZsnQRE5SYSOhh+LcK2w
     yQkdgcMv11l4KoBkcwIDAQAB
     -----END PUBLIC KEY-----

    -----BEGIN CERTIFICATE-----
    MIIBpjCCAQ+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAZMRcwFQYDVQQDDA5UZXN0
    IFByaW5jaXBhbDAeFw03MDAxMDEwODAwMDBaFw0zODEyMzEwODAwMDBaMBkxFzAV
    BgNVBAMMDlRlc3QgUHJpbmNpcGFsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
    gQC0YjCwIfYoprq/FQO6lb3asXrxLlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlY
    zypSRjVxwxrsuRcP3e641SdASwfrmzyvIgP08N4S0IFzEURkV1wp/IpH7kH41Etb
    mUmrXSwfNZsnQRE5SYSOhh+LcK2wyQkdgcMv11l4KoBkcwIDAQABMA0GCSqGSIb3
    DQEBBQUAA4GBAGZLPEuJ5SiJ2ryq+CmEGOXfvlTtEL2nuGtr9PewxkgnOjZpUy+d
    4TvuXJbNQc8f4AMWL/tO9w0Fk80rWKp9ea8/df4qMq5qlFWlx6yOLQxumNOmECKb
    WpkUQDIDJEoFUzKMVuJf4KO/FJ345+BNLGgbJ6WujreoM1X/gYfdnJ/J
    -----END CERTIFICATE-----


Whoa?!
------
Betchyoo weren't expecting that. Ha!

    "What's up with all that gibberish up there, man?" you ask.

::

      ____________________________________
     /                                    \
    |                                      |
    |   Yeah, dude. I mean, up there! -^   |
    |                                      |
     \____________________________________/
                                   V
                                  You. =O


That, my friend, is three friends. Wait, my grammar has left with the wind.

    "Three friends, huh?"

Yep, three friends. They keep your privates private and your publics... err,
they're not really worried about your publics.

    "Do these friends have names, man?"

Yeah. They're:

1. RSA private key
2. RSA public key
3. X.509 certificate

They're a happy couple.

    "One. Two. Three. Hmm. Oye, that's 3 of them. Couple? So, umm... how do they
    work? Somethin' to do with opensll yeah?"

We'll get to this in a bit. Kinda, yes, and that's "OpenSSL," by the way.


Why should you use public-key encryption?
-----------------------------------------
Because it's harder—it's harder for an attacker to snoop into your privacy.
Consider two people, say A and B, trying to communicate securely with each
other. What they need to communicate securely are these guarantees:

1. Ensure that the messages that A and B exchange are **confidential**.
2. Ensure that the message that B receives from A were **actually sent by A**
   and vice versa.
3. Ensure that the messages that A and B exchange **aren't tampered with while
   in transit**.

Using public-key encryption provides those guarantees. Now, using RSA-SHA-1
signatures shouldn't be as difficult as they are to use with OAuth. Therefore,
we have tried to take the burden of implementing it away from you and made
it as easy as possible for you to use this signature method.

So how does OAuth use public-key encryption?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
OAuth requires the use of SSL by the clients when requesting token secrets
from OAuth servers. This takes care of the confidential part. The other two
are handled by RSA-SHA-1 signatures.

Imagine public-key encryption as equivalent to having a lock with two
complementary keys—that is, if you lock something with one key, only the
other key can open it. So, RSA public-key encryption uses the notion of these
two keys to secure your messages. Here is what you have to do to use
these keys with OAuth:

1. You share your public key (an RSA public key or an X.509 public-key
   certificate) with the OAuth provider.

2. Sign your messages with your RSA private key (which you keep safe and don't
   share with anybody else including the OAuth provider).

3. The OAuth provider can now use the public key that you shared with it
   to verify the messages that you sent to it signed with your private key.

So, after that, all you have to do is use ``"RSA-SHA1"`` as your signature
method to build your client requests. That's essentially it. Easy, huh?


What does a key look like?
--------------------------

A key can come in multiple formats. The PEM_, or Privacy Enhanced
electronic-Mail, format is a commonly accepted format, and that is the one
preferred by this library. Keys can be also stored in JSON formats as the one
used by the Keyczar_ library. Have a look at the
`Keyczar RSA private key format`_. Public keys that you generate are
generally encoded into something called an X.509 public-key certificate.
You can share either an RSA public key or an X.509 public-key certificate
with your OAuth provider. Providers usually ask for an X.509 public-key
certificate.

RSA Private Key
~~~~~~~~~~~~~~~

An example::

    -----BEGIN RSA PRIVATE KEY-----
    MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
    A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
    7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
    hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
    X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
    uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
    rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
    zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
    qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
    WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
    cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
    3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
    AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
    Lw03eHTNQghS0A==
    -----END RSA PRIVATE KEY-----

RSA Public Key
~~~~~~~~~~~~~~

An example::

    -----BEGIN PUBLIC KEY-----
     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0YjCwIfYoprq/FQO6lb3asXrx
     LlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlYzypSRjVxwxrsuRcP3e641SdASwfr
     mzyvIgP08N4S0IFzEURkV1wp/IpH7kH41EtbmUmrXSwfNZsnQRE5SYSOhh+LcK2w
     yQkdgcMv11l4KoBkcwIDAQAB
     -----END PUBLIC KEY-----

X.509 Public-key Certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An example::

    -----BEGIN CERTIFICATE-----
    MIIBpjCCAQ+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAZMRcwFQYDVQQDDA5UZXN0
    IFByaW5jaXBhbDAeFw03MDAxMDEwODAwMDBaFw0zODEyMzEwODAwMDBaMBkxFzAV
    BgNVBAMMDlRlc3QgUHJpbmNpcGFsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
    gQC0YjCwIfYoprq/FQO6lb3asXrxLlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlY
    zypSRjVxwxrsuRcP3e641SdASwfrmzyvIgP08N4S0IFzEURkV1wp/IpH7kH41Etb
    mUmrXSwfNZsnQRE5SYSOhh+LcK2wyQkdgcMv11l4KoBkcwIDAQABMA0GCSqGSIb3
    DQEBBQUAA4GBAGZLPEuJ5SiJ2ryq+CmEGOXfvlTtEL2nuGtr9PewxkgnOjZpUy+d
    4TvuXJbNQc8f4AMWL/tO9w0Fk80rWKp9ea8/df4qMq5qlFWlx6yOLQxumNOmECKb
    WpkUQDIDJEoFUzKMVuJf4KO/FJ345+BNLGgbJ6WujreoM1X/gYfdnJ/J
    -----END CERTIFICATE-----


Making your own key-pair
------------------------

    "Alright. I get it Sherlock. Now, how do I make my pair of keys
    to use with an OAuth provider?"

You can generate your own self-signed X.509 certificate and private RSA key
using the tools OpenSSL provides. You'll need OpenSSL_ installed for the
following command to work at the terminal::

    $ openssl req -x509 -nodes -days 365 -newkey rsa:1024 -sha1 -keyout \
        rsa_private_key.pem -out x509_public_certificate.pem

Answer all the questions that the tool asks and you should be good to go.
For more detailed information about generating X.509 public-key certificates,
read:

1. http://www.ipsec-howto.org/x595.html
2. http://www.imacat.idv.tw/tech/sslcerts.html#reqform


.. toctree::
   :maxdepth: 2
