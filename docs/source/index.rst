.. pyoauth documentation master file, created by
   sphinx-quickstart on Thu Jun 23 23:23:49 2011.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

.. include:: global.rst.inc

PyOAuth
=======

A Python library that implements the OAuth protocol for clients and servers.

About the implementation
------------------------
This library implements version 1.0 of the OAuth protocol as per
the RFC5849_ specification, which supersedes any previous versions of the
protocol.

Client classes do not send HTTP requests but implement enough of the
OAuth protocol to help you build request proxies that can be used to send actual
HTTP requests. In essence, it implements OAuth 1.0 and nothing else.

This is a very conscious decision by the library authors. It allows
framework authors and API users to use the library without pulling in
unnecessary dependencies which may not work on their platform of choice.
For example, you can use any of httplib2_, tornado_, webapp2_, or django_ to
send HTTP requests built with this library.

Wherever possible the implementation tries to warn you about problems you may
encounter when processing or building OAuth requests by using a fail-fast
approach. For example, OAuth relies on the availability of SSL to communicate
securely, and therefore, the library does check whether the OAuth endpoint URLs
you specify use SSL. Of course, we won't stop you from forcing otherwise, but
we have taken great care to ensure that you will be warned.

Signature methods
~~~~~~~~~~~~~~~~~
All the signature methods mentioned in the OAuth specification have been
implemented by this library, namely:

1. PLAINTEXT
2. HMAC-SHA1
3. RSA-SHA1

However, the RSA-SHA1 signature method relies on the availability of
third-party libraries like PyCrypto_ or M2Crypto_.

RSA-SHA1 requirements
*********************
The RSA-SHA1 signature methods accept PEM-encoded X.509 certificates,
RSA public keys, and RSA private keys. The validity of the X.509 certificates
will not be verified by any of these routines. You must ensure the validity of
certificates you accept by using other utility methods provided by this
library.

For a quick rundown about these certificates and keys, please read
:ref:`using-rsa-sha1`.

Easy explanation of an OAuth flow in simple words
-------------------------------------------------

1. Construct a client with its client credentials.

2. Send an HTTPS request for temporary credentials with a callback URL
   which the server will call with an OAuth verification code after
   authorizing the resource owner (end-user).

3. Obtain temporary credentials from a successful server response.

4. Use the temporary credentials to build an authorization URL and
   redirect the resource owner (end-user) to the generated URL.

5. If a callback URL is not provided when requesting temporary credentials,
   the server displays the OAuth verification code to the resource owner
   (end-user), which she then types into your application.

   OR

   If a callback URL is provided, the server redirects the resource owner
   (end-user) after authorization to your callback URL attaching the
   OAuth verification code as a query parameter.

6. Using the obtained OAuth verification code from step 5 and the
   temporary credentials obtained in step 3, send an HTTPS request for
   token credentials.

7. Obtain token credentials from a successful server response.

8. Save the token credentials for future use (say, in a database).


Accessing a resource
--------------------

1. Construct a client with its client credentials.

2. Using the token credentials that you have saved (say, in a database),
   send an HTTP request to a resource URL.

3. Obtain the response and deal with it.



User's Guide:
=============

.. toctree::
   :maxdepth: 2

   api
   hacking
   rsa_sha1

Contribute
==========
Found a bug in or want a feature added to |project_name|?
You can fork the official `code repository`_ or file an issue ticket
at the `issue tracker`_. You may also want to refer to :ref:`hacking` for
information about contributing code or documentation to |project_name|.


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

