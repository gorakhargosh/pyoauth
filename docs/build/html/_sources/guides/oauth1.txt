
.. include:: ../global.rst.inc

.. guide_oauth1:


A typical OAuth 1.0 flow in simple words
========================================

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


.. toctree::
   :maxdepth: 2
