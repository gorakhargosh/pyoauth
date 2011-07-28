#!/usr/bin/env python
# -*- coding: utf-8 -*-

import webbrowser
from pprint import pprint

import httplib2
import sys
from pyoauth.oauth1.client.google import GoogleClient
from pyoauth.oauth1.client.twitter import TwitterClient

httplib2.debuglevel = 1

from pyoauth.oauth1 import Credentials
from pyoauth.httplib2.httpclient import HttpClient

client_info = {
    'twitter': dict(
        client=TwitterClient(HttpClient(),
                             client_credentials=\
                                Credentials('CONSUMER-KEY',
                                 'CONSUMER-SECRET')),
        temporary_credentials_params=dict(),
    ),
    'google': dict(
        client=GoogleClient(HttpClient(),
                             client_credentials=\
                                Credentials('CONSUMER-KEY',
                                 'CONSUMER-SECRET')),
        temporary_credentials_params=dict(
            scopes=['https://docs.google.com/feeds/'],
        ),
    ),
}


def main(service_name):
    service = client_info[service_name]
    oauth = service["client"]

    # Fetch temporary credentials.
    response = oauth.fetch_temporary_credentials(
        **service["temporary_credentials_params"]
    )
    print("Temporary credentials response: %r" % response.body)
    temporary_credentials, _ = \
        oauth.parse_temporary_credentials_response(response)

    # Open the web browser to allow the user to authorize and grab
    # the verification code. (Emulates redirect).
    try:
        webbrowser.open(oauth.get_authentication_url(temporary_credentials),
                        new=2, autoraise=True)
    except NotImplementedError:
        webbrowser.open(oauth.get_authorization_url(temporary_credentials),
                        new=2, autoraise=True)

    # Get the verification code.
    oauth_verifier = oauth.check_verification_code(temporary_credentials,
                                  temporary_credentials.identifier,
                                  raw_input("Enter verification code: "))

    # Now fetch the token credentials.
    response = oauth.fetch_token_credentials(temporary_credentials,
                                             oauth_verifier)
    print("Token credentials response: %r" % response)
    token_credentials, _ = oauth.parse_token_credentials_response(response)

    # Whee. There are your token credentials, to make more requests
    # using oauth.fetch().
    print("Here are your token credentials (access token/secret pair).")
    pprint(token_credentials.to_dict())


if __name__ == "__main__":
    main(sys.argv[1])
