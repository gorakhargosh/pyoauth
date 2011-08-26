#!/usr/bin/env python
# -*- coding: utf-8 -*-

import webbrowser
from pprint import pprint

from pyoauth.httplib2.httpclient import HttpClient
from pyoauth.oauth1.client.google import GoogleClient
from pyoauth.oauth1 import Credentials

client_credentials = Credentials('CONSUMER-KEY',
                                 'CONSUMER-SECRET')
client = GoogleClient(HttpClient(), client_credentials,
                      scopes=['https://docs.google.com/feeds/'])

def main():
    temp, _ = client.fetch_temporary_credentials()
    webbrowser.open(client.get_authorization_url(temp), new=2, autoraise=True)

    oauth_verifier = raw_input("Enter verification code: ")
    client.check_verification_code(temp, temp.identifier, oauth_verifier)
    token, _ = client.fetch_token_credentials(temp, oauth_verifier)
    pprint(token.to_dict())


if __name__ == "__main__":
    main()
