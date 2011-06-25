# -*- coding: utf-8 -*-

import urllib
import pyoauth.utils

print pyoauth.utils.oauth_parse_authorization_header_value('''
    OAuth

    realm="Examp%20le",
    oauth_consumer_key="0685bd9184jfhq22",
    oauth_token="ad180jjd733klru7",
    oauth_signature_method="HMAC-SHA1",
    oauth_signature="wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
    oauth_timestamp="137131200",
    oauth_nonce="4572616e48616d6d65724c61686176",
    oauth_version="1.0",
    oauth_something="%20Some+Example",
    oauth_empty="",
''')

u = u'åéîøü'.encode('utf16')
print urllib.quote(u, safe="~")

