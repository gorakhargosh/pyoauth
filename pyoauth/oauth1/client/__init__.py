# -*- coding: utf-8 -*-

from pyoauth.decorators import deprecated
from pyoauth.oauth1 import SIGNATURE_METHOD_HMAC_SHA1, SIGNATURE_METHOD_RSA_SHA1, SIGNATURE_METHOD_PLAINTEXT
from pyoauth.utils import oauth_generate_nonce, \
    oauth_generate_timestamp, \
    oauth_get_hmac_sha1_signature, \
    oauth_get_rsa_sha1_signature, \
    oauth_get_plaintext_signature, oauth_get_normalized_authorization_header_value


class Credentials(object):
    def __init__(self, identifier, shared_secret):
        """
        OAuth Credentials.

        :param identifier:
            Identifier (old: key)
        :param shared_secret:
            Shared secret (old: secret)
        """
        self._identifier = identifier
        self._shared_secret = shared_secret

    @property
    def identifier(self):
        return self._identifier

    @property
    def shared_secret(self):
        return self._shared_secret

    @property
    @deprecated
    def key(self):
        return self._identifier

    @property
    @deprecated
    def secret(self):
        return self._shared_secret


    def to_oauth_dict(self):
        """Overriden by each credential type."""
        raise NotImplementedError()

SIGNATURE_METHOD_MAP = {
    SIGNATURE_METHOD_HMAC_SHA1: oauth_get_hmac_sha1_signature,
    SIGNATURE_METHOD_RSA_SHA1: oauth_get_rsa_sha1_signature,
    SIGNATURE_METHOD_PLAINTEXT: oauth_get_plaintext_signature,
}


class Client(object):
    def __init__(self,
                 http_client,
                 client_credentials,
                 temporary_credentials_request_uri,
                 resource_owner_authorization_uri,
                 token_request_uri,
                 use_authorization_header=True):
        self._http_client = http_client
        self._client_credentials = client_credentials
        self._temporary_credentials_request_uri = temporary_credentials_request_uri
        self._resource_owner_authorization_uri = resource_owner_authorization_uri
        self._token_request_uri = token_request_uri
        self._use_authorization_header = use_authorization_header

    @property
    def oauth_version(self):
        return "1.0"


    def _sign_request(self, signature_method,
             method, url, oauth_params,
             credentials=None):
        sign_func = SIGNATURE_METHOD_MAP[signature_method]
        credentials_shared_secret = credentials.shared_secret if credentials else None
        return sign_func(self.client_credentials.shared_secret, method, url, oauth_params, credentials_shared_secret)

    def request(self, method, url, payload_params, headers=None):

        headers = headers or {}
        if method.upper() == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"


    def request_temporary_credentials(self,
                                      method,
                                      payload_params=None,
                                      realm=None,
                                      oauth_callback=None,
                                      oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                                      **extra_oauth_params):
        oauth_args = dict(
            oauth_consumer_key=self._client_credentials.identifier,
            oauth_signature_method=oauth_signature_method,
            oauth_timestamp=oauth_generate_timestamp(),
            oauth_nonce=oauth_generate_nonce(),
            oauth_version=self.oauth_version,
        )
        if oauth_callback:
            oauth_args["oauth_callback"] = oauth_callback
        oauth_args.update(extra_oauth_params)

        url = self._temporary_credentials_request_uri
        oauth_args["oauth_signature"] = self._sign_request(oauth_signature_method, method, url, oauth_args)

        headers = {}
        if self._use_authorization_header:
            auth_header_value = oauth_get_normalized_authorization_header_value(oauth_params, realm=realm)
            headers["Authorization"] = auth_header_value
        else:



        # TODO: Create temporary credentials request URL.
        # TODO: Send an HTTP request to this URL with the header if allowed.
        # TODO: return temporary credentials if successful.
        pass



"""
def request_temporary_credentials(http_client,
                                  client_credentials,
                                  method,
                                  temporary_credentials_request_uri,
                                  oauth_params,
                                  realm=None,
                                  use_authorization_header=True):


# Response contains temporary credentials

def get_authorization_url(temporary_credentials,
                          resource_owner_authorization_uri):
    pass

# Send the user to the authorization URL.

# User signs in at that URL.

# Got verifier from server redirect if callback set when
# requesting temporary credentials or user is shown the verifier which
# is input into the client.

def request_token_credentials(http_client,
                              client_credentials,
                              temporary_credentials,
                              method,
                              token_request_uri,
                              realm=None,
                              use_authorization_header=True):
    pass

# Response contains token credentials
# Save these credentials.

def request_api(http_client,
                client_credentials,
                token_credentials,
                method,
                api_uri,
                realm=None,
                use_authorization_header=True):
    pass
"""
