# -*- coding: utf-8 -*-
import logging

from pyoauth.decorators import deprecated
from pyoauth.oauth1 import SIGNATURE_METHOD_HMAC_SHA1, \
    SIGNATURE_METHOD_RSA_SHA1, \
    SIGNATURE_METHOD_PLAINTEXT
from pyoauth.url import oauth_url_sanitize, oauth_protocol_params_sanitize, oauth_url_query_params_sanitize, oauth_url_query_params_add, oauth_urlencode_s, oauth_url_concat
from pyoauth.utils import oauth_generate_nonce, \
    oauth_generate_timestamp, \
    oauth_get_hmac_sha1_signature, \
    oauth_get_rsa_sha1_signature, \
    oauth_get_plaintext_signature, \
    oauth_get_normalized_authorization_header_value


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


class Request(object):
    def __init__(self, method, url, payload=None, headers=None):
        self._method = method
        self._url = url
        self._payload = payload
        self._headers = headers

    @property
    def method(self):
        return self._method

    @property
    def url(self):
        return self._url

    @property
    def payload(self):
        return self._payload

    @property
    def body(self):
        return self.payload

    @property
    def headers(self):
        return self._headers


class Client(object):
    def __init__(self,
                 client_credentials,
                 temporary_credentials_request_uri,
                 resource_owner_authorization_uri,
                 token_request_uri,
                 use_authorization_header=True):
        """
        Creates an instance of an OAuth client.

        :param client_credentials:
            Client (consumer) credentials.
        :param temporary_credentials_request_uri:
            OAuth request token URI.

            Any query parameters starting with "oauth_" will be excluded from
            the URL. All OAuth parameters must be specified in their respective
            requests.
        :param resource_owner_authorization_uri:
            OAuth authorization URI.

            Any query parameters starting with "oauth_" will be excluded from
            the URL. All OAuth parameters must be specified in their respective
            requests.
        :param token_request_uri:
            OAuth access token request URI.

            Any query parameters starting with "oauth_" will be excluded from
            the URL. All OAuth parameters must be specified in their respective
            requests.
        :param use_authorization_header:
            ``True`` to use the HTTP Authorization header to pass OAuth
            parameters; ``False`` will force using the URL query string or
            the entity-body of a request.
        """
        self._client_credentials = client_credentials
        self._temporary_credentials_request_uri = oauth_url_sanitize(temporary_credentials_request_uri)
        self._resource_owner_authorization_uri = oauth_url_sanitize(resource_owner_authorization_uri)
        self._token_request_uri = oauth_url_sanitize(token_request_uri)
        self._use_authorization_header = use_authorization_header

    @property
    def oauth_version(self):
        """Must return ``1.0`` (unless for compatibility, in which case,
        you are all by yourself.)"""
        return "1.0"

    def _sign_request_data(self, signature_method,
             method, url, oauth_params,
             credentials=None):
        sign_func = SIGNATURE_METHOD_MAP[signature_method]
        credentials_shared_secret = credentials.shared_secret if credentials else None
        return sign_func(self._client_credentials.shared_secret,
                         method, url, oauth_params,
                         credentials_shared_secret)

    def build_temporary_credentials_request(self,
                                            method,
                                            payload_params=None,
                                            realm=None,
                                            oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                                            oauth_callback=None,
                                            **extra_oauth_params):
        oauth_request_url = self._temporary_credentials_request_uri
        return self.build_request(method=method,
                                       oauth_request_url=oauth_request_url,
                                       payload_params=payload_params,
                                       realm=realm,
                                       oauth_signature_method=oauth_signature_method,
                                       oauth_callback=oauth_callback,
                                       **extra_oauth_params)

    def build_request(self,
                      method,
                      oauth_request_url,
                      payload_params=None,
                      realm=None,
                      oauth_signature_method=SIGNATURE_METHOD_HMAC_SHA1,
                      **extra_oauth_params):
        """
        Builds request data.

        :param method:
            HTTP request method.
        :param payload_params:
            A dictionary of payload parameters. These will be serialized
            into the URL or the entity-body depending on the HTTP request method.
            These must not include any parameters starting with "oauth_".
        :param realm:
            The value to use for the realm parameter in the Authorization HTTP
            header. It will be excluded from the base string, however.
        :param oauth_callback:
            A callback URL that you want the server to call when done
            with your requests.
        :param oauth_signature_method:
            One of ``SIGNATURE_METHOD_HMAC_SHA1``,
            ``SIGNATURE_METHOD_RSA_SHA1``, or ``SIGNATURE_METHOD_PLAINTEXT``.
        :param extra_oauth_params:
            Any additional oauth parameters you would like to include.
            The parameter names must begin with "oauth_" otherwise they will
            not be included.
        """
        # Common OAuth params.
        oauth_params = dict(
            oauth_consumer_key=self._client_credentials.identifier,
            oauth_signature_method=oauth_signature_method,
            oauth_timestamp=oauth_generate_timestamp(),
            oauth_nonce=oauth_generate_nonce(),
            oauth_version=self.oauth_version,
        )

        # Filter and add additional OAuth parameters.
        extra_oauth_params = oauth_protocol_params_sanitize(extra_oauth_params)
        for k, v in extra_oauth_params.items():
            if k.startswith("oauth_"):
                if k in ("oauth_signature",):
                    logging.warning("Extra protocol parameter `%r` will be ignored.", k)
                    continue
                elif k == "oauth_callback" and v:
                    oauth_params["oauth_callback"] = v
                else:
                    if oauth_params.has_key(k):
                        # Warn when an existing protocol parameter is being
                        # overridden.
                        logging.warning("Overriding existing protocol parameter `%r`=`%r` with `%r`=`%r`",
                                        k, oauth_params[k], k, v)
                    oauth_params[k] = v

        # Filter payload parameters for the request.
        payload_params = oauth_url_query_params_sanitize(payload_params)

        # Determine the request's OAuth signature.
        signature_url = oauth_url_query_params_add(oauth_request_url, payload_params)
        oauth_params["oauth_signature"] = self._sign_request_data(oauth_signature_method,
                                                                  method, signature_url, oauth_params)

        # Build request data now.
        request_headers = {}
        if self._use_authorization_header:
            auth_header_value = oauth_get_normalized_authorization_header_value(oauth_params, realm=realm)
            request_headers["Authorization"] = auth_header_value

        if method == "GET":
            request_url = oauth_url_concat(signature_url, oauth_params)
            request_payload = ""
        elif method == "POST":
            request_url = oauth_request_url
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            request_payload = oauth_urlencode_s(payload_params)
        else:
            raise NotImplementedError("Not implemented any other HTTP methods yet.")

        return Request(method, url=request_url, payload=request_payload, headers=request_headers)



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
