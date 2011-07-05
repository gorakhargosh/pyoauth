# Copyright (C) 2010 Rick Copeland <rcopeland@geek.net>

# OLD
#try:
#    from Crypto.PublicKey import RSA
#    from Crypto.Util.number import long_to_bytes, bytes_to_long
#except ImportError:
#    RSA = None
#    def long_to_bytes(v):
#        raise NotImplementedError()
#    def bytes_to_long(v):
#        raise NotImplementedError()
#
#
#def pkcs1_v1_5_encode(key, data):
#    """
#    Encodes a SHA1 digest using PKCS1's emsa-pkcs1-v1_5 encoding.
#
#    Adapted from paramiko.
#
#    :author:
#        Rick Copeland <rcopeland@geek.net>
#
#    :param key:
#        RSA Key.
#    :param data:
#        Data
#    :returns:
#        A blob of data as large as the key's N, using PKCS1's
#        "emsa-pkcs1-v1_5" encoding.
#    """
#    SHA1_DIGESTINFO = '\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
#    size = len(long_to_bytes(key.n))
#    filler = '\xff' * (size - len(SHA1_DIGESTINFO) - len(data) - 3)
#    return '\x00\x01' + filler + '\x00' + SHA1_DIGESTINFO + data
#

#def old_generate_rsa_sha1_signature(client_private_key,
#                           method, url, oauth_params=None,
#                           token_or_temporary_shared_secret=None,
#                           _test_rsa=RSA):
#    # Arguments.
#    oauth_params = oauth_params or {}
#    if _test_rsa is None:
#        raise NotImplementedError()
#    try:
#        getattr(client_private_key, "sign")
#        private_key = client_private_key
#    except AttributeError:
#        private_key = _test_rsa.importKey(client_private_key)
#
#    # Calculate the base string.
#    base_string = generate_signature_base_string(method, url, oauth_params)
#
#    signature = private_key.sign(
#        pkcs1_v1_5_encode(
#            private_key,
#            sha1(base_string).digest()
#        ), ""
#    )[0]
#    signature_bytes = long_to_bytes(signature)
#
#    return binascii.b2a_base64(signature_bytes)[:-1]


#def old_check_rsa_sha1_signature(signature,
#                             client_public_key,
#                             method, url, oauth_params=None,
#                             token_or_temporary_shared_secret=None,
#                             _test_rsa=RSA):
#    oauth_params = oauth_params or {}
#
#    if _test_rsa is None:
#        raise NotImplementedError()
#
#    try:
#        getattr(client_public_key, "publickey")
#        key = client_public_key
#    except AttributeError:
#        key = _test_rsa.importKey(client_public_key)
#
#    base_string = generate_signature_base_string(method, url, oauth_params)
#
#    digest = sha1(base_string).digest()
#    signature = bytes_to_long(binascii.a2b_base64(signature))
#    data = pkcs1_v1_5_encode(key, digest)
#
#    return key.publickey().verify(data, (signature,))


#class Test_generate_and_check_rsa_sha1_signature(object):
#    # Taken from https://github.com/rick446/python-oauth2/commit/a8bee2ad1a993faa1e13a04f14f1754489ad35bd
#    def setUp(self):
#        self.oauth_signature_method = "RSA-SHA1"
#        self.oauth_token_key = "tok-test-key"
#        self.oauth_token_secret = "tok-test-secret"
#        self.oauth_consumer_key = "con-test-key"
#        self.oauth_consumer_secret = '''-----BEGIN RSA PRIVATE KEY-----
#MIIBOgIBAAJBAM7B+5TJsc93ymBSFtC5DE1qDlqvwio0xDfS6bZQTfFiHLm8pHXg
#Atkm7QB6gvyRKm+a/G3qEbmBdz21Fw0RLJsCAwEAAQJAS68qnr5uPlnFVRj3jRQP
#8s6dzoiD9Ns38I9eSgR/Y5ozl8r/cClLeGWvDKfXvrxlsaMuqWLZ5KMtamaRS9Fl
#sQIhAPmOY+s5ZxsYtem+Uc2IUGexNoP/Ng7MPS3C+Q3L6K4nAiEA1Biv6i7TqAbx
#oHulPIXb2Z9JmO46aT81n9WnD1qyim0CIF9eN/cLf8iOH+7MqYxHHJsT0QaOgEUV
#bgfP68eG9kufAiEAtUSAHGp29HUyzxC9sNNKiVysnuqDu22NXBRSmjnOu6UCIEFZ
#nqb0GVzfF6wbsf40mkp1kdHq/fNiFRrLYWWJSpGY
#-----END RSA PRIVATE KEY-----'''
#        self.http_method = "GET"
#        self.url = u"http://sp.example.com/?bar=blerg&multi=FOO&multi=BAR&foo=59"
#        self.oauth_params = dict(
#            oauth_version='1.0',
#            oauth_nonce="4572616e48616d6d65724c61686176",
#            oauth_timestamp="137131200",
#            oauth_token=self.oauth_token_key,
#            oauth_consumer_key=self.oauth_consumer_key,
#            oauth_signature_method=self.oauth_signature_method,
#        )
#        self.oauth_signature = "D2rdx9TiFajZbXChqMca6eaal8FxZhLMU1bdNX0glIN+BT4nrYGJqmIW92kWZYEYKHsVz7e67oDBEYlIIQMKWg=="
#
#    def test_get_signature(self):
#        from Crypto.PublicKey import RSA
#
#        # consumer_secret is a string.
#        assert_equal(old_generate_rsa_sha1_signature(
#            self.oauth_consumer_secret,
#            method=self.http_method,
#            url=self.url,
#            oauth_params=self.oauth_params,
#            token_or_temporary_shared_secret=self.oauth_token_secret
#        ), self.oauth_signature)
#
#        # consumer_secret is an RSA instance.
#        assert_equal(old_generate_rsa_sha1_signature(
#            RSA.importKey(self.oauth_consumer_secret),
#            method=self.http_method,
#            url=self.url,
#            oauth_params=self.oauth_params,
#            token_or_temporary_shared_secret=self.oauth_token_secret
#        ), self.oauth_signature)
#
#
#    def test_check_signature(self):
#        from Crypto.PublicKey import RSA
#
#        # consumer_secret is a string.
#        assert_true(old_check_rsa_sha1_signature(
#            signature=self.oauth_signature,
#            client_shared_secret=self.oauth_consumer_secret,
#            method=self.http_method,
#            url=self.url,
#            oauth_params=self.oauth_params,
#            token_or_temporary_shared_secret=self.oauth_token_secret
#        ))
#
#        # consumer_secret is an RSA instance.
#        assert_true(old_check_rsa_sha1_signature(
#            signature=self.oauth_signature,
#            client_shared_secret=RSA.importKey(self.oauth_consumer_secret),
#            method=self.http_method,
#            url=self.url,
#            oauth_params=self.oauth_params,
#            token_or_temporary_shared_secret=self.oauth_token_secret
#        ))
#
#    def test_get_raises_NotImplementedError_when_Crypto_unavailable(self):
#        # consumer_secret is a string.
#        assert_raises(NotImplementedError,
#                      old_generate_rsa_sha1_signature,
#                      self.oauth_consumer_secret,
#                      self.http_method,
#                      self.url,
#                      self.oauth_params,
#                      self.oauth_token_secret,
#                      _test_rsa=None
#        )
#
#    def test_check_raises_NotImplementedError_when_Crypto_unavailable(self):
#        # consumer_secret is a string.
#        assert_raises(NotImplementedError,
#                      old_check_rsa_sha1_signature,
#                      self.oauth_signature,
#                      self.oauth_consumer_secret,
#                      self.http_method,
#                      self.url,
#                      self.oauth_params,
#                      self.oauth_token_secret,
#                      _test_rsa=None
#        )
