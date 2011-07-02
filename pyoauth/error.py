#!/usr/bin/env python
# -*- coding: utf-8 -*-


class OAuthError(RuntimeError):
    """
    Base exception class.
    """
    def __init__(self, message="OAuth error occurred"):
        self._message = message
        super(OAuthError, self).__init__()

    @property
    def message(self):
        """A hack to get around the deprecation errors in Python 2.6"""
        return self._message

    def __str__(self):
        return self._message


class InvalidQueryParametersError(OAuthError):
    pass

class InsecureOAuthParametersError(OAuthError):
    pass

class InvalidOAuthParametersError(OAuthError):
    pass

class InsecureOAuthUrlError(OAuthError):
    pass

class InvalidUrlError(OAuthError):
    pass

class InvalidHttpMethodError(OAuthError):
    pass

class InvalidAuthorizationHeaderError(OAuthError):
    pass
