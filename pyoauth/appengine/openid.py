#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import urlparse
import urllib

from google.appengine.api import urlfetch


class OpenIdMixin(object):
    """
    Abstract implementation of OpenID and Attribute Exchange.

    See GoogleMixin for example implementation.
    """

    # Implement this in subclasses.
    #_OPENID_ENDPOINT = None

    def authenticate_redirect(self, callback_uri=None, ax_attrs=None):
        """
        Redirects to the authentication URL for this service.

        After authentication, the service will redirect back to the given
        callback URI.

        We request the given attributes for the authenticated user by default
        (name, email, language, and username). If you don't need all those
        attributes for your app, you can request fewer with the ax_attrs keyword
        argument.

        :param callback_uri:
            The URL to redirect to after authentication.
        :param ax_attrs:
            List of Attribute Exchange attributes to be fetched.
        :returns:
            None
        """
        ax_attrs = ax_attrs or ["name", "email", "language", "username"]
        request_uri = self.request.path

        callback_uri = callback_uri or request_uri
        args = self._openid_args(callback_uri, ax_attrs=ax_attrs)
        self.redirect(self._OPENID_ENDPOINT + "?" + urllib.urlencode(args))


    def get_authenticated_user(self, callback):
        """
        Fetches the authenticated user data upon redirect.

        This method should be called by the handler that handles the callback
        URL to which the service redirects when the authenticate_redirect()
        or authorize_redirect() methods are called.

        :param callback:
            A function that is called after the authentication attempt. It is
            called passing a dictionary with the requested user attributes or
            None if the authentication failed.
        """
        request_arguments = self.request.params

        # Verify the OpenID response via direct request to the OP
        args = dict((k, v[-1]) for k, v in request_arguments.iteritems())
        args["openid.mode"] = u"check_authentication"
        url = self._OPENID_ENDPOINT

        try:
            response = urlfetch.fetch(url, deadline=10, method=urlfetch.POST,
                                      payload=urllib.urlencode(args))
            if response.status_code < 200 or response.status_code >= 300:
                logging.warning("Invalid OpenID response (%d): %s",
                                response.status_code, response.content)
            else:
                self._on_authentication_verified(callback, response)
                return
        except urlfetch.DownloadError, e:
            logging.exception(e)
        self._on_authentication_verified(callback, None)


    def _openid_args(self, callback_uri, ax_attrs=None, oauth_scope=None):
        """
        Builds and returns the OpenID arguments used in the authentication request.

        :param callback_uri:
            The URL to redirect to after authentication.
        :param ax_attrs:
            List of Attribute Exchange attributes to be fetched.
        :param oauth_scope:
            OAuth scope.
        :returns:
            A dictionary of arguments for the authentication URL.
        """
        ax_attrs = ax_attrs or []
        url = urlparse.urljoin(self.request.url, callback_uri)
        request_host = self.request.host
        request_protocol = self.request.scheme

        args = {
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.claimed_id":
                "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.identity":
                "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.return_to": url,
            "openid.realm": request_protocol + "://" + request_host + "/",
            "openid.mode": "checkid_setup",
            }
        if ax_attrs:
            args.update({
                "openid.ns.ax": "http://openid.net/srv/ax/1.0",
                "openid.ax.mode": "fetch_request",
                })
            ax_attrs = set(ax_attrs)
            required = []
            if "name" in ax_attrs:
                ax_attrs -= set(["name", "firstname", "fullname", "lastname"])
                required += ["firstname", "fullname", "lastname"]
                args.update({
                    "openid.ax.type.firstname":
                        "http://axschema.org/namePerson/first",
                    "openid.ax.type.fullname":
                        "http://axschema.org/namePerson",
                    "openid.ax.type.lastname":
                        "http://axschema.org/namePerson/last",
                    })
            known_attrs = {
                "email": "http://axschema.org/contact/email",
                "language": "http://axschema.org/pref/language",
                "username": "http://axschema.org/namePerson/friendly",
                }
            for name in ax_attrs:
                args["openid.ax.type." + name] = known_attrs[name]
                required.append(name)
            args["openid.ax.required"] = ",".join(required)
        if oauth_scope:
            args.update({
                "openid.ns.oauth":
                    "http://specs.openid.net/extensions/oauth/1.0",
                "openid.oauth.consumer": request_host.split(":")[0],
                "openid.oauth.scope": oauth_scope,
                })
        return args


    def _on_authentication_verified(self, callback, response):
        """
        Called after the authentication attempt. It calls the callback function
        set when the authentication process started, passing a dictionary of
        user data if the authentication was successful or None if it failed.

        :param callback:
            A function that is called after the authentication attempt
        """
        if not response:
            logging.warning("Missing OpenID response.")
            callback(None)
            return
        elif response.status_code < 200 or response.status_code >= 300 or \
             u"is_value:true" not in response.content:
            logging.warning("Invalid OpenID response (%d): %s",
                            response.status_code, response.content)
            callback(None)
            return

        request_arguments = self.request.params
        claimed_id = self.request.get("openid.claimed_id", u"")

        # Make sure we got back at least an email from Attribute Exchange.
        ax_ns = None
        for name, values in request_arguments.iteritems():
            if name.startswith("openid.ns.") and\
               values[-1] == u"http://openid.net/srv/ax/1.0":
                ax_ns = name[10:]
                break

        email = self._get_ax_arg("http://axschema.org/contact/email", ax_ns)
        name = self._get_ax_arg("http://axschema.org/namePerson", ax_ns)
        first_name = self._get_ax_arg("http://axschema.org/namePerson/first",
                                      ax_ns)
        last_name = self._get_ax_arg("http://axschema.org/namePerson/last",
                                     ax_ns)
        username = self._get_ax_arg("http://axschema.org/namePerson/friendly",
                                    ax_ns)
        locale = self._get_ax_arg("http://axschema.org/pref/language",
                                  ax_ns).lower()

        user = dict()
        name_parts = []
        if first_name:
            user["first_name"] = first_name
            name_parts.append(first_name)
        if last_name:
            user["last_name"] = last_name
            name_parts.append(last_name)
        if name:
            user["name"] = name
        elif name_parts:
            user["name"] = u" ".join(name_parts)
        elif email:
            user["name"] = email.split("@")[0]
        if email: user["email"] = email
        if locale: user["locale"] = locale
        if username: user["username"] = username

        # Get the claimed ID. Not in facebook code. Borrowed from Tipfy.
        user["claimed_id"] = claimed_id

        callback(user)


    def _get_ax_arg(self, uri, ax_ns):
        """
        Returns an Attribute Exchange value from the request.

        :param uri:
            Attribute Exchange URI.
        :param ax_ns:
            Attribute Exchange namespace.
        :returns:
            The Attribute Exchange value, if found in the request.
        """
        request_arguments = self.request.params

        if not ax_ns:
            return u""
        prefix = "openid." + ax_ns + ".type."
        ax_name = None
        for name, values in request_arguments.iteritems():
            if values[-1] == uri and name.startswith(prefix):
                part = name[len(prefix):]
                ax_name = "openid." + ax_ns + ".value." + part
                break
        if not ax_name:
            return u""
        return self.request.get(ax_name, u"")

