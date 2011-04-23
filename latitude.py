#!/usr/bin/env python

import sys, time, ConfigParser
import oauth.oauth as oauth
import httplib, urlparse, BaseHTTPServer
from urllib2 import urlopen, Request

"""
http://code.google.com/apis/accounts/docs/OAuth.html
http://code.google.com/apis/accounts/docs/OAuth_ref.html
and the source of the python-oauth library to work out what it's doing:
https://github.com/leah/python-oauth/blob/master/oauth/oauth.py

This will move to python-oauth2 shortly.
"""


class OAuthCallbackHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    # Disable logging DNS lookups
    def address_string(self):
        return str(self.client_address[0])

    def do_GET(self):
        url = urlparse.urlparse(self.path)
        params = urlparse.parse_qs(url.query)
        path = url.path

        #if not started for one-off
        if path == '/add':
            callback_url = CALLBACK_BASE + '/authorized'

            # Currently the req_token is stored in the client,
            # but everything else is passed in via methods, so
            # it could easily be fixed for multiple requests.
            try:
                OAUTH.get_request_token(callback_url)
                auth_url = OAUTH.get_auth_url(callback_url)
            except Exception, e:
                print 'Unable to get token: %s' % repr(e)
                self.send_error(500, 'Unable to get token: %s' % repr(e))
            else:
                self.send_response(301)
                self.send_header('Location', auth_url)
                self.end_headers()

        elif path == '/authorized':
            try:
                OAUTH.process_authorized(params)
                auth_token = OAUTH.get_access_token()
            except Exception, e:
                print 'Authorisation failed: %s' % repr(e)
                self.send_error(500, 'Authorisation failed: %s' % repr(e))
            else:
                print 'Got auth token: %s' % auth_token
                self.send_response(200, 'Authorised')

            # if started for one-off, self.shutdown()

        else:
            self.send_error(404, 'File not found')


class GoogleOAuthClient():
    request_token_url = 'https://www.google.com/accounts/OAuthGetRequestToken'
    access_token_url  = 'https://www.google.com/accounts/OAuthGetAccessToken'

    def __init__(self, consumer, sig=oauth.OAuthSignatureMethod_HMAC_SHA1()):
        self.consumer = consumer
        self.signature_method = sig # TODO: support RSA_SHA1
        self.scopes = []

    def get_request_token(self, callback_url='oob'):
        req = oauth.OAuthRequest.from_consumer_and_token(
            self.consumer,
            callback=callback_url,
            http_url=self.request_token_url,
            parameters={'scope': ' '.join(self.scopes)},
        )
        req.sign_request(self.signature_method, self.consumer, None)

        # python-oauth puts it all in to_url anyway - headers=req.to_header()
        f = urlopen(Request(req.to_url()))
        self.req_token = oauth.OAuthToken.from_string(f.read())
        if self.req_token.callback_confirmed != 'true':
            raise Exception('Callback not confirmed')

    def get_access_token(self):
        req = oauth.OAuthRequest.from_consumer_and_token(
            self.consumer,
            token=self.req_token,
            verifier=self.verifier,
            http_url=self.access_token_url,
        )
        req.sign_request(self.signature_method, self.consumer, self.req_token)

        f = urlopen(Request(req.to_url()))
        token = oauth.OAuthToken.from_string(f.read())
        return token

    def get_auth_url(self):
        raise NotImplementedError

    def process_authorized(self, params):
        raise NotImplementedError


class LatitudeOAuthClient(GoogleOAuthClient):
    auth_url = 'https://www.google.com/latitude/apps/OAuthAuthorizeToken'
    resource_url = 'https://www.googleapis.com/latitude/v1/currentLocation'
    scope_url = 'https://www.googleapis.com/auth/latitude'

    def __init__(self, consumer, sig=oauth.OAuthSignatureMethod_HMAC_SHA1()):
        GoogleOAuthClient.__init__(self, consumer, sig=sig)
        self.scopes += [self.scope_url]

    def get_auth_url(self, callback_url,
            location='current', granularity='best'):

        # This is supremely pointless. It's just a URL.
        req = oauth.OAuthRequest.from_token_and_callback(
            token=self.req_token,
            http_url=self.auth_url,
            callback=callback_url,
            parameters={
                'domain': self.consumer.key,
                'location': location,
                'granularity': granularity,
            }
        )
        return req.to_url()

    def process_authorized(self, params):
        try:
            self.verifier = params['oauth_verifier'][0]

        except KeyError, e:
            resp = params['latitudeAuthResponse'][0]
            raise Exception('Authorisation failed: %s' % repr(resp))


if __name__ == '__main__':

    config = ConfigParser.ConfigParser()
    config.read((
        'latitude.conf',
        sys.path[0] + '/latitude.conf',
    ))

    consumer = oauth.OAuthConsumer(
        # Conceptually, this should include the extra Google stuff, but
        # I don't think it should be one-to-one with the client anyway.
        config.get('oauth', 'key'),
        config.get('oauth', 'secret'),
    )
    OAUTH = LatitudeOAuthClient(consumer)

    CALLBACK_BASE = config.get('callback', 'base_url')
    SERVER = config.get('callback', 'server')
    PORT = config.getint('callback', 'port')

    httpd = BaseHTTPServer.HTTPServer((SERVER, PORT), OAuthCallbackHandler)
    httpd.serve_forever()


