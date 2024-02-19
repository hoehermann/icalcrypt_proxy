#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import BaseServer
import ssl
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from .icalcrypt import encrypt_ics, decrypt_ics, DEFAULT_CRYPT_CATEGORY, DEFAULT_SENSITIVE_COMPNENTS
import argparse

class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server, args):
        self.args = args
        super().__init__(request, client_address, server)
    
    def _send_headers(self, headers, host = None):
        for k,v in headers.items():
            if (host and k == "Host"):
                v = host # override response host information
            self.send_header(k, v) # forward all other headers
        self.end_headers()
    
    def _do_forward(self, method):
        auth = None
        passphrase = self.args.passphrase
        if (passphrase is None):
            if "Authorization" in self.headers:
                auth = self.headers["Authorization"] # extract auth string from client request # TODO: make optional / configurable
                if (not self.args.forward_auth):
                    del self.headers["Authorization"] # remove auth string client request
                passphrase = auth.encode('utf-8') # TODO: extract password?
            else:
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="iCalendar Encrypting Proxy", charset="UTF-8"')
                self.end_headers()
                self.wfile.write('Username and password required.\n'.encode('utf-8'))
                return
        host = ""
        if "Host" in self.headers:
            host = self.headers["Host"] # extract host from client request
            del self.headers["Host"] # remove host from client request 
        # prepare request for forwarding to upstream
        url = self.path[1:] # strip slash from url
        data = None
        if ('Content-Length' in self.headers):
            length = int(self.headers['Content-Length'])
            del self.headers['Content-Length']
            data = self.rfile.read(length)
            if ('Content-Type' in self.headers and self.headers['Content-Type'] == 'text/calendar'):
                print("This is a calendar upload. Should encrypt.")
                if (passphrase):
                    data = encrypt_ics(data, passphrase, self.args.category, self.args.components)
                else:
                    print("Cannot encrypt without passphrase.")
        try:
            request = Request(url, headers=self.headers, data=data, method=method)
            with urlopen(request, context=ssl._create_unverified_context()) as upstream:
                # examine answer from upsteam then forward to client
                self.send_response(upstream.code)
                self._send_headers(upstream.headers, host)
                if ('Content-Length' in upstream.headers):
                    data = upstream.read()
                    if ('Content-Type' in upstream.headers and upstream.headers['Content-Type'] == 'text/calendar'):
                        print("This is a calendar download. Should decrypt.")
                        if (passphrase):
                            data = decrypt_ics(data, passphrase, self.args.category, self.args.components)
                        else:
                            print("Cannot decrypt without passphrase.")
                    self.wfile.write(data) # forward upstream data to client
        except HTTPError as err:
            self.send_response(err.code)
            self._send_headers(err.headers, host)
            self.wfile.write(err.read())
        except URLError as err:
            self.send_error(500, str(err.reason))
        except ValueError as err:
            self.send_error(500, str(err))
  
    def do_GET(self):
      self._do_forward("GET")

    def do_PUT(self):
      self._do_forward("PUT")
      
    def do_HEAD(self):
      self._do_forward("HEAD")

    def do_DELETE(self):
      self._do_forward("DELETE")
    
    def do_PROPFIND(self):
      self._do_forward("PROPFIND")

def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--host', default='0.0.0.0', type=str, help='Host or IP-Address to listen on (default: 0.0.0.0)')
    parser.add_argument('--port', default=443, type=int, help='Port to listen on (default: 443)')
    parser.add_argument('--certfile', default='/etc/ssl/certs/ssl-cert-snakeoil.pem', type=str, help='certfile (default: /etc/ssl/certs/ssl-cert-snakeoil.pem)')
    parser.add_argument('--keyfile', default='/etc/ssl/private/ssl-cert-snakeoil.key', type=str, help='keyfile (default: /etc/ssl/private/ssl-cert-snakeoil.key)')
    parser.add_argument('--forward-auth', action='store_true', help='Forward authentication to upstream server (default: no)')
    parser.add_argument('--passphrase', default=None, type=bool, help='Static global passphrse to use for encryption (default: None, uses credentials supplied by client)')
    parser.add_argument('--category', default=DEFAULT_CRYPT_CATEGORY, type=str, help='category whose presence will trigger encryption (default: %s)'%(DEFAULT_CRYPT_CATEGORY))
    parser.add_argument('--components', action='append', type=str, help='event component to encrypt (may be mentioned multiple times, default: %s)'%(','.join(DEFAULT_SENSITIVE_COMPNENTS)))
    
    args = parser.parse_args()
    if (not args.components):
        args.components = DEFAULT_SENSITIVE_COMPNENTS
    
    httpd = HTTPServer((args.host, args.port), lambda r, a, s: RequestHandler(r, a, s, args))
    httpd.socket = ssl.wrap_socket(
      httpd.socket, 
      certfile = args.certfile, 
      keyfile = args.keyfile, 
      server_side=True
    )
    httpd.serve_forever()

if __name__ == "__main__":
    main()
