#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import BaseServer
import ssl
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from .icalcrypt import encrypt_ics, decrypt_ics

class RequestHandler(BaseHTTPRequestHandler):
    def _do_forward(self, method):
        auth = None
        passphrase = None
        if "Authorization" in self.headers:
            auth = self.headers["Authorization"] # extract auth string from client request # TODO: make optional / configurable
            del self.headers["Authorization"] # remove auth string client request # TODO: make optional / configurable
            passphrase = auth.encode('utf-8') # TODO: extract password?
        else:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="iCalendar Encrypting Proxy", charset="UTF-8"')
            self.end_headers()
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
                    data = encrypt_ics(data, passphrase)
                else:
                    print("Cannot encrypt without passphrase.")
        request = Request(url, headers=self.headers, data=data, method=method)
        try:
            with urlopen(request, context=ssl._create_unverified_context()) as upstream:
                self.send_response(upstream.code)
                for k,v in upstream.headers.items():
                    if (k == "Host"):
                        v = host # override response host information
                    self.send_header(k, v) # forward all headers
                self.end_headers()
                if ('Content-Length' in upstream.headers):
                    data = upstream.read()
                    if ('Content-Type' in upstream.headers and upstream.headers['Content-Type'] == 'text/calendar'):
                        print("This is a calendar download. Should decrypt.")
                        if (passphrase):
                            data = decrypt_ics(data, passphrase)
                        else:
                            print("Cannot decrypt without passphrase.")
                    self.wfile.write(data) # forward upstream data to client
        except HTTPError as err:
            self.send_response(err.code)
            for k,v in err.headers.items():
                if (k == "Host"):
                    v = host # override response host information
                self.send_header(k, v) # forward all headers
            self.end_headers()
            self.wfile.write(err.read())
        except URLError as err:
            #self.send_error(500, str(err.reason))
            self.send_response(500)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(str(err.reason).encode('utf-8'))
  
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
    httpd = HTTPServer(('0.0.0.0', 443), RequestHandler)
    httpd.socket = ssl.wrap_socket(
      httpd.socket, 
      certfile='/etc/ssl/certs/ssl-cert-snakeoil.pem', # TODO: make optional / configurable
      keyfile='/etc/ssl/private/ssl-cert-snakeoil.key', # TODO: make optional / configurable
      server_side=True
    )
    httpd.serve_forever()

if __name__ == "__main__":
    main()
