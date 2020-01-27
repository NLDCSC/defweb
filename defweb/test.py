from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl

from defweb.webserver import DefWebServer

httpd = HTTPServer(('127.0.0.1', 8000), DefWebServer)
httpd.socket = ssl.wrap_socket(httpd.socket, certfile='./server.pem', server_side=True)
httpd.serve_forever()
