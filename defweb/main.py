import argparse
import os
import ssl
from http.server import HTTPServer
from subprocess import call, DEVNULL

from defweb.webserver import DefWebServer


def main():
    code_root = os.path.dirname(os.path.realpath(__file__))

    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--secure', action='store_true', help='use https instead of http')
    parser.add_argument('-p', '--port', action='store_true', help='port to use; defaults to 8000')
    parser.add_argument('-b', '--bind', action='store_true', help='ip to bind to; defaults to 127.0.0.1')

    args = parser.parse_args()

    if args.port:
        port = args.port
    else:
        port = 8000

    if args.bind:
        host = args.bind
    else:
        host = '127.0.0.1'

    httpd = HTTPServer((host, port), DefWebServer)

    if args.secure:

        cert_path = os.path.join(code_root, 'server.pem')

        result = call(['/usr/bin/openssl', 'req', '-new', '-x509', '-keyout', cert_path,
                       '-out', cert_path, '-days', '365', '-nodes',
                       '-subj', '/C=NL/ST=DefWeb/L=DefWeb/O=DefWeb/OU=DefWeb/CN=DefWeb.nl', '-passout',
                       'pass:DefWeb'], shell=False, stdout=DEVNULL, stderr=DEVNULL, cwd=code_root)

        if result == 0:
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=cert_path, server_side=True)
        else:
            print('Cannot create certificate... skipping https...')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('User cancelled execution, closing down server!')
        httpd.server_close()
        print('Server closed, quitting!')


if __name__ == '__main__':
    main()
