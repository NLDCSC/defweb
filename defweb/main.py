import argparse
import os
import ssl
from http.server import HTTPServer
from subprocess import call, DEVNULL

from defweb.webserver import DefWebServer


def main():
    code_root = os.path.dirname(os.path.realpath(__file__))

    proto = 'http://'

    parser = argparse.ArgumentParser()

    parser.add_argument('-s', '--secure', action='store_true', help='use https instead of http')
    parser.add_argument('-p', '--port', action='store_true', help='port to use; defaults to 8000')
    parser.add_argument('-b', '--bind', action='store_true', help='ip to bind to; defaults to 127.0.0.1')
    parser.add_argument('-d', dest='directory', metavar='[ DIR ]', default=None,
                        help='path to use as document root')
    parser.add_argument('-i', dest='impersonate', metavar='[ SERVER NAME ]', default=None,
                        help='server name to send in headers')

    args = parser.parse_args()

    if args.port:
        port = args.port
    else:
        port = 8000

    if args.bind:
        host = args.bind
    else:
        host = '127.0.0.1'

    WebHandler = DefWebServer

    if args.directory:
        if os.path.exists(args.directory):
            # os.chdir(args.directory)
            WebHandler.directory = args.directory
        else:
            raise FileNotFoundError('Path: {} cannot be found!!!'.format(args.directory))

    if args.impersonate:
        WebHandler.server_version = args.impersonate

    httpd = HTTPServer((host, port), WebHandler)

    if args.secure:

        cert_path = os.path.join(code_root, 'server.pem')

        result = call(['/usr/bin/openssl', 'req', '-new', '-x509', '-keyout', cert_path,
                       '-out', cert_path, '-days', '365', '-nodes',
                       '-subj', '/C=NL/ST=DefWeb/L=DefWeb/O=DefWeb/OU=DefWeb/CN=DefWeb.nl', '-passout',
                       'pass:DefWeb'], shell=False, stdout=DEVNULL, stderr=DEVNULL, cwd=code_root)

        if result == 0:
            proto = 'https://'
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=cert_path, server_side=True)
        else:
            print('[-] Cannot create certificate... skipping https...')

    try:
        print('[+] Starting webserver on: {}{}:{}'.format(proto, host, port))
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('[+] User cancelled execution, closing down server...', end=" ", flush=True)
        httpd.server_close()
        print('Server closed, exiting!')
    except ssl.SSLError:
        pass


if __name__ == '__main__':
    main()
