import argparse
import os
import ssl
from http.server import HTTPServer
from subprocess import call, DEVNULL

from defweb.webserver import DefWebServer

__version__ = '0.1.3'


def main():
    code_root = os.path.dirname(os.path.realpath(__file__))

    proto = DefWebServer.protocols.HTTP

    parser = argparse.ArgumentParser()

    parser.add_argument('-b', dest='bind', help='ip to bind to; defaults to 127.0.0.1')
    parser.add_argument('-d', dest='directory', metavar='[ DIR ]', default=None,
                        help='path to use as document root')
    parser.add_argument('-i', dest='impersonate', metavar='[ SERVER NAME ]', default=None,
                        help='server name to send in headers')
    parser.add_argument('-p', dest='port', type=int, help='port to use; defaults to 8000')
    parser.add_argument('-r', '--recreate_cert', action='store_true', help='re-create the ssl certificate')
    parser.add_argument('-s', '--secure', action='store_true', help='use https instead of http')
    parser.add_argument('-v', '--version', action='store_true', help='show version and then exit')

    args = parser.parse_args()

    if args.version:
        print(__version__)
        exit(0)

    if args.port:
        if args.port <= 1024:
            if os.geteuid() != 0:
                print('Need to be root to bind to privileged port; increasing port number with 8000')
                port = args.port + 8000
            else:
                port = args.port
        else:
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
            WebHandler.directory = args.directory
        else:
            raise FileNotFoundError('Path: {} cannot be found!!!'.format(args.directory))

    if args.impersonate:
        WebHandler.server_version = args.impersonate

    try:
        httpd = HTTPServer((host, port), WebHandler)
    except OSError:
        print('\n[-] Error trying to bind to port {}, is there another service '
              'running on that port?\n'.format(args.port))
        return

    if args.secure:

        cert_path = os.path.join(code_root, 'server.pem')

        result = 0

        if not os.path.exists(cert_path) or args.recreate_cert:

            result = call(['/usr/bin/openssl', 'req', '-new', '-x509', '-keyout', cert_path,
                           '-out', cert_path, '-days', '365', '-nodes',
                           '-subj', '/C=NL/ST=DefWeb/L=DefWeb/O=DefWeb/OU=DefWeb/CN=DefWeb.nl', '-passout',
                           'pass:DefWeb'], shell=False, stdout=DEVNULL, stderr=DEVNULL, cwd=code_root)

        if result == 0:
            proto = DefWebServer.protocols.HTTPS
            httpd.socket = ssl.wrap_socket(httpd.socket, certfile=cert_path, server_side=True)
        else:
            print('[-] Cannot create certificate... skipping https...')

    try:
        print('[+] Running: {}'.format(WebHandler.server_version))
        print('[+] Starting webserver on: {}{}:{}'.format(proto, host, port))
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('[+] User cancelled execution, closing down server...', end=" ", flush=True)
        httpd.server_close()
        print('Server closed, exiting!')


if __name__ == '__main__':
    main()
