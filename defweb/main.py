import argparse
import ipaddress
import logging
import os
import ssl
import sys
from http.server import HTTPServer
from logging.config import dictConfig

from defweb.common.constants import CERT_PATH, KEY_PATH, SIGNED_CERT_PATH
from defweb.common.mapping_handlers import handler_mapping
from defweb.common.pki import DefWebPKI
from defweb.proxy import DefWebProxy
from defweb.reverse_proxy import DefWebReverseProxy
from defweb.utils.logger_class import HelperLogger
from defweb.version import get_version_from_file
from defweb.webserver import DefWebServer

__version__ = get_version_from_file()


def main():

    proto = DefWebServer.protocols.HTTP

    parser = argparse.ArgumentParser(prog="defweb")

    # General options
    gen_grp = parser.add_argument_group("General options")
    gen_grp.add_argument("-b", dest="bind", help="ip to bind to; defaults to 127.0.0.1")
    gen_grp.add_argument(
        "-p", dest="port", type=int, help="port to use; defaults to 8000"
    )
    gen_grp.add_argument(
        "-v", "--version", action="store_true", help="show version and then exit"
    )
    gen_grp.add_argument(
        "--log-level",
        default="INFO",
        help="DEBUG, INFO (default), WARNING, ERROR, CRITICAL",
    )

    # Webserver options
    web_grp = parser.add_argument_group("Webserver options")
    web_grp.add_argument(
        "-d",
        dest="directory",
        metavar="DIR",
        default=None,
        help="path to use as document root",
    )
    web_grp.add_argument(
        "-i",
        dest="impersonate",
        metavar="SERVER NAME",
        default=None,
        help="server name to send in headers",
    )
    web_grp.add_argument(
        "-s",
        "--secure",
        action="store_true",
        help="use https instead of http, if --key and --cert are omitted certificates will be auto generated",
    )
    web_grp.add_argument(
        "-r",
        "--recreate_cert",
        action="store_true",
        help="re-create the generated ssl certificate",
    )
    web_grp.add_argument(
        "--sign",
        action="store_true",
        help="when using auto generated certs (-s without --key or --cert), should they be signed or not",
    )
    web_grp.add_argument(
        "--key", dest="key", metavar="KEY", help="key file to use for webserver"
    )
    web_grp.add_argument(
        "--cert",
        dest="cert",
        metavar="CERT",
        help="certificate file to use for webserver",
    )

    # Proxy options
    proxy_grp = parser.add_argument_group("Proxy options")

    proxy_grp.add_argument(
        "--proxy", action="store_true", help="start proxy for SOCKS4, SOCKS5 & HTTP(S)"
    )
    proxy_grp.add_argument(
        "--proxy_socks_only",
        action="store_true",
        help="start proxy only for SOCKS4, SOCKS5",
    )
    proxy_grp.add_argument(
        "--proxy_http_only", action="store_true", help="start proxy only for HTTP(S)"
    )
    proxy_grp.add_argument(
        "--rotate_user_agents",
        action="store_true",
        help="generate random user agent for each HTTP request (only HTTP supported)",
    )
    proxy_grp.add_argument(
        "--ip-limit",
        dest="ip_limit",
        metavar="CIDR",
        default=None,
        help="limit proxy to only accept connections coming from this CIDR range",
    )
    proxy_grp.add_argument(
        "-u",
        dest="credentials",
        metavar="USER:PASSWORD",
        help="user credentials to use when authenticating to the proxy server",
    )

    # Reverse Proxy options
    rev_proxy_grp = parser.add_argument_group("Reverse Proxy options")
    rev_proxy_grp.add_argument(
        "--rev_proxy", action="store_true", help="start reverse TCP proxy"
    )
    rev_proxy_grp.add_argument(
        "--rev_proxy_tls",
        action="store_true",
        help="add TLS support to the reverse TCP proxy",
    )
    rev_proxy_grp.add_argument(
        "-ca",
        action="store_true",
        help="whether to setup own CA and sign the certificates used by the --rev_proxy_tls option",
    )
    rev_proxy_grp.add_argument(
        "-pi",
        dest="proxied_ip",
        metavar="PROXIED_IP",
        default=None,
        help="provide the ip of the service we are proxying for",
    )
    rev_proxy_grp.add_argument(
        "-pp",
        dest="proxied_port",
        type=int,
        metavar="PROXIED_PORT",
        default=None,
        help="provide the port of the service we are proxying for",
    )
    rev_proxy_grp.add_argument(
        "-ptls",
        action="store_true",
        help="whether the service we are proxying for uses TLS",
    )
    rev_proxy_grp.add_argument(
        "-m",
        dest="middlewares",
        metavar="MIDDLEWARES",
        default=None,
        help="comma seperated middlewares to use",
    )
    rev_proxy_grp.add_argument(
        "--protocol",
        metavar="PROXIED_PROTOCOL",
        default=None,
        help="provide the protocol of the service we are proxying for",
    )

    args = parser.parse_args()

    logDict = {
        "version": 1,
        "formatters": {"simpleFormatter": {"format": "%(asctime)s %(message)s"}},
        "handlers": {
            "consoleHandler": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "simpleFormatter",
            }
        },
        "root": {
            "level": getattr(logging, args.log_level),
            "handlers": ["consoleHandler"],
        },
    }

    dictConfig(logDict)

    logging.setLoggerClass(HelperLogger)

    logger = logging.getLogger(__name__)

    if args.version:
        print(__version__)
        exit(0)

    if not os.path.exists("/tmp/defweb"):
        os.mkdir("/tmp/defweb")

    logger.info(f"Defweb version: {__version__}")

    if args.port:
        if args.port <= 1024:
            if os.geteuid() != 0:
                logger.info(
                    "Need to be root to bind to privileged port; increasing port number with 8000"
                )
                port = args.port + 8000
            else:
                port = args.port
        else:
            port = args.port
    else:
        if os.geteuid() == 0 and args.secure:
            port = 443
        else:
            port = 8000

    if args.bind:
        host = args.bind
    else:
        host = "127.0.0.1"

    if not any(
        [args.proxy, args.proxy_socks_only, args.proxy_http_only, args.rev_proxy]
    ):
        # setup webserver
        WebHandler = DefWebServer

        if args.directory:
            if os.path.exists(args.directory):
                os.chdir(args.directory)
                WebHandler.root_dir = os.getcwd()
            else:
                raise FileNotFoundError(f"Path: {args.directory} cannot be found!!!")
        else:
            WebHandler.root_dir = os.getcwd()

        if args.impersonate:
            WebHandler.server_version = args.impersonate

        try:
            httpd = HTTPServer((host, port), WebHandler)
        except OSError:
            logger.error(
                f"\nError trying to bind to port {port}, is there another service "
                "running on that port?\n",
                exc_info=True,
            )
            return

        if args.secure:

            use_cert_path = CERT_PATH
            use_key_path = KEY_PATH

            if args.cert:
                if os.path.exists(args.cert):
                    use_cert_path = args.cert
                else:
                    raise FileNotFoundError("Certificate file not found!")

            if args.key:
                if os.path.exists(args.key):
                    use_key_path = args.key
                else:
                    raise FileNotFoundError("Key file not found!")

            result = False

            if not args.cert:
                if not os.path.exists(use_cert_path) or args.recreate_cert:
                    dwp = DefWebPKI()
                    result = dwp.create_https_certs()
                else:
                    result = True

                if args.sign:
                    dwp = DefWebPKI()
                    ca = dwp.create_ca_certs()
                    ca_sign = dwp.sign_https_certs()

                    result = all([ca, ca_sign])

                    if result:
                        use_cert_path = SIGNED_CERT_PATH

            if result:
                proto = DefWebServer.protocols.HTTPS
                httpd.socket = ssl.wrap_socket(
                    httpd.socket,
                    keyfile=use_key_path,
                    certfile=use_cert_path,
                    server_side=True,
                    ssl_version=ssl.PROTOCOL_TLSv1_2,
                )
            else:
                logger.error(f"Certificate creation produced an error: {result}")
                logger.error("Cannot create certificate... skipping https...")

        try:
            logger.info(f"Running DefWebServer: {WebHandler.server_version}")
            logger.info(f"Starting webserver on: {proto}{host}:{port}")
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("User cancelled execution, closing down server...")
            httpd.server_close()
            logger.info("Server closed, exiting!")
            sys.exit(0)
    else:
        if args.rev_proxy:

            logger.info(
                f"Running DefWebReverseProxy: {DefWebReverseProxy.server_version}"
            )

            handler = "default"

            if args.protocol:
                handler = args.protocol.lower()

            rev_proxy_server = DefWebReverseProxy(
                socketaddress=(host, port),
                proxied_ip=args.proxied_ip,
                proxied_port=args.proxied_port,
                proxied_tls=args.ptls,
                middlewares=args.middlewares.lower().split(","),
                request_handler_class=handler_mapping[handler],
            ).init_proxy()

            if args.rev_proxy_tls:
                use_cert_path = CERT_PATH
                use_key_path = KEY_PATH

                result = False

                if not os.path.exists(use_cert_path):
                    dwp = DefWebPKI()
                    result = dwp.create_https_certs()
                else:
                    result = True

                if args.ca:
                    dwp = DefWebPKI()
                    ca = dwp.create_ca_certs()
                    ca_sign = dwp.sign_https_certs()

                    result = all([ca, ca_sign])

                    if result:
                        use_cert_path = SIGNED_CERT_PATH

                if result and rev_proxy_server is not None:
                    rev_proxy_server.socket = ssl.wrap_socket(
                        rev_proxy_server.socket,
                        keyfile=use_key_path,
                        certfile=use_cert_path,
                        server_side=True,
                        ssl_version=ssl.PROTOCOL_TLSv1_2,
                    )
                else:
                    logger.error(f"Certificate creation produced an error: {result}")
                    logger.error("Cannot create certificate... skipping TLS...")

            if rev_proxy_server is not None:
                try:
                    ip, host = rev_proxy_server.server_address
                    logger.info(f"Starting DefWebReverseProxy on {ip}:{host}")
                    rev_proxy_server.serve_forever()
                # handle CTRL+C
                except KeyboardInterrupt:
                    logger.info("Exiting...")
                except Exception as err:
                    logger.error("Exception occurred", exc_info=True)
                finally:
                    rev_proxy_server.shutdown()
                    rev_proxy_server.server_close()
                    sys.exit(0)

        else:
            # setup proxy
            if args.ip_limit:
                try:
                    set_ip_limit = ipaddress.ip_network(args.ip_limit)
                except ValueError:
                    logger.error(
                        "The provided value for --ip-limit does not appear to be a valid IPv4 or IPv6 CIDR notation"
                    )
                    sys.exit(1)
            else:
                set_ip_limit = None

            use_proxies = {
                "http": any([args.proxy, args.proxy_http_only]),
                "socks": any([args.proxy, args.proxy_socks_only]),
            }

            logger.info(
                f"Running DefWebProxy: {DefWebProxy.server_version}; using proxies: {use_proxies}"
            )

            if args.credentials:
                username, password = args.credentials.split(":")
                proxy_server = DefWebProxy(
                    socketaddress=(host, port),
                    username=username,
                    password=password,
                    enforce_auth=True,
                    use_proxy_types=use_proxies,
                    rotate_user_agents=args.rotate_user_agents,
                    ip_limit=set_ip_limit,
                ).init_proxy()
            else:
                proxy_server = DefWebProxy(
                    socketaddress=(host, port),
                    use_proxy_types=use_proxies,
                    rotate_user_agents=args.rotate_user_agents,
                    ip_limit=set_ip_limit,
                ).init_proxy()

            if proxy_server is not None:
                try:
                    ip, host = proxy_server.server_address
                    logger.info(f"Starting DefWebProxy on {ip}:{host}")
                    proxy_server.serve_forever()
                # handle CTRL+C
                except KeyboardInterrupt:
                    logger.info("Exiting...")
                except Exception as err:
                    logger.error("Exception occurred", exc_info=True)
                finally:
                    proxy_server.shutdown()
                    proxy_server.server_close()
                    sys.exit(0)


if __name__ == "__main__":
    main()


# TODO setup hook to execute code to cleanup old files from tmp/defweb
