import collections
import errno
import logging
import select
import socket
import ssl
from socket import error as SocketError
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

__version__ = "0.1.0"


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class ReverseProxyTCPHandler(StreamRequestHandler):

    server_ip = None
    server_port = None

    proxied_ip = None
    proxied_port = None
    proxied_tls = None

    middlewares = None
    middleware_loaded = None

    def __init__(self, request, client_address, server):

        self.logger = logging.getLogger(__name__)

        super().__init__(request, client_address, server)

        self.server_ip = ReverseProxyTCPHandler.server_ip
        self.server_port = ReverseProxyTCPHandler.server_port

        self.proxied_ip = ReverseProxyTCPHandler.proxied_ip
        self.proxied_port = ReverseProxyTCPHandler.proxied_port
        self.proxied_tls = ReverseProxyTCPHandler.proxied_tls

        self.client_ip = None
        self.client_port = None

        self.remote = None

        self.middlewares = ReverseProxyTCPHandler.middlewares
        self.middleware_loaded = ReverseProxyTCPHandler.middleware_loaded

    @staticmethod
    def load_middlewares(needed_middleware):
        from defweb.middlewares.middleware_loader import MiddlewareLoader

        ml = MiddlewareLoader()

        configured_middlewares = collections.defaultdict(list)

        for m in ml.middleware_choises:
            if m in needed_middleware:
                configured_middlewares[ml.middleware_choises[m].__weight__].append(
                    ml.load_middleware(m)
                )

        od = collections.OrderedDict(sorted(configured_middlewares.items()))

        return od

    def handle(self):

        self.client_ip, self.client_port = self.client_address

        self.logger.info(
            f"Connection accepted from {self.client_ip}:{self.client_port}"
        )

        if self.proxied_ip is not None and self.proxied_port is not None:
            try:
                # setup connection to destination (service for which we are reverse proxying
                self.remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                if self.proxied_tls:
                    self.remote = ssl.wrap_socket(
                        self.remote, suppress_ragged_eofs=True
                    )

                self.remote.connect((self.proxied_ip, self.proxied_port))
                bind_address = self.remote.getsockname()
                self.logger.debug(f"bind_address: {bind_address}")

                if self.remote:
                    self.exchange_loop(self.connection, self.remote)

            except ConnectionError:
                self.logger.error(
                    f"Could not establish a connection to the proxied service at {self.proxied_ip}:{self.proxied_port} "
                    f"with TLS: {self.proxied_tls}"
                )
        else:
            self.logger.error(f"Missing ip address and port for the proxied service")

        self.server.close_request(self.request)

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            try:
                if client in r:
                    data = client.recv(4096)

                    if len(data) <= 0:
                        break
                    else:
                        remote.send(data)

                    self.logger.data(
                        f"{self.client_ip}:{self.client_port} "
                        f"=> {self.server_ip}:{self.server_port} "
                        f"=> {self.proxied_ip}:{self.proxied_port}"
                        f" | B:{len(data)}",
                        "REV_PROXY",
                        True,
                    )
                    if self.middleware_loaded is not None:
                        for weight, middleware_list in self.middleware_loaded.items():
                            for each_middleware in middleware_list:
                                each_middleware(data).execute()

            except ConnectionResetError:
                self.logger.error(
                    "Connection reset.... Might be expected behaviour..."
                )  # Handle connection resets.

            try:
                if remote in r:
                    data = remote.recv(4096)

                    if len(data) <= 0:
                        break
                    else:
                        client.send(data)

                    self.logger.data(
                        f"{self.client_ip}:{self.client_port} "
                        f"<= {self.server_ip}:{self.server_port} "
                        f"<= {self.proxied_ip}:{self.proxied_port}"
                        f" | B:{len(data)}",
                        "REV_PROXY",
                    )
                    if self.middleware_loaded is not None:
                        for weight, middleware_list in self.middleware_loaded.items():
                            for each_middleware in middleware_list:
                                each_middleware(data).execute()

            except SocketError as e:
                if e.errno != errno.ECONNRESET:
                    raise  # Not error we are looking for
                client.send(data)
                self.logger.error(
                    "Connection reset.... Might be expected behaviour..."
                )  # Handle connection resets.

        self.logger.info("Forwarding requests ended!")


class DefWebReverseProxy(object):

    server_version = "DefWebReverseProxy/" + __version__

    def __init__(
        self, socketaddress, proxied_ip, proxied_port, proxied_tls, middlewares
    ):

        if not isinstance(socketaddress, tuple):
            raise TypeError(
                f"Argument socket address should be a tuple, not a {type(socketaddress)}"
            )

        self.hostname = socketaddress[0]
        self.port = socketaddress[1]

        self.logger = logging.getLogger(__name__)

        self.rev_proxy_server = None

        self.ReverseProxyTCPHandler = ReverseProxyTCPHandler

        self.ReverseProxyTCPHandler.server_ip = self.hostname
        self.ReverseProxyTCPHandler.server_port = self.port

        self.ReverseProxyTCPHandler.proxied_ip = proxied_ip
        self.ReverseProxyTCPHandler.proxied_port = proxied_port
        self.ReverseProxyTCPHandler.proxied_tls = proxied_tls

        self.ReverseProxyTCPHandler.middlewares = middlewares
        self.ReverseProxyTCPHandler.middleware_loaded = self.ReverseProxyTCPHandler.load_middlewares(
            middlewares
        )

    def init_proxy(self):
        try:
            self.rev_proxy_server = ThreadingTCPServer(
                (self.hostname, int(self.port)), self.ReverseProxyTCPHandler
            )
            self.logger.info("Initializing...")
        except OSError as err:
            self.logger.error(f"{err}")

        return self.rev_proxy_server
