import collections
import errno
import logging
import select
import socket
import ssl
from socket import error as SocketError
from socketserver import StreamRequestHandler

from defweb.errors.middleware_errors import MiddlewareInitError


class ReverseProxyTCPHandler(StreamRequestHandler):

    server_ip = None
    server_port = None

    proxied_ip = None
    proxied_port = None
    proxied_tls = None

    middlewares = None
    middleware_loaded = None

    protocol = "general"

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

        self.protocol = ReverseProxyTCPHandler.protocol

    @staticmethod
    def default_to_regular(d):
        if isinstance(d, collections.defaultdict):
            d = {k: ReverseProxyTCPHandler.default_to_regular(v) for k, v in d.items()}
        return d

    @staticmethod
    def load_middlewares(needed_middleware):
        from defweb.middlewares.middleware_loader import MiddlewareLoader

        ml = MiddlewareLoader()

        configured_middlewares = collections.defaultdict(
            lambda: collections.defaultdict(lambda: collections.defaultdict(list))
        )

        for m in ml.middleware_choises:
            if m in needed_middleware:
                if isinstance(ml.middleware_choises[m].__hook__, list):
                    for h in ml.middleware_choises[m].__hook__:
                        configured_middlewares[ml.middleware_choises[m].__protocol__][
                            h
                        ][ml.middleware_choises[m].__weight__].append(
                            ml.load_middleware(m)
                        )
                elif isinstance(ml.middleware_choises[m].__hook__, str):
                    configured_middlewares[ml.middleware_choises[m].__protocol__][
                        ml.middleware_choises[m].__hook__
                    ][ml.middleware_choises[m].__weight__].append(ml.load_middleware(m))

        ret_dict = collections.defaultdict(
            lambda: collections.defaultdict(lambda: collections.OrderedDict(list))
        )

        for protocol, hooks in configured_middlewares.items():
            for hook, weights in hooks.items():
                ret_dict[protocol][hook] = collections.OrderedDict(
                    sorted(weights.items())
                )

        return ReverseProxyTCPHandler.default_to_regular(ret_dict)

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
                        self.remote,
                        suppress_ragged_eofs=True,
                        ssl_version=ssl.PROTOCOL_TLSv1_2,
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
            except ssl.SSLError:
                self.logger.error(
                    f"Could not establish TLS connection to proxied service at {self.proxied_ip}:{self.proxied_port}, "
                    f"is the service accepting TLS connections?"
                )

        else:
            self.logger.error(f"Missing ip address and port for the proxied service")

        self.server.close_request(self.request)

    def handle_middleware(self, data, hook, **kwargs):

        if self.middleware_loaded is not None:
            # first execute protocol specific then execute general middlewares
            for proto in [self.protocol, "general"]:
                try:
                    for weight, middleware_list in self.middleware_loaded[proto][
                        hook
                    ].items():
                        for each_middleware in middleware_list:
                            try:
                                active_middleware = each_middleware(data, **kwargs)
                                if not active_middleware.execute():
                                    self.logger.warning(
                                        f"{active_middleware.__class__.__name__} drops data..."
                                    )
                                    return False
                            except MiddlewareInitError as err:
                                self.logger.error(f"{err}")
                                pass
                except KeyError:
                    # no middleware loaded for this hook, just continue
                    continue
        return True

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            try:
                if client in r:
                    kill_communication = False
                    data = client.recv(4096)

                    if len(data) <= 0:
                        break
                    else:
                        if self.handle_middleware(data=data, hook="before_remote_send"):
                            if isinstance(client, ssl.SSLSocket):
                                # SSL Sockets cannot be recursively recv(), so drain the SSL socket's internal buffer.
                                data_left = client.pending()
                                while data_left:
                                    data += client.recv(data_left)
                                    data_left = client.pending()
                            remote.send(data)
                        else:
                            kill_communication = True

                    self.logger.data(
                        f"{self.client_ip}:{self.client_port} "
                        f"=> {self.server_ip}:{self.server_port} "
                        f"=> {self.proxied_ip}:{self.proxied_port}"
                        f" | B:{len(data)}",
                        "REV_PROXY",
                        True,
                    )
                    self.handle_middleware(data=data, hook="printers")

                    if kill_communication:
                        break

            except ConnectionResetError:
                self.logger.error(
                    "Connection reset.... Might be expected behaviour..."
                )  # Handle connection resets.

            try:
                if remote in r:
                    kill_communication = False
                    data = remote.recv(4096)

                    if len(data) <= 0:
                        break
                    else:
                        if self.handle_middleware(data=data, hook="before_client_send"):
                            if isinstance(remote, ssl.SSLSocket):
                                # SSL Sockets cannot be recursively recv(), so drain the SSL socket's internal buffer.
                                data_left = remote.pending()
                                while data_left:
                                    data += remote.recv(data_left)
                                    data_left = remote.pending()
                            client.send(data)
                        else:
                            kill_communication = True

                    self.logger.data(
                        f"{self.client_ip}:{self.client_port} "
                        f"<= {self.server_ip}:{self.server_port} "
                        f"<= {self.proxied_ip}:{self.proxied_port}"
                        f" | B:{len(data)}",
                        "REV_PROXY",
                    )
                    self.handle_middleware(data=data, hook="printers")

                    if kill_communication:
                        break

            except SocketError as e:
                if e.errno != errno.ECONNRESET:
                    raise  # Not error we are looking for
                self.logger.error(
                    "Connection reset.... Might be expected behaviour..."
                )  # Handle connection resets.

        self.logger.info("Forwarding requests ended!")
