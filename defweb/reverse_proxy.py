import logging
from socketserver import ThreadingMixIn, TCPServer

__version__ = "0.1.0"


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class DefWebReverseProxy(object):

    server_version = "DefWebReverseProxy/" + __version__

    def __init__(
        self,
        socketaddress,
        proxied_ip,
        proxied_port,
        proxied_tls,
        middlewares,
        request_handler_class,
    ):

        if not isinstance(socketaddress, tuple):
            raise TypeError(
                f"Argument socket address should be a tuple, not a {type(socketaddress)}"
            )

        self.hostname = socketaddress[0]
        self.port = socketaddress[1]

        self.logger = logging.getLogger(__name__)

        self.rev_proxy_server = None

        self.request_handler_class = request_handler_class

        self.request_handler_class.server_ip = self.hostname
        self.request_handler_class.server_port = self.port

        self.request_handler_class.proxied_ip = proxied_ip
        self.request_handler_class.proxied_port = proxied_port
        self.request_handler_class.proxied_tls = proxied_tls

        self.request_handler_class.middlewares = middlewares
        self.request_handler_class.middleware_loaded = self.request_handler_class.load_middlewares(
            middlewares
        )

    def init_proxy(self):
        try:
            self.logger.info(f"Configured middlewares: {self.request_handler_class.middlewares}")
            self.logger.info(f"Using {self.request_handler_class} as request handler")
            self.rev_proxy_server = ThreadingTCPServer(
                (self.hostname, int(self.port)), self.request_handler_class
            )
            self.logger.info("Initializing...")
        except OSError as err:
            self.logger.error(f"{err}")

        return self.rev_proxy_server
