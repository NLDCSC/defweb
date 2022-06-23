import logging
from ipaddress import IPv4Network, IPv6Network
from socketserver import ThreadingMixIn, TCPServer
from typing import Union, Tuple

from defweb.handlers.proxy_tcp_handler import ProxyTCPHandler

__version__ = "0.1.0"


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class DefWebProxy(object):

    server_version = "DefWebProxy/" + __version__

    def __init__(
        self,
        socketaddress: Tuple[str, int],
        username: str = None,
        password: str = None,
        enforce_auth: bool = False,
        use_proxy_types: dict = None,
        rotate_user_agents: bool = False,
        ip_limit: Union[IPv4Network, IPv6Network] = None,
    ) -> None:

        if not isinstance(socketaddress, tuple):
            raise TypeError(
                f"Argument socket address should be a tuple, not a {type(socketaddress)}"
            )

        self.hostname = socketaddress[0]
        self.port = socketaddress[1]

        self.logger = logging.getLogger(__name__)

        self.proxy_server = None

        self.ProxyTCPHandler = ProxyTCPHandler

        self.ProxyTCPHandler.enfore_auth = enforce_auth
        self.ProxyTCPHandler.username = username
        self.ProxyTCPHandler.password = password

        self.ProxyTCPHandler.use_proxy_types = use_proxy_types
        self.ProxyTCPHandler.rotate_user_agents = rotate_user_agents
        if rotate_user_agents:
            self.ProxyTCPHandler.user_agents_list = self.ProxyTCPHandler.load_from_file(
                "user_agents.txt"
            )
        self.ProxyTCPHandler.ip_limit = ip_limit

        self.ProxyTCPHandler.server_ip = self.hostname
        self.ProxyTCPHandler.server_port = self.port

    def init_proxy(self) -> ThreadingTCPServer:
        try:
            self.proxy_server = ThreadingTCPServer(
                (self.hostname, int(self.port)), self.ProxyTCPHandler
            )
            self.logger.info("Initializing...")
        except OSError as err:
            self.logger.error(f"{err}")

        return self.proxy_server
