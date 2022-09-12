import errno
import ipaddress
import logging
import os
import random
import re
import select
import socket
import struct
from socket import error as SocketError
from socketserver import StreamRequestHandler
from typing import Tuple, List

SOCKS_VERSION_MAP = {4: "SOCKSv4", 5: "SOCKSv5", 67: "HTTPS", 71: "HTTP"}

METHOD_MAP = {
    0: "NO AUTH",
    1: "GSSAPI",
    2: "USERNAME & PASSWORD",
    255: "NO ACCEPTABLE METHODS",
}

COMMAND_MAP = {1: "CONNECT", 2: "BIND", 3: "UDP ASSOCIATE"}

ERROR_MAP_5 = {
    0: "succeeded",
    1: "general SOCKS server failure",
    2: "connection not allowed by ruleset",
    3: "Network unreachable",
    4: "Host unreachable",
    5: "Connection refused",
    6: "TTL expired",
    7: "Command not supported",
    8: "Address type not supported",
}

ERROR_MAP_4 = {
    90: "request granted",
    91: "request rejected or failed",
    92: "request rejected because SOCKS server cannot connect to identd on the client",
    93: "request rejected because the client program and identd report different user-ids",
}


class ProxyTCPHandler(StreamRequestHandler):

    enfore_auth = False

    username = None
    password = None
    server_ip = None
    server_port = None

    dst_address = None
    dst_port = None
    dst_domain = None

    use_proxy_types = None
    rotate_user_agents = None
    user_agents_list = None
    ip_limit = None

    def __init__(self, request, client_address, server):

        self.logger = logging.getLogger(__name__)

        super().__init__(request, client_address, server)

        # Defaults to SOCKS4 proxy
        self.socks_version = 4

        self.enfore_auth = ProxyTCPHandler.enfore_auth
        self.username = ProxyTCPHandler.username
        self.password = ProxyTCPHandler.password

        self.server_ip = ProxyTCPHandler.server_ip
        self.server_port = ProxyTCPHandler.server_port

        self.dst_address = ProxyTCPHandler.dst_address
        self.dst_port = ProxyTCPHandler.dst_port
        self.dst_domain = ProxyTCPHandler.dst_domain

        self.use_proxy_types = ProxyTCPHandler.use_proxy_types
        self.rotate_user_agents = ProxyTCPHandler.rotate_user_agents
        self.user_agents_list = ProxyTCPHandler.user_agents_list
        self.ip_limit = ProxyTCPHandler.ip_limit

        self.client_ip = None
        self.client_port = None

    def handle(self) -> None:

        self.client_ip, self.client_port = self.client_address

        if self.ip_limit is not None:
            if ipaddress.ip_address(self.client_ip) not in self.ip_limit:
                self.server.close_request(self.request)
                self.logger.warning(
                    f"Denied connection from {self.client_ip}; reason IP not in ip_limit variable"
                )
                return
            else:
                self.logger.info(
                    f"Client ip {self.client_ip} is within the configured ip limit range ({self.ip_limit})"
                )

        self.logger.info(
            f"Connection accepted from {self.client_ip}:{self.client_port}"
        )

        # Assemble header and parse version and nmethods
        header = self.connection.recv(2)

        # +----+----------+----------+
        # |VER | NMETHODS |  METHODS |
        # +----+----------+----------+
        # | 1  |    1     | 1 to 255 |
        # +----+----------+----------+
        if len(header) == struct.calcsize("BB"):
            version, nmethods = struct.unpack("!BB", header)
        else:
            self.server.close_request(self.request)
            return

        self.logger.info(f"Client requesting {SOCKS_VERSION_MAP[version]} proxy")

        # build check to differentiate between SOCKSv4, SOCKSv5 and HTTP
        self.socks_version = int(version)

        if self.socks_version == 4:

            if self.use_proxy_types["socks"]:

                # +----+-----+---------+----------+----------+
                # |VER | CMD | DSTPORT |   DSTIP  |    ID    |
                # +----+-----+---------+----------+----------+
                # | 1  | 1   |    2    |    4     | variable |
                # +----+-----+---------+----------+----------+

                cmd = nmethods

                self.dst_port = struct.unpack("!H", self.connection.recv(2))[0]

                self.dst_address = socket.inet_ntoa(self.connection.recv(4))

                self.logger.debug(
                    f"version: {version}; cmd: {cmd}; dst_port: {self.dst_port}; address: {self.dst_address}"
                )

                # server reply
                try:
                    if cmd == 1:  # CONNECT
                        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        remote.connect((self.dst_address, self.dst_port))
                        bind_address = remote.getsockname()
                        self.logger.debug(f"Bind_address: {bind_address}")
                    elif cmd == 2:  # BIND
                        self.logger.error(f"Not supported command: {COMMAND_MAP[cmd]}")
                        self.server.close_request(self.request)
                        return
                    else:
                        self.logger.error("Unknown command received!!")
                        self.server.close_request(self.request)
                        return

                    bind_addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[
                        0
                    ]
                    bind_port = bind_address[1]
                    self.logger.debug(f"Bind_addr: {bind_addr}; bind_port: {bind_port}")
                    # +----+-----+---------+----------+
                    # |VN  | REP | DSTPORT |   DSTIP  |
                    # +----+-----+---------+----------+
                    # | 1  | 1   |    2    |    4     |
                    # +----+-----+---------+----------+
                    reply = struct.pack("!BBHI", 0, 90, bind_port, bind_addr)

                except Exception as err:
                    self.logger.error(f"Server reply produced an error: {err}")
                    # return Connection refused error
                    reply = self.generate_failed_reply_4(91)

                self.connection.sendall(reply)

                # Establish data exchange
                if reply[1] == 90 and cmd == 1:
                    self.logger.info("Forwarding requests!")
                    self.exchange_loop(self.connection, remote)
            else:
                self.logger.warning(
                    f"Request received for disabled proxy service -> {SOCKS_VERSION_MAP[self.socks_version]}"
                )

            self.server.close_request(self.request)

        elif self.socks_version == 5:

            if self.use_proxy_types["socks"]:
                # Get available methods
                methods = self.get_available_methods(nmethods)

                # TODO incorporate GSSAPI as authentication method!!
                if self.enfore_auth:
                    if 2 not in methods.keys():
                        # cannot validate creds closing connection
                        self.logger.error(
                            f"Client not supporting {METHOD_MAP[2]} authentication, server is configured to "
                            "force authentication. Closing connection"
                        )
                        self.connection.sendall(
                            struct.pack("!BB", self.socks_version, 255)
                        )
                        self.server.close_request(self.request)
                        return
                    else:
                        chosen_method = 2
                else:
                    if 2 in methods.keys():
                        # don't force authentication so set to 'NO AUTH'
                        chosen_method = 0
                    elif 0 in methods.keys():
                        chosen_method = 0
                    else:
                        chosen_method = 255

                self.logger.info(
                    f'Client supports "{METHOD_MAP[chosen_method]}" as method, '
                    f"accepting and sending servers choice"
                )

                # Send server choice as welcome message
                # +----+--------+
                # |VER | METHOD |
                # +----+--------+
                # | 1  |   1    |
                # +----+--------+
                # The values currently defined for METHOD are:
                #
                #           o  X'00' NO AUTHENTICATION REQUIRED
                #           o  X'01' GSSAPI
                #           o  X'02' USERNAME/PASSWORD
                #           o  X'03' to X'7F' IANA ASSIGNED
                #           o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
                #           o  X'FF' NO ACCEPTABLE METHODS

                self.connection.sendall(
                    struct.pack("!BB", self.socks_version, chosen_method)
                )

                if chosen_method == 2:
                    # verify the credentials...
                    if not self.verify_credentials():
                        return

                # parse version, cmd, rsv(=/x00), adress_type from reply
                # +----+-----+-------+------+----------+----------+
                # |VER | CMD | RSV   | ATYP | DST.ADDR | DST.PORT |
                # +----+-----+-------+------+----------+----------+
                # | 1  | 1   | X'00' | 1    | Variable |    2     |
                # +----+-----+-------+------+----------+----------+
                # Where:
                #
                #           o  VER    protocol version: X'05'
                #           o  CMD
                #              o  CONNECT X'01'
                #              o  BIND X'02'
                #              o  UDP ASSOCIATE X'03'
                #           o  RSV    RESERVED
                #           o  ATYP   address type of following address
                #              o  IP V4 address: X'01'
                #              o  DOMAINNAME: X'03'
                #              o  IP V6 address: X'04'
                #           o  DST.ADDR       desired destination address
                #           o  DST.PORT desired destination port in network octet order

                pkt_len_packed = self.connection.recv(struct.calcsize("BBBB"))
                if len(pkt_len_packed) == struct.calcsize("BBBB"):
                    version, cmd, _, atype = struct.unpack("!BBBB", pkt_len_packed)
                else:
                    self.server.close_request(self.request)
                    return

                self.logger.debug(f"version: {version}; cmd: {cmd}; atype: {atype}")

                if atype == 1:  # IPv4

                    self.dst_address = socket.inet_ntoa(self.connection.recv(4))
                    self.logger.debug(f"dst_address: {self.dst_address}")

                elif atype == 3:  # domain

                    domain_length = self.connection.recv(1)[0]

                    self.dst_domain = self.connection.recv(domain_length).decode(
                        "utf-8"
                    )

                    self.dst_address = socket.gethostbyname(self.dst_domain)

                    # set atype to 1 as the proxy-server will perform DNS resolution and the reply to the client always
                    # has an ip address
                    atype = 1

                    self.logger.debug(
                        f"domain: {self.dst_domain}; domain_length: {domain_length}; address: {self.dst_address}"
                    )

                else:  # atype == 4:  # IPv6
                    # Depends on host support
                    self.dst_address = socket.inet_ntop(
                        socket.AF_INET6, self.connection.recv(16)
                    )
                    self.logger.debug(f"dst_address: {self.dst_address}")

                self.dst_port = struct.unpack("!H", self.rfile.read(2))[0]

                self.logger.debug(f"dst_port: {self.dst_port}")

                # server reply
                try:
                    if cmd == 1:  # CONNECT
                        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        remote.connect((self.dst_address, self.dst_port))
                        bind_address = remote.getsockname()
                        self.logger.debug(f"bind_address: {bind_address}")
                    elif cmd == 2:  # BIND
                        self.logger.error(f"Not supported command: {COMMAND_MAP[cmd]}")
                        self.server.close_request(self.request)
                        return
                    elif cmd == 3:  # UDP ASSOCIATE
                        self.logger.error(f"Not supported command: {COMMAND_MAP[cmd]}")
                        self.server.close_request(self.request)
                        return
                    else:
                        self.logger.error("Unknown command received!!")
                        self.server.close_request(self.request)
                        return

                    bind_addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[
                        0
                    ]
                    bind_port = bind_address[1]
                    self.logger.debug(f"bind_addr: {bind_addr}; bind_port: {bind_port}")

                    # +----+-----+-------+------+----------+----------+
                    # |VER | REP | RSV   | ATYP | BND.ADDR | BND.PORT |
                    # +----+-----+-------+------+----------+----------+
                    # | 1  |  1  | X'00' |  1   | Variable |    2     |
                    # +----+-----+-------+------+----------+----------+
                    # Where:
                    #
                    #           o  VER    protocol version: X'05'
                    #           o  REP    Reply field:
                    #              o  X'00' succeeded
                    #              o  X'01' general SOCKS server failure
                    #              o  X'02' connection not allowed by ruleset
                    #              o  X'03' Network unreachable
                    #              o  X'04' Host unreachable
                    #              o  X'05' Connection refused
                    #              o  X'06' TTL expired
                    #              o  X'07' Command not supported
                    #              o  X'08' Address type not supported
                    #              o  X'09' to X'FF' unassigned
                    #           o  RSV    RESERVED
                    #           o  ATYP   address type of following address
                    #              o  IP V4 address: X'01'
                    #              o  DOMAINNAME: X'03'
                    #              o  IP V6 address: X'04'
                    #           o  BND.ADDR       server bound address
                    #           o  BND.PORT       server bound port in network octet order
                    #
                    #    Fields marked RESERVED (RSV) must be set to X'00'.

                    reply = struct.pack(
                        "!BBBBIH", self.socks_version, 0, 0, atype, bind_addr, bind_port
                    )

                except Exception as err:
                    self.logger.error(f"Server reply produced an error: {err}")
                    # return Connection refused error
                    reply = self.generate_failed_reply_5(int(atype), 5)
                try:
                    self.connection.sendall(reply)
                except ConnectionResetError:
                    return

                # Establish data exchange
                if reply[1] == 0 and cmd == 1:
                    self.logger.info("Forwarding requests!")
                    self.exchange_loop(self.connection, remote)

            else:
                self.logger.warning(
                    f"Request received for disabled proxy service -> {SOCKS_VERSION_MAP[self.socks_version]}"
                )

            self.server.close_request(self.request)

        elif self.socks_version == 67 or self.socks_version == 71:

            if self.use_proxy_types["http"]:

                connection_bytes = header + self.connection.recv(4096)

                connection_string = connection_bytes.decode("utf-8")

                self.logger.debug(f"Connection string received: {connection_string}")

                self.dst_domain, self.dst_port = self.parse_connection_string(
                    connection_string
                )

                if self.rotate_user_agents:
                    connection_bytes = self.rotate_user_agent(
                        connection_bytes=connection_bytes
                    )

                try:
                    # resolve ip address
                    self.dst_address = socket.gethostbyname(self.dst_domain)

                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((self.dst_address, self.dst_port))

                except Exception as err:
                    self.logger.error(f"Error connecting to remote HTTP host: {err}")

                # if HTTPS proxy is requested; notify the client that the tunnel is established...
                if self.socks_version == 67:
                    self.connection.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    self.exchange_loop(self.connection, remote)

                # if HTTP proxy is requested, forward the request in a separate loop...
                if self.socks_version == 71:
                    self.http_exchange_loop(self.connection, remote, connection_bytes)

            else:
                self.logger.warning(
                    f"Request received for disabled proxy service -> {SOCKS_VERSION_MAP[self.socks_version]}"
                )

            self.server.close_request(self.request)

    @staticmethod
    def load_from_file(filename: str) -> List[str]:

        with open(
            os.path.join(os.path.dirname(__file__), "sources/", filename), "r"
        ) as f:
            data = f.read()

        data = data.split("\n")

        return data[:-1]

    def generate_user_agent(self) -> str:

        user_agent = random.choice(self.user_agents_list)

        return user_agent

    def rotate_user_agent(self, connection_bytes: bytes) -> bytes:

        connection_string = connection_bytes.decode("utf-8")

        altered_connection_string = re.sub(
            "(?<=\nUser-Agent: ).+", self.generate_user_agent(), connection_string
        )

        return altered_connection_string.encode("utf-8")

    def parse_connection_string(self, data: str) -> Tuple[str, int]:
        try:
            first_line = data.split("\r\n")[0]

            url = first_line.split(" ")[1]

            http_pos = url.find("://")  # Finding the position of ://
            if http_pos == -1:
                temp = url
            else:
                temp = url[(http_pos + 3) :]

            port_pos = temp.find(":")

            webserver_pos = temp.find("/")
            if webserver_pos == -1:
                webserver_pos = len(temp)

            if port_pos == -1 or webserver_pos < port_pos:
                port = 80
                webserver = temp[:webserver_pos]
            else:
                port = int((temp[(port_pos + 1) :])[: webserver_pos - port_pos - 1])
                webserver = temp[:port_pos]

            return webserver, port
        except Exception as err:
            self.logger.error(f"Error parsing connection_string, error --> {err}")

    def http_exchange_loop(
        self, client: socket.socket, remote: socket.socket, connection_bytes: bytes
    ) -> None:

        try:
            remote.send(connection_bytes)

            while True:

                # wait until client or remote is available for read
                r, w, e = select.select([client, remote], [], [])

                try:
                    if remote in r:
                        data = remote.recv(4096)
                        if client.send(data) <= 0:
                            break
                        self.logger.data(
                            f"{self.client_ip}:{self.client_port} "
                            f"<= {self.server_ip}:{self.server_port} "
                            f"<= {self.dst_domain if self.dst_domain is not None else self.dst_address}"
                            f"({self.dst_address if self.dst_domain is not None else '*'}):{self.dst_port}"
                            f" | B:{len(data)}",
                            SOCKS_VERSION_MAP[self.socks_version],
                        )
                except SocketError as e:
                    if e.errno != errno.ECONNRESET:
                        raise  # Not error we are looking for
                    client.send(data)
                    self.logger.error(
                        "Connection reset.... Might be expected behaviour..."
                    )  # Handle connection resets.
                except Exception as err:
                    self.logger.error(
                        f"Unhandled error during http data exchange, error --> {err}"
                    )

        except Exception as err:
            self.logger.error(
                f"Error during the transmission of the connection_bytes, error --> {err}"
            )

        self.logger.info("Forwarding requests ended!")

    def exchange_loop(self, client: socket.socket, remote: socket.socket) -> None:

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            try:
                if client in r:
                    data = client.recv(4096)
                    if remote.send(data) <= 0:
                        break
                    if self.socks_version == 4:
                        data = data[1:]
                    self.logger.data(
                        f"{self.client_ip}:{self.client_port} "
                        f"=> {self.server_ip}:{self.server_port} "
                        f"=> {self.dst_domain if self.dst_domain is not None else self.dst_address}"
                        f"({self.dst_address if self.dst_domain is not None else '*'}):{self.dst_port}"
                        f" | B:{len(data)}",
                        SOCKS_VERSION_MAP[self.socks_version],
                        True,
                    )
            except ConnectionResetError:
                self.logger.error(
                    "Connection reset.... Might be expected behaviour..."
                )  # Handle connection resets.

            try:
                if remote in r:
                    data = remote.recv(4096)
                    if client.send(data) <= 0:
                        break
                    self.logger.data(
                        f"{self.client_ip}:{self.client_port} "
                        f"<= {self.server_ip}:{self.server_port} "
                        f"<= {self.dst_domain if self.dst_domain is not None else self.dst_address}"
                        f"({self.dst_address if self.dst_domain is not None else '*'}):{self.dst_port}"
                        f" | B:{len(data)}",
                        SOCKS_VERSION_MAP[self.socks_version],
                    )
            except SocketError as e:
                if e.errno != errno.ECONNRESET:
                    raise  # Not error we are looking for
                client.send(data)
                self.logger.error(
                    "Connection reset.... Might be expected behaviour..."
                )  # Handle connection resets.

        self.logger.info("Forwarding requests ended!")

    def get_available_methods(self, n: int) -> dict:
        methods = {}
        for _ in range(n):
            type = struct.unpack("!B", self.connection.recv(1))
            try:
                methods[type[0]] = METHOD_MAP[type[0]]
            except KeyError:
                methods[type] = "UNSUPPORTED"
        return methods

    def verify_credentials(self) -> bool:
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode("utf-8")

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode("utf-8")

        if username == self.username and password == self.password:
            # success, status = 0
            self.logger.debug("Authentication succeeded!!")
            response = struct.pack("!BB", version, 0x00)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        self.logger.error("Authentication failed, wrong username and password!!")
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    @staticmethod
    def generate_failed_reply_4(error_number: int) -> struct.pack:
        return struct.pack("!BBHI", 0, error_number, 0, 0)

    def generate_failed_reply_5(
        self, address_type: str, error_number: str
    ) -> struct.pack:
        return struct.pack(
            "!BBBBIH",
            int(self.socks_version),
            int(error_number),
            0,
            int(address_type),
            0,
            0,
        )
