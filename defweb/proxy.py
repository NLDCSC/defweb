import errno
import logging
import select
import socket
import struct
from socket import error as SocketError
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

__version__ = "0.0.5"

SOCKS_VERSION_MAP = {4: "SOCKSv4", 5: "SOCKSv5", 67: "HTTP"}
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


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksTCPHandler(StreamRequestHandler):

    enfore_auth = False

    username = None
    password = None

    def __init__(self, request, client_address, server):

        self.logger = logging.getLogger(__name__)

        super().__init__(request, client_address, server)

        self.socks_version = 4

        self.enfore_auth = SocksTCPHandler.enfore_auth
        self.username = SocksTCPHandler.username
        self.password = SocksTCPHandler.password

    def handle(self):

        client_ip, client_port = self.client_address

        self.logger.info(f"[+] Connection accepted from {client_ip}:{client_port}")

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

        self.logger.info(f"[+] Client requesting {SOCKS_VERSION_MAP[version]} proxy")

        # build check to differentiate between SOCKSv4, SOCKSv5 and HTTP
        self.socks_version = int(version)

        if self.socks_version == 4:

            # +----+-----+---------+----------+----------+
            # |VER | CMD | DSTPORT |   DSTIP  |    ID    |
            # +----+-----+---------+----------+----------+
            # | 1  | 1   |    2    |    4     | variable |
            # +----+-----+---------+----------+----------+

            cmd = nmethods

            port = struct.unpack("!H", self.connection.recv(2))[0]

            address = socket.inet_ntoa(self.connection.recv(4))

            self.logger.debug(f"[D] version: {version}; cmd: {cmd}; port: {port}; address: {address}")

            # server reply
            try:
                if cmd == 1:  # CONNECT
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((address, port))
                    bind_address = remote.getsockname()
                    self.logger.debug(f"[D] bind_address: {bind_address}")
                elif cmd == 2:  # BIND
                    self.logger.error(f"[-] Not supported command: {COMMAND_MAP[cmd]}")
                    self.server.close_request(self.request)
                    return
                else:
                    self.logger.error("[-] Unknown command received!!")
                    self.server.close_request(self.request)
                    return

                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
                port = bind_address[1]
                self.logger.debug(f"[D] addr: {addr}; port: {port}")
                # +----+-----+---------+----------+
                # |VN  | REP | DSTPORT |   DSTIP  |
                # +----+-----+---------+----------+
                # | 1  | 1   |    2    |    4     |
                # +----+-----+---------+----------+
                reply = struct.pack("!BBHI", 0, 90, port, addr)

            except Exception as err:
                self.logger.error(f"[-] Server reply produced an error: {err}")
                # return Connection refused error
                reply = self.generate_failed_reply_4(91)

            self.connection.sendall(reply)

            # Establish data exchange
            if reply[1] == 90 and cmd == 1:
                self.logger.info("[+] Forwarding requests!")
                self.exchange_loop(self.connection, remote)

            self.server.close_request(self.request)

        elif self.socks_version == 5:

            # Get available methods
            methods = self.get_available_methods(nmethods)

            # TODO incorporate GSSAPI as authentication method!!
            if self.enfore_auth:
                if 2 not in methods.keys():
                    # cannot validate creds closing connection
                    self.logger.error(
                        f"[-] Client not supporting {METHOD_MAP[2]} authentication, server is configured to "
                        "force authentication. Closing connection"
                    )
                    self.connection.sendall(struct.pack("!BB", self.socks_version, 255))
                    self.server.close_request(self.request)
                    return
                else:
                    chosen_method = 2
            else:
                if 2 in methods.keys():
                    chosen_method = 2
                elif 0 in methods.keys():
                    chosen_method = 0
                else:
                    chosen_method = 255

            self.logger.info(f'[+] Client supports "{METHOD_MAP[chosen_method]}" as method, '
                             f'accepting and sending servers choice')

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

            self.logger.debug(f"[D] version: {version}; cmd: {cmd}; atype: {atype}")

            if atype == 1:  # IPv4

                address = socket.inet_ntoa(self.connection.recv(4))
                self.logger.debug(f"[D] address: {address}")

            elif atype == 3:  # domain

                domain_length = self.connection.recv(1)[0]

                domain = self.connection.recv(domain_length).decode("utf-8")

                address = socket.gethostbyname(domain)

                # set atype to 1 as the proxy-server will perform DNS resolution and the reply to the client always
                # has an ip address
                atype = 1

                self.logger.debug(f"[D] domain: {domain}; domain_length: {domain_length}; address: {address}")

            else:  # atype == 4:  # IPv6
                # Depends on host support
                address = socket.inet_ntop(socket.AF_INET6, self.connection.recv(16))

            port = struct.unpack("!H", self.rfile.read(2))[0]

            self.logger.debug(f"[D] port: {port}")

            # server reply
            try:
                if cmd == 1:  # CONNECT
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((address, port))
                    bind_address = remote.getsockname()
                    self.logger.debug(f"[D] bind_address: {bind_address}")
                elif cmd == 2:  # BIND
                    self.logger.error(f"[-] Not supported command: {COMMAND_MAP[cmd]}")
                    self.server.close_request(self.request)
                    return
                elif cmd == 3:  # UDP ASSOCIATE
                    self.logger.error(f"[-] Not supported command: {COMMAND_MAP[cmd]}")
                    self.server.close_request(self.request)
                    return
                else:
                    self.logger.error("[-] Unknown command received!!")
                    self.server.close_request(self.request)
                    return

                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
                port = bind_address[1]
                self.logger.debug(f"[D] addr: {addr}; port: {port}")
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
                    "!BBBBIH", self.socks_version, 0, 0, atype, addr, port
                )

            except Exception as err:
                self.logger.error(f"[-] Server reply produced an error: {err}")
                # return Connection refused error
                reply = self.generate_failed_reply_5(int(atype), 5)
            try:
                self.connection.sendall(reply)
            except ConnectionResetError:
                return

            # Establish data exchange
            if reply[1] == 0 and cmd == 1:
                self.logger.info("[+] Forwarding requests!")
                self.exchange_loop(self.connection, remote)

            self.server.close_request(self.request)

        elif self.socks_version == 67:
            # TODO setup HTTP proxy

            self.logger.error("[!] Not implemented!!")

            self.server.close_request(self.request)

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            try:
                if client in r:
                    data = client.recv(4096)
                    self.logger.debug(f"[<=] Received client data bytes: {len(data)}")
                    if remote.send(data) <= 0:
                        break
            except ConnectionResetError:
                self.logger.error(
                    "[!] Connection reset.... Might be expected behaviour..."
                )  # Handle connection resets.

            try:
                if remote in r:
                    data = remote.recv(4096)
                    self.logger.debug(f"[=>] Send remote data bytes: {len(data)}")
                    if client.send(data) <= 0:
                        break
            except SocketError as e:
                if e.errno != errno.ECONNRESET:
                    raise  # Not error we are looking for
                client.send(data)
                self.logger.error(
                    "[!] Connection reset.... Might be expected behaviour..."
                )  # Handle connection resets.

        self.logger.info("[+] Forwarding requests ended!")

    def get_available_methods(self, n):
        methods = {}
        for _ in range(n):
            type = struct.unpack("!B", self.connection.recv(1))
            try:
                methods[type[0]] = METHOD_MAP[type[0]]
            except KeyError:
                methods[type] = "UNSUPPORTED"
        return methods

    def verify_credentials(self):
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode("utf-8")

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode("utf-8")

        if username == self.username and password == self.password:
            # success, status = 0
            self.logger.debug("[D] Authentication succeeded!!")
            response = struct.pack("!BB", version, 0x00)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        self.logger.error("[!] Authentication failed, wrong username and password!!")
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    @staticmethod
    def generate_failed_reply_4(error_number):
        return struct.pack("!BBHI", 0, error_number, 0, 0)

    def generate_failed_reply_5(self, address_type, error_number):
        return struct.pack(
            "!BBBBIH",
            int(self.socks_version),
            int(error_number),
            0,
            int(address_type),
            0,
            0,
        )


class DefWebProxy(object):

    server_version = "DefWebProxy/" + __version__

    def __init__(self, socketaddress, username=None, password=None, enforce_auth=False):

        if not isinstance(socketaddress, tuple):
            raise TypeError(f"Argument socketaddress should be a tuple, not a {type(socketaddress)}")

        self.hostname = socketaddress[0]
        self.port = socketaddress[1]

        self.logger = logging.getLogger(__name__)

        self.proxy_server = None

        self.SocksTCPHandler = SocksTCPHandler

        self.SocksTCPHandler.enfore_auth = enforce_auth
        self.SocksTCPHandler.username = username
        self.SocksTCPHandler.password = password

    def init_proxy(self):
        try:
            self.proxy_server = ThreadingTCPServer(
                (self.hostname, int(self.port)), self.SocksTCPHandler
            )
            self.logger.info("[+] Initializing...")
        except OSError as err:
            self.logger.error(f"[!] {err}")

        return self.proxy_server
