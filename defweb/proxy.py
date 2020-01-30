import errno
import select
import socket
import struct
from socket import error as SocketError
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler

__version__ = '0.0.1'

SOCKS_VERSION_MAP = {4: 'SOCKSv4', 5: 'SOCKSv5', 67: 'HTTP'}
METHOD_MAP = {0: 'NO AUTH', 1: 'GSSAPI', 2: 'USERNAME & PASSWORD'}
COMMAND_MAP = {1: 'CONNECT', 2: 'BIND', 3: 'UDP ASSOCIATE'}
ERROR_MAP_5 = {0: 'succeeded', 1: 'general SOCKS server failure', 2: 'connection not allowed by ruleset',
               3: 'Network unreachable', 4: 'Host unreachable', 5: 'Connection refused', 6: 'TTL expired',
               7: 'Command not supported', 8: 'Address type not supported'}
ERROR_MAP_4 = {90: 'request granted', 91: 'request rejected or failed', 92: 'request rejected becasue SOCKS server '
                                                                            'cannot connect to identd on the client',
               93: 'request rejected because the client program and identdreport different user-ids'}

USERNAME = 'secret'
PASSWORD = 'secret'


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


class SocksTCPHandler(StreamRequestHandler):
    global USERNAME
    global PASSWORD

    SOCKS_VERSION = None

    username = USERNAME
    password = PASSWORD

    def __init__(self, request, client_address, server):

        super().__init__(request, client_address, server)

        self.socks_version = 4

    def handle(self):

        client_ip, client_port = self.client_address

        print('[+] Connection accepted from {}:{}'.format(client_ip, client_port))

        # Assemble header and parse version and nmethods
        header = self.connection.recv(2)

        # +----+----------+----------+
        # |VER | NMETHODS |  METHODS |
        # +----+----------+----------+
        # | 1  |      1   | 1 to 255 |
        # +----+----------+----------+
        if len(header) == struct.calcsize('BB'):
            version, nmethods = struct.unpack("!BB", header)
        else:
            self.server.close_request(self.request)
            return

        print('[+] Client requesting {} proxy'.format(SOCKS_VERSION_MAP[version]))

        # build check to differentiate between SOCKSv4, SOCKSv5 and HTTP
        self.socks_version = int(version)

        if self.socks_version == 4:

            cmd = nmethods

            port = struct.unpack("!H", self.connection.recv(2))[0]

            address = socket.inet_ntoa(self.connection.recv(4))

            # print('[D] version: {}; cmd: {}; port: {}; address: {}'.format(version, cmd, port, address))

            # server reply
            try:
                if cmd == 1:  # CONNECT
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((address, port))
                    bind_address = remote.getsockname()
                    # print('[D] bind_address: {}'.format(bind_address))
                elif cmd == 2:  # BIND
                    print("[-] Not supported command: {}".format(COMMAND_MAP[cmd]))
                    self.server.close_request(self.request)
                else:
                    print("[-] Unknown command received!!")
                    self.server.close_request(self.request)

                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
                port = bind_address[1]
                # print('[D] addr: {}; port: {}'.format(addr, port))
                reply = struct.pack("!BBHI", 0, 90, port, addr)

            except Exception as err:
                print('[-] Server reply produced an error: {}'.format(err))
                # return Connection refused error
                reply = self.generate_failed_reply_4(91)

            self.connection.sendall(reply)

            # Establish data exchange
            if reply[1] == 90 and cmd == 1:
                print('[+] Forwarding requests!')
                self.exchange_loop(self.connection, remote)

            self.server.close_request(self.request)

        elif self.socks_version == 5:

            # Get available methods
            methods = self.get_available_methods(nmethods)

            # incorporate GSSAPI as authentication method!!
            if 2 in methods.keys():
                chosen_method = 2
            else:
                chosen_method = 0

            print('[+] Client supports "{}" as method, accepting and sending servers choice'.format(
                METHOD_MAP[chosen_method]))

            # Send server choice as welcome message
            # +----+--------+
            # |VER | METHOD |
            # +----+--------+
            # | 1  |   1    |
            # +----+--------+
            self.connection.sendall(struct.pack("!BB", self.socks_version, chosen_method))

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

            pkt_len_packed = self.connection.recv(struct.calcsize('BBBB'))
            if len(pkt_len_packed) == struct.calcsize('BBBB'):
                version, cmd, _, atype = struct.unpack("!BBBB", pkt_len_packed)
            else:
                self.server.close_request(self.request)
                return

            # print('[D] version: {}; cmd: {}; atype: {}'.format(version, cmd, atype))

            if atype == 1:  # IPv4

                address = socket.inet_ntoa(self.connection.recv(4))
                # print('[D] address: {}'.format(address))

            elif atype == 3:  # domain

                domain_length = self.connection.recv(1)[0]

                address = self.connection.recv(domain_length).decode("utf-8")

                # print('[D] address: {}; domain_length: {}'.format(address, domain_length))

            elif atype == 4:  # IPv6

                print("[-] Not supported atype: {}".format('IPv6'))
                reply = self.generate_failed_reply_5(int(atype), 5)
                self.connection.sendall(reply)
                return
                # self.server.close_request(self.request)

            port = struct.unpack('!H', self.rfile.read(2))[0]

            # print('[D] address: {}'.format(port))

            # server reply
            try:
                if cmd == 1:  # CONNECT
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((address, port))
                    bind_address = remote.getsockname()
                    # print('[D] bind_address: {}'.format(bind_address))
                elif cmd == 2:  # BIND
                    print("[-] Not supported command: {}".format(COMMAND_MAP[cmd]))
                    self.server.close_request(self.request)
                elif cmd == 3:  # UDP ASSOCIATE
                    print("[-] Not supported command: {}".format(COMMAND_MAP[cmd]))
                    self.server.close_request(self.request)
                else:
                    print("[-] Unknown command received!!")
                    self.server.close_request(self.request)

                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
                port = bind_address[1]
                # print('[D] addr: {}; port: {}'.format(addr, port))
                # +----+-----+-------+------+----------+----------+
                # |VER | CMD | RSV   | ATYP | BND.ADDR | BND.PORT |
                # +----+-----+-------+------+----------+----------+
                # | 1  | 1   | X'00' | 1    | Variable |    2     |
                # +----+-----+-------+------+----------+----------+
                reply = struct.pack("!BBBBIH", self.socks_version, 0, 0, atype, addr, port)

            except Exception as err:
                print('[-] Server reply produced an error: {}'.format(err))
                # return Connection refused error
                reply = self.generate_failed_reply_5(int(atype), 5)
            try:
                self.connection.sendall(reply)
            except ConnectionResetError:
                return

            # Establish data exchange
            if reply[1] == 0 and cmd == 1:
                print('[+] Forwarding requests!')
                self.exchange_loop(self.connection, remote)

            self.server.close_request(self.request)

        elif self.socks_version == 67:

            print('[!] Not implemented!!')

            self.server.close_request(self.request)

    def exchange_loop(self, client, remote):
        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            try:
                if client in r:
                    data = client.recv(4096)
                    # print('[<=] Received client data bytes: {}'.format(len(data)))
                    if remote.send(data) <= 0:
                        break
            except ConnectionResetError:
                print('[!] Connection reset.... Might be expected behaviour...')  # Handle connection resets.

            try:
                if remote in r:
                    data = remote.recv(4096)
                    # print('[=>] Send remote data bytes: {}'.format(len(data)))
                    if client.send(data) <= 0:
                        break
            except SocketError as e:
                if e.errno != errno.ECONNRESET:
                    raise  # Not error we are looking for
                client.send(data)
                print('[!] Connection reset.... Might be expected behaviour...')  # Handle connection resets.

        print('[+] Forwarding requests ended!')

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
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            print('[+] Authentication succeeded!!')
            response = struct.pack("!BB", version, 0x00)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        print('[+] Authentication failed, wrong username and password!!')
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    @staticmethod
    def generate_failed_reply_4(error_number):
        return struct.pack("!BBHI", 0, error_number, 0, 0)

    def generate_failed_reply_5(self, address_type, error_number):
        return struct.pack("!BBBBIH", int(self.socks_version), int(error_number), 0, int(address_type), 0, 0)


class DefWebProxy(object):

    server_version = 'DefWebProxy/' + __version__

    def __init__(self, socketaddress):

        if not isinstance(socketaddress, tuple):
            raise TypeError('Argument socketaddress should be a tuple, not a {}'.format(type(socketaddress)))

        self.hostname = socketaddress[0]
        self.port = socketaddress[1]

        self.proxy_server = None

    def init_proxy(self):
        try:
            self.proxy_server = ThreadingTCPServer((self.hostname, int(self.port)), SocksTCPHandler)
            print('[+] Initializing...')
        except OSError as err:
            print("[!] " + str(err))

        return self.proxy_server
