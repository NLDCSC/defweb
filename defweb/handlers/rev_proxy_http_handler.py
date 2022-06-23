import errno
import select
import ssl
from socket import error as SocketError

from defweb.handlers.rev_proxy_tcp_handler import ReverseProxyTCPHandler


class ReverseProxyHTTPHandler(ReverseProxyTCPHandler):
    protocol = "http"

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

        self.protocol = ReverseProxyHTTPHandler.protocol

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
                        if isinstance(client, ssl.SSLSocket):
                            # SSL Sockets cannot be recursively recv(), so drain the SSL socket's internal buffer.
                            data_left = client.pending()
                            while data_left:
                                data += client.recv(data_left)
                                data_left = client.pending()
                        if self.handle_middleware(
                            data=data,
                            hook="before_remote_send",
                            client_ip=self.client_ip,
                            client_port=self.client_port,
                        ):
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
                        if isinstance(remote, ssl.SSLSocket):
                            # SSL Sockets cannot be recursively recv(), so drain the SSL socket's internal buffer.
                            data_left = remote.pending()
                            while data_left:
                                data += remote.recv(data_left)
                                data_left = remote.pending()
                        if self.handle_middleware(
                            data=data,
                            hook="before_client_send",
                            client_ip=self.client_ip,
                            client_port=self.client_port,
                        ):
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
