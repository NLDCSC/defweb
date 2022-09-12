from defweb.objects.middlewarebase import DefWebMiddlewareBase


class HttpLogRequests(DefWebMiddlewareBase):

    __protocol__ = "http"
    __hook__ = "before_remote_send"
    __weight__ = 100

    def initialize(self) -> bool:
        return True

    def execute(self) -> bool:
        import os
        import hashlib
        from datetime import datetime

        self.file_hash = hashlib.sha1(
            f"{self.client_ip, self.client_port}".encode("utf-8")
        ).hexdigest()[:12]

        if not os.path.exists(os.path.join("/tmp/defweb", "http_log_requests")):
            os.mkdir(os.path.join("/tmp/defweb", "http_log_requests"))

        data_list = self.parse_connection_string()

        with open(
            os.path.join("/tmp/defweb", "http_log_requests", f"request_logger.txt"),
            "a+",
        ) as f:
            f.write(
                f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} request={data_list[0]}\t"
                f"user_agent={data_list[1]}\textra={data_list[2:]}\t"
                f"\tsession_file=/tmp/defweb/{self.client_ip}/http_session_{self.file_hash}\n"
            )

        return True

    def parse_connection_string(self):

        list_con = self.data.decode("utf-8").split("\r\n")

        list_con = [
            x
            for x in list_con
            if x != "" and not x.startswith("Host") and not x.startswith("Accept")
        ]

        return list_con
