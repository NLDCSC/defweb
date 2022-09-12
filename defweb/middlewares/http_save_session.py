from defweb.objects.middlewarebase import DefWebMiddlewareBase


class HttpSaveSession(DefWebMiddlewareBase):

    __protocol__ = "http"
    __hook__ = ["before_remote_send", "before_client_send"]
    __weight__ = 100

    def initialize(self) -> bool:
        return True

    def execute(self) -> bool:
        import hashlib
        import os

        self.file_hash = hashlib.sha1(
            f"{self.client_ip, self.client_port}".encode("utf-8")
        ).hexdigest()[:12]

        if not os.path.exists(os.path.join("/tmp/defweb", self.client_ip)):
            os.mkdir(os.path.join("/tmp/defweb", self.client_ip))

        with open(
            os.path.join(
                "/tmp/defweb", self.client_ip, f"http_session_{self.file_hash}"
            ),
            "a+",
        ) as f:
            f.write(self.data.decode("utf-8"))

        return True
