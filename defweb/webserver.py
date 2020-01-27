from http.server import SimpleHTTPRequestHandler


class DefWebServer(SimpleHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

