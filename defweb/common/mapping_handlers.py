from defweb.handlers.rev_proxy_http_handler import ReverseProxyHTTPHandler
from defweb.handlers.rev_proxy_tcp_handler import ReverseProxyTCPHandler

handler_mapping = {"default": ReverseProxyTCPHandler, "http": ReverseProxyHTTPHandler}
