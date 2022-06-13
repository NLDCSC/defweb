[![Upload Python Package](https://github.com/NLDCSC/defweb/actions/workflows/package_to_pypi.yaml/badge.svg)](https://github.com/NLDCSC/defweb/actions/workflows/package_to_pypi.yaml)

#### DEFWEB

Defweb is an enhancement of the standard http.server of python3.
Defweb supports https and file uploads and can function as a SOCKS 4, 5 or HTTP proxy. 
Defweb can act as an TCP reverse proxy and can perform TLS MITM / TLS Interception.

##### Installing

Installing the package via pypi:

```
pip install defweb
```
##### Options

```bash
usage: defweb [-h] [-b BIND] [-p PORT] [-v] [--log-level LOG_LEVEL] [-d DIR] [-i SERVER NAME] [-s] [-r] [--sign] [--key KEY] [--cert CERT] [--proxy] [--proxy_socks_only] [--proxy_http_only]
              [--rotate_user_agents] [--ip-limit CIDR] [-u USER:PASSWORD] [--rev_proxy] [--rev_proxy_tls] [-ca] [-pi PROXIED_IP] [-pp PROXIED_PORT] [-ptls] [-m MIDDLEWARES]

optional arguments:
  -h, --help            show this help message and exit

General options:
  -b BIND               ip to bind to; defaults to 127.0.0.1
  -p PORT               port to use; defaults to 8000
  -v, --version         show version and then exit
  --log-level LOG_LEVEL
                        DEBUG, INFO (default), WARNING, ERROR, CRITICAL

Webserver options:
  -d DIR                path to use as document root
  -i SERVER NAME        server name to send in headers
  -s, --secure          use https instead of http, if --key and --cert are omitted certificates will be auto generated
  -r, --recreate_cert   re-create the generated ssl certificate
  --sign                when using auto generated certs (-s without --key or --cert), should they be signed or not
  --key KEY             key file to use for webserver
  --cert CERT           certificate file to use for webserver

Proxy options:
  --proxy               start proxy for SOCKS4, SOCKS5 & HTTP(S)
  --proxy_socks_only    start proxy only for SOCKS4, SOCKS5
  --proxy_http_only     start proxy only for HTTP(S)
  --rotate_user_agents  generate random user agent for each HTTP request (only HTTP supported)
  --ip-limit CIDR       limit proxy to only accept connections coming from this CIDR range
  -u USER:PASSWORD      user credentials to use when authenticating to the proxy server

Reverse Proxy options:
  --rev_proxy           start reverse TCP proxy
  --rev_proxy_tls       add TLS support to the reverse TCP proxy
  -ca                   whether to setup own CA and sign the certificates used by the --rev_proxy_tls option
  -pi PROXIED_IP        provide the ip of the service we are proxying for
  -pp PROXIED_PORT      provide the port of the service we are proxying for
  -ptls                 whether the service we are proxying for uses TLS
  -m MIDDLEWARES        comma seperated middlewares to use
```

##### Usage

```bash
python3 -m defweb.main
```

##### Upload

Defweb facilitates uploading files to the document root via the PUT command.

Example for \'curl\' and wget (the -k switch (curl) and  
--no-check-certificate (wget) is needed because Defweb uses self signed
certificates by default).

```bash
curl -X PUT --upload-file file.txt https://localhost:8000 -k
wget -O- --method=PUT --body-file=file.txt https://localhost:8000/somefile.txt --no-check-certificate 
```
