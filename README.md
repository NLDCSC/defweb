[![Upload Python Package](https://github.com/NLDCSC/defweb/actions/workflows/package_to_pypi.yaml/badge.svg)](https://github.com/NLDCSC/defweb/actions/workflows/package_to_pypi.yaml)

#### DEFWEB

Defweb is an enhancement of the standard http.server of python3.
Defweb supports https and file uploads and can function as a SOCKS 4, 5 or HTTP proxy. 

##### Installing

Installing the package via pypi:

```
pip install defweb
```
##### Options

```bash
usage: python3 -m defweb.main [-h] [-b BIND] [-p PORT] [-v] [--log-level LOG_LEVEL] [-d DIR] [-i SERVER NAME] [--key KEY] [--cert CERT] [-r] [-s] [--proxy] [--proxy_socks_only] [--proxy_http_only]
                              [--rotate_user_agents] [--ip-limit CIDR] [-u USER:PASSWORD]

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
  --key KEY             key file to use for webserver
  --cert CERT           certificate file to use for webserver
  -r, --recreate_cert   re-create the ssl certificate
  -s, --secure          use https instead of http

Proxy options:
  --proxy               start proxy for SOCKS4, SOCKS5 & HTTP(S)
  --proxy_socks_only    start proxy only for SOCKS4, SOCKS5
  --proxy_http_only     start proxy only for HTTP(S)
  --rotate_user_agents  generate random user agent for each HTTP request (only HTTP supported)
  --ip-limit CIDR       limit proxy to only accept connections coming from this CIDR range
  -u USER:PASSWORD      user credentials to use when authenticating to the proxy server
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
