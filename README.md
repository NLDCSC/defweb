#### DEFWEB

Defweb is an enhancement of the standard http.server of python3.
Defweb supports https en file uploads.

##### Installing

Installing the package via pypi:

```
pip install defweb
```
##### Options

```bash
usage: __main__.py [-h] [-s] [-r] [-p PORT] [-b BIND] [-d [DIR]]
                   [-i [SERVER NAME]]

optional arguments:
  -h, --help           show this help message and exit
  -s, --secure         use https instead of http
  -r, --recreate_cert  re-create the ssl certificate
  -p PORT              port to use; defaults to 8000
  -b BIND              ip to bind to; defaults to 127.0.0.1
  -d [ DIR ]           path to use as document root
  -i [ SERVER NAME ]   server name to send in headers
```
##### Usage

```bash
python3 -m defweb
```

##### Upload

Defweb facilitates uploading files to the document root via the PUT command.

Example for \'curl\' and wget (the -k switch (curl) and  
--no-check-certificate (wget) is needed because Defweb uses self signed
certificates).

```bash
curl -X PUT --upload-file file.txt https://localhost:8000 -k
wget -O- --method=PUT --body-file=file.txt https://localhost:8000/somefile.txt --no-check-certificate 
```
