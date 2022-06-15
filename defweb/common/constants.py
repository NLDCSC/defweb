import os

env = os.environ

CERT_ROOT = os.path.join(env["HOME"], ".defweb")

CERT_PATH = os.path.join(CERT_ROOT, "server.pem")
KEY_PATH = os.path.join(CERT_ROOT, "server_key.pem")
CSR_PATH = os.path.join(CERT_ROOT, "server_csr.pem")
SIGNED_CERT_PATH = os.path.join(CERT_ROOT, "server_signed.pem")

CA_CERT_PATH = os.path.join(CERT_ROOT, "ca.pem")
CA_KEY_PATH = os.path.join(CERT_ROOT, "ca_key.pem")
CA_SIGNING_KEY_PATH = os.path.join(CERT_ROOT, "ca-signing_key.pem")

DEFAULT_CONFIG = b"""[ req ]
default_bits        = 2048
distinguished_name	= req_distinguished_name
attributes		    = req_attributes
string_mask         = utf8only

[ req_distinguished_name ]
countryName			    = Country Name (2 letter code)
countryName_min			= 2
countryName_max			= 2
stateOrProvinceName		= State or Province Name (full name)
localityName			= Locality Name (eg, city)
organizationName		= Organization Name (eg, company)
organizationalUnitName	= Organizational Unit Name (eg, section)
commonName			    = Common Name (eg, fully qualified host name)
commonName_max			= 64
emailAddress			= Email Address
emailAddress_max		= 64

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min	= 4
challengePassword_max	= 20"""
