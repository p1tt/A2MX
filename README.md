A2MX
====

Generate keypair with OpenSSL
-----------------------------
    openssl ecparam -out key.pem -name secp521r1 -genkey -noout
    openssl req -new -key key.pem -x509 -nodes -days 365 -out cert.pem
    openssl pkcs8 -topk8 -inform PEM -in key.pem -nocrypt -out pkcs8.der -outform DER

Dependencies
------------
bson python module from pymongo (tested with version 2.6). https://pypi.python.org/pypi/pymongo/

forked pyelliptic from https://github.com/p1tt/pyelliptic.git
