A2MX
====

Generate keypair with OpenSSL
-----------------------------
openssl ecparam -out key.pem -name secp521r1 -genkey -noout

openssl req -new -key key.pem -x509 -nodes -days 365 -out cert.pem
