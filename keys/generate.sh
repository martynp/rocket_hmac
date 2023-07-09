#!/bin/bash

openssl req -x509 \
            -sha256 -days 356 \
            -nodes \
            -newkey rsa:2048 \
            -subj "/CN=example.com/C=US/L=San Fransisco" \
            -keyout rootCA.key -out rootCA.crt 

openssl genrsa -out server.key 2048

cat > csr.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
#req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = California
L = San Fransisco
O = MyOrg
OU = MyOrg
CN = example.com

#[ req_ext ]
#subjectAltName = @alt_names

#[ alt_names ]
#DNS.1 = demo.mlopshub.com
#DNS.2 = www.demo.mlopshub.com
#IP.1 = 192.168.1.5
#IP.2 = 192.168.1.6

EOF

openssl req -new -key server.key -out server.csr -config csr.conf

cat > cert.conf <<EOF

authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
#subjectAltName = @alt_names

#[alt_names]
#DNS.1 = demo.mlopshub.com

EOF

openssl x509 -req \
    -in server.csr \
    -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out server.crt \
    -days 365 \
    -sha256 -extfile cert.conf


openssl genrsa -out server_2.key 2048
openssl req -new -key server_2.key -out server_2.csr -config csr.conf
openssl x509 -req \
    -in server_2.csr \
    -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out server_2.crt \
    -days 365 \
    -sha256 -extfile cert.conf

