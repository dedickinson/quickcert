#!/bin/bash -e

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

CLIENT_NAME=$1

if [ "$CLIENT_NAME" = "" ]
  then echo "Please provide a client name"
  exit
fi

echo Create the client key
cd /root/ca

openssl genrsa \
    -out /root/ca/intermediate/private/$CLIENT_NAME.key.pem 4096

chmod 400 /root/ca/intermediate/private/$CLIENT_NAME.key.pem

echo Create the signing request
#   Organizational Unit Name []:Kraken Certificate Authority
#   Common Name []: client@kraken.local
openssl req -config /root/intermediate-openssl.cnf \
    -key /root/ca/intermediate/private/$CLIENT_NAME.key.pem \
    -new -sha256 \
    -subj '/CN=client' \
    -out /root/ca/intermediate/csr/$CLIENT_NAME.csr.pem

echo Create the certificate

openssl ca -config /root/ca/intermediate-openssl.cnf \
      -days 375 -notext -md sha256 \
      -in /root/ca/intermediate/csr/$CLIENT_NAME.csr.pem \
      -out /root/ca/intermediate/certs/$CLIENT_NAME.cert.pem

chmod 444 /root/ca/intermediate/certs/$CLIENT_NAME.cert.pem

echo Check the cert
openssl x509 -noout -text \
    -in /root/ca/intermediate/certs/$CLIENT_NAME.cert.pem
