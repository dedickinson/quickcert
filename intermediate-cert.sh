#!/bin/bash -e

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

mkdir -p /root/ca/intermediate
cd /root/ca/intermediate

mkdir -p certs crl csr newcerts private
chmod 700 private
touch index.txt

echo 1000 > serial
echo 1000 > crlnumber

echo Create the intermediate key

openssl genrsa -aes256 \
    -out /root/ca/intermediate/private/intermediate.key.pem 4096

chmod 400 /root/ca/intermediate/private/intermediate.key.pem

echo Create the intermediate csr
# Make sure you set a different Common Name to the root cert - e.g.
#   Organizational Unit Name []:Kraken Certificate Authority
#   Common Name []:Kraken Intermediate CA

openssl req -config /root/intermediate-openssl.cnf -new -sha256 \
    -key /root/ca/intermediate/private/intermediate.key.pem \
    -out /root/ca/intermediate/csr/intermediate.csr.pem

echo Create the intermediate cert
openssl ca -config /root/root-openssl.cnf -extensions v3_intermediate_ca \
    -days 3650 -notext -md sha256 \
    -in /root/ca/intermediate/csr/intermediate.csr.pem \
    -out /root/ca/intermediate/certs/intermediate.cert.pem

chmod 444 /root/ca/intermediate/certs/intermediate.cert.pem

echo Verify the cert
openssl x509 -noout -text -in /root/ca/intermediate/certs/intermediate.cert.pem

echo Verify against the root cert
openssl verify -CAfile /root/ca/certs/ca.cert.pem \
      /root/ca/intermediate/certs/intermediate.cert.pem

echo Create the certificate chain file
cat /root/ca/intermediate/certs/intermediate.cert.pem \
    /root/ca/certs/ca.cert.pem > /root/ca/intermediate/certs/ca-chain.cert.pem

chmod 444 /root/ca/intermediate/certs/ca-chain.cert.pem
