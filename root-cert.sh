#!/bin/bash -e

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

mkdir -p certs crl newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial

echo Create the root key
openssl genrsa -aes256 -out /root/ca/private/ca.key.pem 4096
chmod 400 /root/ca/private/ca.key.pem

echo Create the root certificate
# Make sure you set a Common Name - e.g.
#   Organizational Unit Name []:Kraken Certificate Authority
#   Common Name []:Kraken Root CA
openssl req -config /root/root-openssl.cnf \
      -key /root/ca/private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out /root/ca/certs/ca.cert.pem

chmod 444 /root/ca/certs/ca.cert.pem

echo Verify the root certificate
openssl x509 -noout -text -in /root/ca/certs/ca.cert.pem
