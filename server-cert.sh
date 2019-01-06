#!/bin/bash -e

FQDN=$1

if [ "$FQDN" = "" ]
  then echo "Please provide the server fqdn"
  exit
fi

if [ "$2" = "" ]
  then 
  IP_ADDR=127.0.0.1
fi

echo FQDN: $FQDN
echo IP Address: $IP_ADDR

if [ "$EUID" -ne 0 ]
  then 
  echo "Please run as root"
  exit
fi

cd /root/ca

echo Create the key
openssl genrsa -aes256 \
    -out /root/ca/intermediate/private/$FQDN.key.pem 2048

chmod 400 /root/ca/intermediate/private/$FQDN.key.pem

echo Create the signing request
#   Organizational Unit Name []:Kraken Certificate Authority
#   Common Name []: kraken.local
openssl req -new -sha256 -config /root/intermediate-openssl.cnf \
    -key /root/ca/intermediate/private/$FQDN.key.pem \
    -subj "/CN=$FQDN" \
    -out /root/ca/intermediate/csr/$FQDN.csr.pem

echo Create the certificate
mkdir tmp
# echo subjectAltName = DNS:$FQDN,IP:127.0.0.1 > tmp/$FQDN.extfile.cnf
echo subjectAltName = DNS:$FQDN,IP:$IP_ADDR > tmp/$FQDN.extfile.cnf
echo extendedKeyUsage = serverAuth >> tmp/$FQDN.extfile.cnf

openssl ca -config /root/intermediate-openssl.cnf \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in /root/ca/intermediate/csr/$FQDN.csr.pem \
      -out /root/ca/intermediate/certs/$FQDN.cert.pem

chmod 444 /root/ca/intermediate/certs/$FQDN.cert.pem

# Verify
openssl x509 -noout -text \
    -in /root/ca/intermediate/certs/$FQDN.cert.pem

openssl verify -CAfile /root/ca/intermediate/certs/ca-chain.cert.pem \
      /root/ca/intermediate/certs/$FQDN.cert.pem
