FROM ubuntu:bionic

ARG DEBIAN_FRONTEND=noninteractive

RUN apt update && \
    apt upgrade -y && \
    apt install -y libterm-readline-gnu-perl && \
    apt install -y openssl

WORKDIR /root

COPY root-openssl.cnf /root/
COPY root-cert.sh /root/
COPY intermediate-openssl.cnf /root/
COPY intermediate-cert.sh /root/
COPY server-cert.sh /root/
COPY client-cert.sh /root/

RUN mkdir -p /root/ca

WORKDIR /root/ca
VOLUME /root/ca
