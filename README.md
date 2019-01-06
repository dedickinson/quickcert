# hub-util-tls

Helper tools for setting up TLS keys. The work is is largely based on the
really useful article [OpenSSL Certificate Authority](https://jamielinux.com/docs/openssl-certificate-authority/index.html) by Jamie Nguyen.

This is really just a helper container and shouldn't be relied on for production.

To build the Docker image

    docker build -t hub-util-tls .

Create a volume to store the certs:

    docker volume create certs

You'll likely want to run `/var/lib/docker/volumes/certs/_data` to determine the
location of the volume.

## Creating certificates

Run up an enter an instance:

    docker run --rm -it -v certs:/root/ca hub-util-tls /bin/bash

Start by creating the root certificate:

    ~/root-cert.sh

Followed by the intermediate certificate:

    ~/intermediate-cert.sh

You can then create any number of server certs (for example):

    ~/server-cert.sh kraken.local

The `server-cert.sh` script requires the fqdn of the server and (optionally), the IP address

## Example usage

### Using a cert with an NGINX container

build image:

    cd example/nginx
    docker build -t nginx-demo .

Then try to run up a basic instance (and check it out at http://localhost:8080/):

    docker run --rm -ti -p 8080:80 nginx-demo

And now for realsies:

    docker run --rm -ti -p 8443:443 -p 8080:80 \
        -v $PWD/nginx.conf:/etc/nginx/nginx.conf:ro \
        -v certs:/certs \
        nginx

You should be able to access the site at:

- http://kraken.local:8080
- TLS:  https://kraken.local:8443/

Naturally, your host's fqdn (e.g. `kraken.local`) needs to line up with the configuration 
as it's provided in the NGINX config and used in the TLS cert.

Your browser will still raise an alert that the certificate isn't trusted. 
If you want to make it all "official", add you certificate chain to your system.
Firefox makes this easy - go to `Preferences > Privacy and Security > Certificates: View Certificates`.
Under `Authorities`, click `Import` and add in the `intermediate/certs/ca-chain.cert.pem` cert from the 
docker volume (locate this using `docker volume inspect certs` and noting the `Mountpoint`).


See also [NGINX - Configuring HTTPS servers](http://nginx.org/en/docs/http/configuring_https_servers.html)

### Working with Docker

WARNING: This is yet to be tested.

Connect:

    docker --tlsverify \
        --tlscacert=/root/ca/intermediate/certs/ca-chain.cert.pem \
        --tlscert=/root/ca/intermediate/certs/client.cert.pem \
        --tlskey=/root/ca/intermediate/private/client.key.pem \
        --host=docker.kraken.local:2376 version

The various certificates can be placed in a user's `~/.docker/` directory:

    mkdir -pv ~/.docker
    chmod 700 ~/.docker
    cp -v /root/ca/intermediate/certs/ca-chain.cert.pem ~/.docker/ca.pem
    cp -v /root/ca/intermediate/certs/client.cert.pem ~/.docker/cert.pem
    cp -v /root/ca/intermediate/private/client.key.pem ~/.docker/key.pem

To point at the docker host, set the `DOCKER_HOST` environment variable:

    export DOCKER_HOST=tcp://docker.kraken.local:2376 DOCKER_TLS_VERIFY=1

or in Powershell:

    $Env:DOCKER_HOST += "tcp://docker.kraken.local:2376"

Make sure your DNS/`/etc/hosts`/`C:\Windows\System32\Drivers\etc\hosts` maps 
to your docker host.

You should now be able to run 

    docker run hello-world

... and in Powershell:

    docker --tlsverify run hello-world

See also:

- https://success.docker.com/article/how-do-i-enable-the-remote-api-for-dockerd
- https://docs.docker.com/engine/security/https/#create-a-ca-server-and-client-keys-with-openssl

#### Configure the docker service

1. Copy `daemon.json` to `/etc/docker/`
1. Copy `override.conf` to `/etc/systemd/system/docker.service.d/`