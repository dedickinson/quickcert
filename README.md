# Quickcert

A small tool for quickly creating and managing certificates - aimed at dev/test only


# Incantations

    quickcert.py create-key MyRoot
    quickcert.py create-cert --issuer-key-name MyRoot --signing-key-name MyRoot /root/myroot

    quickcert.py create-key MyIntermediate
    quickcert.py create-cert --issuer-key-name MyRoot --signing-key-name MyIntermediate /root/myroot/intermediate/myintermediate

# References

* [OpenSSL Certificate Authority HOW-TO](https://jamielinux.com/docs/openssl-certificate-authority/index.html)