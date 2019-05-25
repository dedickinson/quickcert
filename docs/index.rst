.. QuickCert documentation master file, created by
   sphinx-quickstart on Sat May 25 11:37:29 2019.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to QuickCert's documentation!
=====================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

A small tool for quickly creating and managing certificates - aimed at dev/test only


Command line incantations
-------------------------

Start off by creating a root key::

    quickcert.py create-key MyRoot

We then use that key to sign a certificate::

    quickcert.py create-cert --issuer-key-name MyRoot --signing-key-name MyRoot /root/myroot

The root key can be used to create an intermediate certificate::

    quickcert.py create-key MyIntermediate
    quickcert.py create-cert --issuer-key-name MyRoot --signing-key-name MyIntermediate /root/myroot/intermediate/myintermediate

It's now possible to create a certificate for your server::

    quickcert.py create-key --no-password MyServer
    quickcert.py create-cert --issuer-key-name MyIntermediate --signing-key-name MyServer --signing-key-no-password /root/myroot/intermediate/myintermediate/server/myserver

Lastly, get a list of our keys and certificates::

    quickcert.py list-keys
    quickcert.py list-certs


API Documentation / Guide
-------------------------

.. toctree::
   :maxdepth: 2

   api


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`


References
==========

* `OpenSSL Certificate Authority HOW-TO <https://jamielinux.com/docs/openssl-certificate-authority/index.html>`_