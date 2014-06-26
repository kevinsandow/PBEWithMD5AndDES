PBEWithMD5AndDES
================

PHP implementation for passphrase based encryption (PBE) as defined in PKCS#5 version 2.0 (RFC 2898)

The key for the cipher (here DES) is derived from the passphrase by applying a hashfunction (here MD5) several times on it.

You can use to generate the same encrypted bytes as OpenSSL when using DES with password (hashed) encryption.
