PBEWithMD5AndDES
================

PHP implementation for passphrase based encryption (PBE) as defined in PKCS#5 version 2.0 (RFC 2898)

The key for the cipher (here DES) is derived from the passphrase by applying a hashfunction (here MD5) several times on it.

You can use to generate the same encrypted bytes as OpenSSL when using DES with password (hashed) encryption.

## Example

```
$ php test.php
Plain text data: Hello World!
Key string:      secret
Salt:            abcdef1234567890
Crypt data:      g0/OhmNJdBXs58Brm3c7sw==
Decripted data:  Hello World!

== Use random salt ==
Plain text data: Hello World!
Key string:      secret
Crypt data:      U2FsdGVkX188lDJBE9omUNc9iGo9sEarSbSeEQwNgDs=
Decripted data:  Hello World!

Check it with openssl command:
echo 'U2FsdGVkX188lDJBE9omUNc9iGo9sEarSbSeEQwNgDs=' | openssl enc -des -a -d -k 'secret'
```
