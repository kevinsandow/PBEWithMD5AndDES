<?php

namespace PBEWithMD5AndDES;

class PBEWithMD5AndDES
{
    //"Magic" keyword used by OpenSSL to put at the beginning of the encrypted
    // bytes.
    private static $MAGIC_SALTED_BYTES = "Salted__";

    private static function getCharRandomSalt($length = 16)
    {
        $salt = '';
        for ($n = 0; $n < $length; $n++) {
            $salt .= dechex(mt_rand(0, 0xF));
        }

        return $salt;
    }

    public static function encrypt(
        $data,
        $keyString,
        $salt = null,
        $iterationsMD5 = 1,
        $segments = 1
    ) {
        $useRandomSalt = false;
        if ($salt === null) {
            $salt = PBEWithMD5AndDES::getCharRandomSalt();
            $useRandomSalt = true;
            /**
             * Number of iterations -
             *  needs to be set to 1 for our roundtrip to work.
             */
            $iterationsMD5 = 1;
        }

        $pkcsKeyGenerator = new PKCSKeyGenerator(
            $keyString,
            $salt,
            $iterationsMD5,
            $segments
        );

        $encryptor = new DESEncryptor(
            $pkcsKeyGenerator->getKey(),
            $pkcsKeyGenerator->getIv()
        );

        $crypt = $encryptor->transformFinalBlock($data);

        if ($useRandomSalt) {
            // add the magic keyword, salt information and encrypted byte
            $crypt = PBEWithMD5AndDES::$MAGIC_SALTED_BYTES
                   . pack("H*", $salt)
                   . $crypt;
        }

        // base64 encode so we can send it around as a string
        return base64_encode($crypt);
    }

    public static function decrypt(
        $data,
        $keyString,
        $salt = null,
        $iterationsMD5 = 1,
        $segments = 1
    ) {
        if ($salt === null) {
            // Get the salt information from the input
            $salt = bin2hex(substr(base64_decode($data), 8, 8));

            $data = base64_encode(substr(base64_decode($data), 16));

            //Number of iterations - needs to be set to 1 for our roundtrip to work
            $iterationsMD5 = 1;
        }

        $pkcsKeyGenerator = new PKCSKeyGenerator(
            $keyString,
            $salt,
            $iterationsMD5,
            $segments
        );

        $encryptor = new DESEncryptor(
            $pkcsKeyGenerator->getKey(),
            $pkcsKeyGenerator->getIv(),
            false
        );

        return $encryptor->transformFinalBlock(base64_decode($data));
    }
}
