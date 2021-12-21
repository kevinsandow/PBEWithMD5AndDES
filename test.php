<?php

require_once 'PKCSKeyGenerator.php';
require_once 'DESEncryptor.php';
require_once 'PBEWithMD5AndDES.php';

$salt = 'abcdef1234567890';

$iterations = 20;
$segments = 1;

$data = 'Hello World!';
$keyString = 'secret';

$crypt = PBEWithMD5AndDES\PBEWithMD5AndDES::encrypt(
    $data,
    $keyString,
    $salt,
    $iterations,
    $segments
);

$decrypt = PBEWithMD5AndDES\PBEWithMD5AndDES::decrypt(
    $crypt,
    $keyString,
    $salt,
    $iterations,
    $segments
);

echo "Plain text data: $data" . PHP_EOL;
echo "Key string:      $keyString" . PHP_EOL;
echo "Salt:            $salt" . PHP_EOL;
echo "Crypt data:      $crypt" . PHP_EOL;
echo "Decripted data:  $decrypt" . PHP_EOL;

echo PHP_EOL . "== Use random salt ==" . PHP_EOL;

$crypt = PBEWithMD5AndDES\PBEWithMD5AndDES::encrypt(
    $data,
    $keyString
);

$decrypt = PBEWithMD5AndDES\PBEWithMD5AndDES::decrypt(
    $crypt,
    $keyString
);

echo "Plain text data: $data" . PHP_EOL;
echo "Key string:      $keyString" . PHP_EOL;
echo "Crypt data:      $crypt" . PHP_EOL;
echo "Decrypted data:  $decrypt" . PHP_EOL;
echo PHP_EOL;
echo "Check it with openssl command:" . PHP_EOL
   . "echo '$crypt' | openssl enc -des -a -d -k '$keyString'" . PHP_EOL;
