<?php

require_once 'PkcsKeyGenerator.php';
require_once 'DesEncryptor.php';
require_once 'PbeWithMd5AndDes.php';

$salt = 'abcdef1234567890';

$iterations = 20;
$segments = 1;

$data = 'Hello World!';
$keystring = 'secret';

$crypt = PbeWithMd5AndDes::encrypt(
	$data, $keystring,
	$salt, $iterations, $segments
);

$decrypt = PbeWithMd5AndDes::decrypt(
    $crypt, $keystring,
    $salt, $iterations, $segments
);

echo "Plain text data: $data" . PHP_EOL;
echo "Key string:      $keystring" . PHP_EOL;
echo "Salt:            $salt" . PHP_EOL;
echo "Crypt data:      $crypt" . PHP_EOL;
echo "Decripted data:  $decrypt" . PHP_EOL;

echo PHP_EOL . "== Use random salt ==" . PHP_EOL;

$data = 'Hello World!';
$keystring = 'secret';

$crypt = PbeWithMd5AndDes::encrypt(
	$data, $keystring
);

$decrypt = PbeWithMd5AndDes::decrypt(
    $crypt, $keystring
);

echo "Plain text data: $data" . PHP_EOL;
echo "Key string:      $keystring" . PHP_EOL;
echo "Crypt data:      $crypt" . PHP_EOL;
echo "Decripted data:  $decrypt" . PHP_EOL;
echo PHP_EOL;
echo "Check it with openssl command: echo '$crypt' | openssl enc -des -a -d -k '$keystring'" . PHP_EOL;

?>