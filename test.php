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

echo '<pre>';
echo $data . PHP_EOL;
echo $crypt . PHP_EOL;