<?php

class PbeWithMd5AndDes
{

    public static function encrypt($data, $keystring, $salt, 
		$iterationsMd5, $segments)
    {
        $pkcsKeyGenerator = new PkcsKeyGenerator(
			$keystring, $salt, $iterationsMd5, $segments);
		
        $encryptor = new DesEncryptor(
			$pkcsKeyGenerator->getKey(), $pkcsKeyGenerator->getIv());
		
        return base64_encode($encryptor->transformFinalBlock($data));
    }

    public static function decrypt($data, $keystring, $salt,
		$iterationsMd5, $segments)
    {
        $pkcsKeyGenerator = new PkcsKeyGenerator(
			$keystring, $salt, $iterationsMd5, $segments);

        $encryptor = new DesEncryptor(
			$pkcsKeyGenerator->getKey(), $pkcsKeyGenerator->getIv(), false);

        return $encryptor->transformFinalBlock(base64_decode($data));
    }
}