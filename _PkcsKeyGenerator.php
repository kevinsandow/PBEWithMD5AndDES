<?php

namespace PBEWithMD5AndDES;

class PKCSKeyGenerator
{
    protected $key;
    protected $iv;

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Gets the initialization vector.
     *
     * @return string
     */
    public function getIv()
    {
        return $this->iv;
    }

    /**
     * @param string $keyString     key string
     * @param string $salt          salt string
     * @param int    $iterationsMD5 number of MF5 iterations
     * @param int    $segments      number of segments
     */
    public function __construct($keyString, $salt, $iterationsMD5, $segments)
    {
        $salt = pack('H*', $salt);
        $keyMaterial = '';
        $data = $keyString . $salt;
        $result = '';

        for ($j = 0; $j < $segments; $j++) {
            if ($j == 0) {
                $result = $data;
            } else {
                $result .= $data;
            }

            for ($i = 0; $i < $iterationsMD5; $i++) {
                $result = md5($result, true);
            }

            $keyMaterial .= $result;
        }

        $this->key = substr($keyMaterial, 0, 8);
        $this->iv = substr($keyMaterial, 8, 8);
    }
}
