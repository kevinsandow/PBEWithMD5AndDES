<?php

class PkcsKeyGenerator 
{

    protected $_key;
    protected $_iv;

    /**
	 * @return string
     */
    public function getKey()
    {
        return $this->_key;
    }

    /**
     * Gets the initialization vector.
	 * @return string
     */
    public function getIv()
    {
        return $this->_iv;
    }

    function __construct($keystring, $salt, $iterationsMd5, $segments)
    {
        $salt = pack('H*', $salt);
        $keyMaterial = '';
        $data = $keystring . $salt;
        $hashtarget = '';

        for ($j = 0; $j < $segments; $j++)
        {
            if ($j == 0)
            {
                $result = $data;
            }
            else
            {
                $result .= $data;
            }

            for ($i = 0; $i < $iterationsMd5; $i++)
            {
                $result = md5($result, true);
            }

            $keyMaterial .= $result;
        }

        $this->_key = substr($keyMaterial, 0, 8);
        $this->_iv = substr($keyMaterial, 8, 8);
    }
}