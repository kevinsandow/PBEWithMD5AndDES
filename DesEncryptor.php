<?php

class DesEncryptor
{

    protected $_key;
    protected $_iv;
    protected $_blocksize = 8;
    protected $_encrypt;
    protected $_cipher;

    /**
     * Creates a symmetric Data Encryption Standard (DES) encryptor object
     * with the specified key and initialization vector.
     * @param string $key 64bit - The secret key to use for the symmetric algorithm.
     * @param string $iv 64bit - The initialization vector to use for the symmetric algorithm.
     */
    public function __construct($key, $iv, $encrypt = true)
    {
        $this->_key = $key;
        $this->_iv = $iv;
        $this->_encrypt = $encrypt;

        $this->_cipher = mcrypt_module_open(MCRYPT_DES, '', MCRYPT_MODE_CBC, '');
        mcrypt_generic_init($this->_cipher, $this->_key, $this->_iv);
    }

    public function __destruct()
    {
        mcrypt_generic_deinit($this->_cipher);
        mcrypt_module_close($this->_cipher);
    }

    /**
     * Transforms the specified region of the specified byte array using PCKS7 padding.
     * @param unknown_type $text
     * @return string
     */
    public function transformFinalBlock($text)
    {
        if ($this->_encrypt)
        {
            $padding = $this->_blocksize - strlen($text) % $this->_blocksize;
            $text .= str_repeat(pack('C', $padding), $padding);
        }

        $text = $this->transformBlock($text);
        
        if (!$this->_encrypt)
        {
            $padding = array_shift(unpack('C', substr($text, -1)));
            $text = substr($text, 0, strlen($text) - $padding);
        }
        
        return $text;
    }

    /**
     * Transforms the specified region of the specified byte array.
     * @param unknown_type $text
     * @return string
     */
    public function transformBlock($text)
    {
        if ($this->_encrypt)
        {
            return mcrypt_generic($this->_cipher, $text);
        }
        else
        {
            return mdecrypt_generic($this->_cipher, $text);
        }
    }
}