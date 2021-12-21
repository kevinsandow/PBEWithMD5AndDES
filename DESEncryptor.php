<?php

namespace PBEWithMD5AndDES;

class DESEncryptor
{
    protected $key;
    protected $iv;
    protected $blockSize = 8;
    protected $encrypt;
    protected $cipher;

    /**
     * Creates a symmetric Data Encryption Standard (DES) encryptor object
     * with the specified key and initialization vector.
     *
     * @param string $key     key
     * @param string $iv      initialization vettor
     * @param bool   $encrypt whether we should encrypt or decrypt
     */
    public function __construct($key, $iv, $encrypt = true)
    {
        $this->key = $key;
        $this->iv = $iv;
        $this->encrypt = $encrypt;
    }

    /**
     * Transforms the specified region of the specified byte array using
     * PCKS7 padding.
     *
     * @param string $text
     *
     * @return string
     */
    public function transformFinalBlock($text)
    {
        if ($this->encrypt) {
            $padding = $this->blockSize - strlen($text) % $this->blockSize;
            $text .= str_repeat(pack('C', $padding), $padding);
        }

        $text = $this->transformBlock($text);

        if (!$this->encrypt) {
            $aPadding = array_values(unpack('C', substr($text, -1)));
            $padding = $aPadding[0];
            $text = substr($text, 0, strlen($text) - $padding);
        }

        return $text;
    }

    /**
     * Transforms the specified region of the specified byte array.
     *
     * @param string $text
     *
     * @return string
     */
    public function transformBlock($text)
    {
        if ($this->encrypt) {
            return openssl_encrypt(
                $text,
                'DES-CBC',
                $this->key,
                OPENSSL_RAW_DATA,
                $this->iv
            );
        }

        return openssl_decrypt(
            $text,
            'DES-CBC',
            $this->key,
            OPENSSL_RAW_DATA,
            $this->iv
        );
    }
}
