<?php

class DesEncryptor {
  protected $_key;
  protected $_iv;
  protected $_blocksize = 8;
  protected $_encrypt;
  protected $_cipher;

  /**
   * Creates a symmetric Data Encryption Standard (DES) encryptor object
   * with the specified key and initialization vector.
   *
   * @param $key
   * @param $iv
   * @param bool $encrypt
   */
  public function __construct($key, $iv, $encrypt = TRUE) {
      $this->_key = $key;
      $this->_iv = $iv;
      $this->_encrypt = $encrypt;
  }

  /**
   * Transforms the specified region of the specified byte array using PCKS7 padding.
   * @param $text
   * @return string
   */
  public function transformFinalBlock($text) {
    if ($this->_encrypt) {
      $padding = $this->_blocksize - strlen($text) % $this->_blocksize;
      $text .= str_repeat(pack('C', $padding), $padding);
    }

    $text = $this->transformBlock($text);
    
    if (!$this->_encrypt) {
      $aPadding = array_values(unpack('C', substr($text, -1)));
      $padding = $aPadding[0];
      $text = substr($text, 0, strlen($text) - $padding);
    }
    
    return $text;
  }

  /**
   * Transforms the specified region of the specified byte array.
   * @param $text
   * @return string
   */
  public function transformBlock($text) {
    if ($this->_encrypt) {
      return openssl_encrypt($text, 'DES-CBC', $this->_key, OPENSSL_RAW_DATA, $this->_iv);
    }
    else {
      return openssl_decrypt($text, 'DES-CBC', $this->_key, OPENSSL_RAW_DATA, $this->_iv);
    }
  }
}