<?php

 namespace Gorin;


 class SecureCookie {

   protected $encrypt_method = 'AES-256-CBC';

   protected $cookie = [];

   protected $key;

   protected $iv;

   public function __construct (string $key) {
     $iv = base64_encode($key);
     $this->key = hash('sha256', $key);
     $this->iv = substr(hash('sha256', $iv), 0, 16);
     foreach ($_COOKIE as $name => $value) {
       $named = $this->decrypt($name);
       $valued = $this->decrypt($value);
       $name = $named ? $named : $name;
       $value = $valued ? $valued : $value;
       $this->cookie[$name] = [
         'value' => $value,
         'expires' => false,
         'path' => '',
         'domain' => '',
         'secure' => false,
         'httponly' => false
       ];
     }
   }

   public function set (string $name, string $value = '', int $expires = 0, string $path = '', string $domain = '', bool $secure = false, bool $httponly = false) {
     $this->cookie[$name] = [
       'value' => $value,
       'expires' => $expires,
       'path' => $path,
       'domain' => $domain,
       'secure' => $secure,
       'httponly' => $httponly
     ];
     return $this;
   }

   public function get (string $name) {
     if ($this->has($name)) {
       return $this->cookie[$name]['value'];
     }
   }

   public function has (string $name) {
     return isset($this->cookie[$name]);
   }

   public function delete (string $name) {
     if ($this->has($name)) {
       $this->cookie[$name]['expires'] = '';
       $this->cookie[$name]['expires'] = time() - 1000;
     }
     return $this;
   }

   public function send () {
     foreach ($this->cookie as $name => $opt) {
       if ($opt['expires'] !== false) {
         setcookie($this->encrypt($name), $this->encrypt($opt['value']), $opt['expires'], $opt['path'], $opt['domain'], $opt['secure'], $opt['httponly']);
       }
     }
   }

   protected function encrypt (string $str) {
     return urlencode(openssl_encrypt($str, $this->encrypt_method, $this->key, 1, $this->iv));
   }

   public function decrypt (string $str) {
     return openssl_decrypt(urldecode($str), $this->encrypt_method, $this->key, 1, $this->iv);
    }

 }
