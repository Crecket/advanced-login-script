<?php

namespace Crecket\AdvancedLogin;

class Jwt
{
    private $passphrase;

    public function __construct($passphrase)
    {
        $this->passphrase = $passphrase;
    }

    public function createToken($data)
    {
        try {
            return \Firebase\JWT\JWT::encode($data, $this->passphrase);
        } catch (\Exception $ex) {
            echo (ADVANCEDLOGINSCRIPT_DEBUG === true) ? $ex : '';
            return false;
        }
    }

    public function verifyToken($token)
    {
        try {
            return \Firebase\JWT\JWT::decode($token, $this->passphrase, array('HS256'));
        } catch (\Exception $ex) {
            echo (ADVANCEDLOGINSCRIPT_DEBUG === true) ? $ex : '';
            return false;
        }
    }

}


