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

        $data['iat'] = time();
        // Set default expiration date
        if (!isset($data['exp'])) {
            $data['exp'] = ADVANCEDLOGINSCRIPT_COOKIE_STORE_DURATION;
        }

        // Try to encode the data
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


