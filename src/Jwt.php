<?php

namespace Crecket\AdvancedLogin;

class Jwt
{
    private $passphrase;

    /**
     * Jwt constructor.
     * @param $passphrase
     */
    public function __construct($passphrase)
    {
        $this->passphrase = $passphrase;
    }

    /**
     * Create a new JWT token
     * @param $data
     * @return bool|string
     */
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

    /**
     * Verify a JWT token
     * @param $token
     * @return bool|object
     */
    public function verifyToken($token)
    {
        try {
            return \Firebase\JWT\JWT::decode($token, $this->passphrase, array('HS256'));
        } catch (\Exception $ex) {
            echo (ADVANCEDLOGINSCRIPT_DEBUG === true) ? $ex : '';
            return false;
        }
    }

    /**
     * Returns the current JWT token if set
     * @return bool
     */
    public static function getCurrentUser()
    {
        if (Core::$loggedIn !== false && ADVANCEDLOGINSCRIPT_ENABLE_JWT && !empty($_SESSION['currentuser']['jwt_token'])) {
            return $_SESSION['currentuser']['jwt_token'];
        }
        return false;
    }

}


