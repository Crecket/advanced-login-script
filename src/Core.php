<?php

namespace Crecket\AdvancedLogin;

class Core
{

    public static $loggedIn;

    protected $conn;

    /**
     * Core constructor.
     */
    public function __construct()
    {
        $this->createConnection();
    }

    /**
     * @throws \Doctrine\DBAL\DBALException
     */
    private function createConnection()
    {
        // Start the DBAL config settings
        $config = new \Doctrine\DBAL\Configuration();
        $connectionParams = array(
            'dbname' => ADVANCEDLOGINSCRIPT_DB_NAME,
            'user' => ADVANCEDLOGINSCRIPT_DB_USER,
            'password' => ADVANCEDLOGINSCRIPT_DB_PASS,
            'host' => ADVANCEDLOGINSCRIPT_DB_HOST,
            'driver' => 'pdo_mysql',
        );
        // Create a connection with DBAL
        $this->conn = \Doctrine\DBAL\DriverManager::getConnection($connectionParams, $config);
    }

    /**
     * @return mixed
     */
    public function newBuilder()
    {
        return $this->conn->createQueryBuilder();
    }

    /**
     * Set a message to session for the given key
     * @param $type
     * @param $message
     */
    public function setMessage($type, $message)
    {
        if (!empty($message)) {
            $_SESSION[ADVANCEDLOGINSCRIPT_MESSAGE_KEY][] = array('message' => $message, 'type' => $type);
        }
    }

    /**
     * Send a email with the given message and title. Targets are in array form >   array("name" => "Target's name", "email" => "Target's email address")
     * @param $message
     * @param $title
     * @param array $target
     * @return bool
     * @throws Exception
     * @throws phpmailerException
     */
    public function sendMail($message, $title, $target = array())
    {
        if (!class_exists('PHPMailer')) {
            throw new Exception("Couldn't find PHPMailer class!");
        }

        $mail = new \PHPMailer(); // create a new object
        $mail->IsSMTP(); // enable SMTP
        $mail->SMTPDebug = 0; // debugging: 1 = errors and messages, 2 = messages only
        $mail->SMTPAuth = true; // authentication enabled
        $mail->SMTPSecure = 'ssl'; // secure transfer enabled REQUIRED for Gmail
        $mail->Host = ADVANCEDLOGINSCRIPT_EMAIL_HOST;
        $mail->Port = 465; // or 587
        $mail->IsHTML(true);
        $mail->Username = ADVANCEDLOGINSCRIPT_EMAIL_USERNAME;
        $mail->Password = ADVANCEDLOGINSCRIPT_EMAIL_PASSWORD;
        $mail->SetFrom(ADVANCEDLOGINSCRIPT_EMAIL_USERNAME);
        $mail->Subject = $title;
        $mail->Body = $message;
        $mail->Timeout = 10; // set the timeout (seconds)
        foreach ($target as $person) {
            $mail->addAddress($person['email'], $person['name']);
        }

        if (!$mail->Send()) {
            echo "Mailer Error: " . $mail->ErrorInfo;
        } else {
            return true;
        }

    }


    /**
     * Basic cookie check function, Returns false if cookie is not set
     * @param $cookiename
     * @return bool
     */
    public function checkCookie($cookiename)
    {
        if (isset($_COOKIE[$cookiename])) {
            return $_COOKIE[$cookiename];
        }
        return false;
    }


    /**
     * Set a new cookie using the config's parameters
     * @param $name
     * @param $value
     * @param bool $expire
     * @return bool
     */
    public function setCookie($name, $value, $expire = false)
    {
        if ($expire == false) {
            $expire = ADVANCEDLOGINSCRIPT_COOKIE_STORE_DURATION;
        }

        if (setcookie($name, $value, $expire, ADVANCEDLOGINSCRIPT_COOKIE_FOLDER, ADVANCEDLOGINSCRIPT_COOKIE_DOMAIN, ADVANCEDLOGINSCRIPT_COOKIE_HTTPS_ONLY)) {
            return true;
        }
        return false;
    }

    /**
     * Delete the cookie for the given key
     * @param $name
     */
    public function deleteCookie($name)
    {

        setcookie($name, null, time() - 3600, ADVANCEDLOGINSCRIPT_COOKIE_FOLDER);
    }

}


