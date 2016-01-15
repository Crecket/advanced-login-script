<?php

namespace Crecket\AdvancedLogin;


class Login extends Core
{

    /**
     * Login constructor.
     */
    public function __construct()
    {
        parent::__construct();
        if (!isset($_SESSION[ADVANCEDLOGINSCRIPT_MESSAGE_KEY])) {
            $_SESSION[ADVANCEDLOGINSCRIPT_MESSAGE_KEY] = array();
        }

        $this->checkLoggedIn();

    }

    /**
     * Login a existing user
     * @param $username
     * @param $password
     * @param $rememberme
     * @return bool
     */
    public function login($username, $password, $rememberme = "off")
    {

        $this->checkLoggedIn();

        if (Core::$loggedIn !== false) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_ALREADY_LOGGED_IN);
            return false;
        }


        $username = strtolower($username);
        $_SESSION['stored_login_fields']['username'] = $username;
        if ($failedLogins = $this->checkFailedLogins() >= 3) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_FAILED_ATTEMPTS);
            return false;
        }
        if (!filter_var($username, FILTER_VALIDATE_EMAIL) === false) {
            // the username that was entered is a valid email, check for a user in the database with this email
            $get_user = $this->newBuilder()
                ->select('*, u.id as id, ug.id as usergroup_id, ug.name as usergroup')
                ->from('users', 'u')
                ->innerJoin('u', 'usergroups', 'ug', 'u.user_group = ug.id')
                ->where('LOWER(email) = :email')
                ->setParameter('email', $username)
                ->execute();

        } else {
            // the username that was entered is not a valid email, check for a user in the database with this username
            $get_user = $this->newBuilder()
                ->select('*, u.id as id, ug.id as usergroup_id, ug.name as usergroup')
                ->from('users', 'u')
                ->innerJoin('u', 'usergroups', 'ug', 'u.user_group = ug.id')
                ->where('LOWER(username) = :username')
                ->setParameter('username', $username)
                ->execute();
        }
        $record = $get_user->fetch(); // fetch the results
        if (!$record) { // no results > no user was found
            $this->addLoginAttempt(NULL, 'not_found'); // add a failed login attempt
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_INVALID_LOGIN);
            return false;
        } elseif ($record['banned'] === 1) {
            // user is banned, run the logout function to make sure the session is reset
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_BANNED);
            $this->logout();
            return false;
        } elseif ($record['active'] == 0) {
            // user is inactive, warn that the user needs to activate his/her account
            $this->logout();
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_INACTIVE);
            return false;
        }

        $rehash = false;

        if (md5($password) === $record['password']) {

            // first check if the password matches with the md5 hash, we do this first because its fast
            $rehash = true;

        } elseif (\SecureFuncs\SecureFuncs::password_verify($password, $record['password'])) {

            //next check for a bcrypt password match
            $rehash = password_needs_rehash($record['password'], PASSWORD_DEFAULT);

        } else {

            // no user found or password invalid, invalid login
            $this->addLoginAttempt($record['id'], 'invalid_password');
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_INVALID_LOGIN);
            return false;

        }

        // update some data
        $update_user = $this->newBuilder()
            ->update('users')
            ->set('last_login', 'now()')
            ->where('id = :id')
            ->setParameter(":id", $record['id']);


        if ($rehash) { // password needs to be rehashed
            $update_data['password'] = \SecureFuncs\SecureFuncs::password_hash($password, PASSWORD_DEFAULT);
            $update_user
                ->set('password', ':password')
                ->setParameter(":password", $update_data['password']);
        }
        $update_user->execute();

        if ($rememberme == "on") { // set new authentication cookie
            $this->set_auth_cookie($record['id']);
        }

        // add a succesful login attempt to the database
        $this->addLoginAttempt($record['id'], 1);

        // unset password variable before adding the session variables
        unset($record['password']);
        unset($_SESSION['stored_login_fields']);
        $_SESSION['currentuser'] = $record;

        // refresh the session ID
        session_regenerate_id();

        // display a message to notify the user
        $this->setMessage('success', ADVANCEDLOGINSCRIPT_USER_LOGGED_IN . $record['username']);

        return true;
    }


    /**
     * @return bool
     * When $verify is set to true, it will also check for changes in the user account (E.G. changes in usergroup, banned and active status)
     * User $verify = false if you only want to check if the user is logged in.
     */
    public function checkLoggedIn()
    {

        // user id is in session
        if (!empty($_SESSION['currentuser']['id'])) {

            // verify user and refresh his user data
            if ($this->login_user($_SESSION['currentuser']['id'])) {
            } else {
                // invalid login, logout user to remove user data fro msession
                $this->logout();
            }
        } else {

            // check for a authentication cookie
            $auth_cookie_data = $this->check_auth_cookie();
            if ($auth_cookie_data !== false) {

                // valid auth cookie, login user
                $this->addLoginAttempt($auth_cookie_data, 'cookie');
                $this->login_user($auth_cookie_data);
            } else {
                // check if QRcode session is set
                if (!empty($_SESSION[ADVANCEDLOGINSCRIPT_QR_COOKIEKEY]['id'])) {

                    $qrData = $this->checkQrActivated($_SESSION[ADVANCEDLOGINSCRIPT_QR_COOKIEKEY]['qr']);
                    if ($qrData !== false) {
                        // QRCode has been activated
                        $this->addLoginAttempt($qrData['user_id'], 'qrcode');
                        $this->login_user($qrData['user_id']);
                        unset($_SESSION[ADVANCEDLOGINSCRIPT_QR_COOKIEKEY]);
                        session_regenerate_id();
                        $this->destroyOldQrCodes();
                    } else {
                        Core::$loggedIn = false;
                    }
                } else {
                    Core::$loggedIn = false;
                }
            }
        }

        return Core::$loggedIn;
    }

    /**
     * @param $id
     * @return bool
     */
    public function login_user($id)
    {
        $check_user = $this->newBuilder()
            ->select('*, u.id as id, ug.id as usergroup_id, ug.name as usergroup')
            ->from('users', 'u')
            ->innerJoin('u', 'usergroups', 'ug', 'u.user_group = ug.id')
            ->where('u.id = :id')
            ->setParameter('id', $id)
            ->execute();

        if ($check_user->rowcount() > 0) {
            $user_data = $check_user->fetch();
            if ($this->verify_user($user_data)) {
                $_SESSION['currentuser'] = $user_data;
                Core::$loggedIn = $_SESSION['currentuser']['id'];
                $this->updateUserTime($_SESSION['currentuser']['id']);
                return Core::$loggedIn;
            }
        }
        Core::$loggedIn = false;
        return Core::$loggedIn;
    }

    public function updateUserTime($id)
    {
        $update = $this->newBuilder()
            ->update('users', 'u')
            ->set('last_login', 'now()')
            ->where('u.id = :id')
            ->setParameter('id', $id)
            ->execute();
        return $update;
    }

    /**
     * Logout the current user and destroy any stored cookies in the database
     * @return bool
     */
    public function logout()
    {

        // remove cookie for this user/ip from database
        $this->newBuilder()
            ->delete('user_auth')
            ->where('userid = :id AND ip = :ip')
            ->setParameter('id', $_SESSION['currentuser']['id'])
            ->setParameter('ip', filter_input(INPUT_SERVER, 'REMOTE_ADDR'))
            ->execute();

        // destroy remember me cookie
        $this->deleteCookie(ADVANCEDLOGINSCRIPT_REMEMBER_ME_COOKIE);

        // only remove the user data from the session
        unset($_SESSION['currentuser']);
        Core::$loggedIn = false;

        $this->setMessage('success', ADVANCEDLOGINSCRIPT_USER_LOGGEDOUT);

    }

    /**
     * @param $user_data
     * @return bool
     */
    public function verify_user($user_data)
    {

        if ($user_data['banned'] === 1) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_BANNED);
        } elseif ($user_data['active'] === 0) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_INACTIVE);
        } else {
            return true;
        }

        return false;

    }

    /**
     * @return bool
     * Set the parameter to true if you want to login the user on success.
     * In both cases it will return the user's id if the authentication cookie is correct
     */
    public function check_auth_cookie()
    {
        if (isset($_COOKIE[ADVANCEDLOGINSCRIPT_REMEMBER_ME_COOKIE])) {
            $cookieData = explode("||", $_COOKIE[ADVANCEDLOGINSCRIPT_REMEMBER_ME_COOKIE]);
            if (count($cookieData) == 2) { // 2 parts should be stored in here

                // get the data based on selector from cookie
                $selectorData = $this->newBuilder()
                    ->select('*')
                    ->from('user_auth')
                    ->where('selector = :selector AND ip = :ip')
                    ->setParameter('selector', $cookieData[0])
                    ->setParameter('ip', filter_input(INPUT_SERVER, 'REMOTE_ADDR'))
                    ->execute();

                if ($selectorData->rowcount() > 0) {

                    // fetch database results
                    $selectorData = $selectorData->fetch();

                    // compare hash and check if cookie has expired
                    if ($selectorData['token'] == hash('sha256', $cookieData[1] . filter_input(INPUT_SERVER, 'REMOTE_ADDR') . ADVANCEDLOGINSCRIPT_SECRET_KEY) && $selectorData['expires'] > date('Y-m-d H:i:s')) {
                        return $selectorData['userid'];
                    }
                }
            }
            $this->deleteCookie(ADVANCEDLOGINSCRIPT_REMEMBER_ME_COOKIE);
        }
        return false;
    }

    /**
     * Set a new authentication cookie and add a row to the database
     * @param $userid
     * @return bool
     */
    public function set_auth_cookie($userid)
    {

        $selector = \SecureFuncs\SecureFuncs::randomString(32);
        $random = \SecureFuncs\SecureFuncs::randomString(64);
        $token = $selector . "||" . $random;
        $randomDb = hash('sha256', $random . filter_input(INPUT_SERVER, 'REMOTE_ADDR') . ADVANCEDLOGINSCRIPT_SECRET_KEY);
        $expiresDb = date('Y/m/d H:i:s', ADVANCEDLOGINSCRIPT_COOKIE_STORE_DURATION);

//        $this->deleteCookie(ADVANCEDLOGINSCRIPT_REMEMBER_ME_COOKIE);
        if ($this->setCookie(ADVANCEDLOGINSCRIPT_REMEMBER_ME_COOKIE, $token)) {

            $this->newBuilder()
                ->delete('user_auth')
                ->where('ip = :ip AND userid = :id')
                ->setParameter('ip', filter_input(INPUT_SERVER, 'REMOTE_ADDR'))
                ->setParameter('id', $userid)
                ->execute();

            $insertToken = $this->newBuilder()
                ->insert('user_auth')
                ->values(
                    array(
                        'selector' => ':selector',
                        'token' => ':token',
                        'userid' => ':id',
                        'expires' => ':expires',
                        'ip' => ':ip'
                    )
                )
                ->setParameter('selector', $selector)
                ->setParameter('token', $randomDb)
                ->setParameter('id', $userid)
                ->setParameter('expires', $expiresDb)
                ->setParameter('ip', filter_input(INPUT_SERVER, 'REMOTE_ADDR'))
                ->execute();
            if ($insertToken === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Add a new login attempt, $type has to be 1 for success or 0 for failure
     * @param $target
     * @param $type
     * @return mixed
     * @throws Exception
     */
    public function addLoginAttempt($target, $type)
    {

        $insert_login_attempt = $this->newBuilder()
            ->insert('login_attempts')
            ->values(
                array(
                    'ip' => ':ip',
                    'login_type' => ':type',
                    'target' => ':target',
                )
            )
            ->setParameter('ip', filter_input(INPUT_SERVER, 'REMOTE_ADDR'))
            ->setParameter('type', $type)
            ->setParameter('target', $target)
            ->execute();
        return $insert_login_attempt;
    }

    /**
     * Return the amount of failed login attempts in the last 15 minutes
     * @return mixed
     */
    public function checkFailedLogins()
    {
        $check_logins = $this->newBuilder()
            ->select('*')
            ->from('login_attempts')
            ->where('ip = :ip')
            ->setParameter('ip', filter_input(INPUT_SERVER, 'REMOTE_ADDR'))
            ->where("login_type = 'fail' AND datetime > DATE_SUB(NOW(), INTERVAL 15 MINUTE)")
            ->execute();
        return $check_logins->rowcount();
    }


    /* ======================= REGISTRATION ============================ */

    /**
     * Register a new user
     * @param $username
     * @param $email
     * @param $password
     * @param $password_repeat
     * @return boolean
     */
    public function register($username, $email, $password, $password_repeat)
    {

        $this->checkLoggedIn();

        if (CORE::$loggedIn !== false) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_ALREADY_LOGGED_IN);
            return false;
        }

        $username = strtolower(trim($username));
        $_SESSION['stored_register_fields']['username'] = $username;
        $email = strtolower(trim($email));
        $_SESSION['stored_register_fields']['email'] = $email;

        if (empty($username)) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_EMPTY_NAME);
        } elseif (preg_match("/^[0-9A-Za-z_]+$/", $username) == 0) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_INVALID_NAME);
        } elseif (empty($password) || empty($password_repeat)) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_EMPTY_PASSWORDS);
        } elseif ($password !== $password_repeat) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_BOTH_PASSWORDS_SAME);
        } elseif (strlen($password) < 8) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_SHORT_PASSWORDS);
        } elseif (strlen($username) > 64 || strlen($username) < 2) {
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_NAME_MINIMUM_LENGTH);
        } elseif (!preg_match('/^[a-zA-Z-_ \d]{2,64}$/i', $username)) {
            $this->setMessage('error', 'You entered a character which is not allowed.');
        } elseif (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->setMessage('error', 'Please enter a valid email');
        } else {

            // Clear all expired user activations
            $this->cleanNotActivatedAccounts();

            $check_user = $this->newBuilder()
                ->select('*')
                ->from('users')
                ->where('LOWER(username) = :username OR LOWER(email) = :email')
                ->setParameter(':username', $username)
                ->setParameter(':email', $email)
                ->execute();

            if ($check_user->rowcount() > 0) {
                $existing_user = $check_user->fetch();
                if ($existing_user['username'] == $username) {
                    $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_USERNAME_TAKEN);
                } elseif ($existing_user['email'] == $email) {
                    $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_EMAIL_TAKEN);
                }
                return false;
            }
            $password_hash = \SecureFuncs\SecureFuncs::password_hash($password, PASSWORD_DEFAULT);

            $new_user = $this->newBuilder()
                ->insert('users')
                ->values(
                    array(
                        'username' => ':username',
                        'password' => ':password',
                        'email' => ':email',
                        'activation_code' => ':code',
                        'activation_created' => 'now()'
                    )
                )
                ->setParameter(':username', $username)
                ->setParameter(':password', $password_hash)
                ->setParameter(':email', $email)
                ->setParameter(':code', \SecureFuncs\SecureFuncs::randomString(64))
                ->execute();

            if ($new_user > 0) {
                $userid = $this->conn->lastInsertId();
                $this->sendActivationCode($userid);
                unset($_SESSION['stored_register_fields']);
                return $userid;
            }
        }
        return false;
    }


    public function changeForgotPassword($password, $repeat_password, $code)
    {
        // get user attached to code
        $get_user = $this->newBuilder()
            ->select('*')
            ->from('users')
            ->where('forgotpassword_code = :code')
            ->setParameter(':code', $code)
            ->execute();
        if ($get_user->rowcount() === 1) {

            // fetch results
            $user_data = $get_user->fetch();

            // verify entered passwords
            if (empty($password) || empty($repeat_password)) {
                $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_EMPTY_PASSWORDS);
            } elseif ($password !== $repeat_password) {
                $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_BOTH_PASSWORDS_SAME);
            } elseif (strlen($password) < 8) {
                $this->setMessage('error', ADVANCEDLOGINSCRIPT_REGISTER_SHORT_PASSWORDS);
            } else {

                // Hash the new password
                $password_hash = \SecureFuncs\SecureFuncs::password_hash($password);

                // Update the database
                $update_user = $this->newBuilder()
                    ->update('users')
                    ->set('password', ':password')
                    ->setParameter('password', $password_hash)
                    ->set('forgotpassword_code', 'NULL')
                    ->set('forgotpassword_created', 'NULL')
                    ->where('id = :id AND forgotpassword_code = :code')
                    ->setParameter('id', $user_data['id'])
                    ->setParameter('code', $code)
                    ->execute();

                if ($update_user === 1) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check for the userid and code when trying to reset a password
     * @param $code
     * @return bool|userdata
     */
    public function checkForgotPasswordCode($code)
    {
        if (!empty($code)) {
            $get_user = $this->conn->prepare('SELECT * from users where forgotpassword_code = :code');
            $get_user->bindparam(':code', $code);
            $get_user->execute();

            if ($get_user->rowcount() > 0) {
                $user_data = $get_user->fetch(\PDO::FETCH_ASSOC);
                if ($user_data['forgotpassword_code'] == $code && $user_data['forgotpassword_created'] <= date('Y-m-d H:i:s', time() + 60 * 60 * 6)) {
                    return $user_data;
                }
            }
        }
        $this->setMessage('error', ADVANCEDLOGINSCRIPT_PASSWORD_RESET_EMAIL_NOTFOUND);
        return false;
    }

    public static function ForgotpasswordLinkCreator($code)
    {
        return str_replace("{code}", $code, ADVANCEDLOGINSCRIPT_RESETPASSWORD_LINK_LOCATION);
    }

    /**
     * @param $email
     * @return bool
     * @throws Exception
     */
    public function sendForgotPasswordCode($email)
    {
        $email = strtolower(trim($email));

        $get_user = $this->newBuilder()
            ->select('*')
            ->from('users')
            ->where('LOWER(email) = :email')
            ->setParameter('email', $email)
            ->execute();

        // user was found
        if ($get_user->rowcount() === 1) {

            // fetch data
            $data = $get_user->fetch();

            // check if user has requested a email in the last 2 minutes to avoid spam
            if ($data['forgotpassword_created'] > date('Y-m-d H:i:s', strtotime('-2minutes'))) {
                $this->setMessage('error', ADVANCEDLOGINSCRIPT_PASSWORD_RESET_EMAIL_TOFAST);
                return false;
            }

            $password_token = \SecureFuncs\SecureFuncs::randomString(40);
            //Replace the {code} tag with the input forgot password code
            $link = self::ForgotpasswordLinkCreator($password_token);

            // Email template
            $title = "Password reset";
            $message = "Please click the following link to reset your password and gain access to your " . ADVANCEDLOGINSCRIPT_EMAIL_DOMAIN . " account. <br>\n";
            $message .= "<a href='" . $link . "'>" . $link . "</a><br>\n<br>\n";
            $message .= "If you did not request a password request, please ignore this email.";

            // update database with the new code and timestamp
            $update_user = $this->newBuilder()
                ->select('*')
                ->update('users')
                ->set('forgotpassword_code', ':code')
                ->setParameter('code', $password_token)
                ->set('forgotpassword_created', 'now()')
                ->where('id = :id')
                ->setParameter('id', $data['id'])
                ->execute();

            if ($update_user > 0) {

                // add user's email as target
                $targets[] = array('name' => $data['username'], 'email' => $data['email']);
                if ($this->sendMail($message, $title, $targets) === true) {

                    // succesfuly sent email
                    $this->setMessage('success', ADVANCEDLOGINSCRIPT_EMAIL_SEND_SUCCESS . $data['email']);
                    return true;
                } else {
                    // failed to send email
                    $this->setMessage('error', ADVANCEDLOGINSCRIPT_EMAIL_SEND_FAIL . $data['email']);
                }
            }
        } else {
            // email was not found
            $this->setMessage('error', ADVANCEDLOGINSCRIPT_PASSWORD_RESET_EMAIL_NOTFOUND);
        }
        return false;
    }


    /**
     * To avoid users created fake accounts and block emails, remove all accounts which have expired
     * @return mixed
     */
    public function cleanNotActivatedAccounts()
    {
        return $this->newBuilder()
            ->delete('users')
            ->where('active = 0 AND activation_created < DATE_SUB(NOW(), INTERVAL 1 DAY)')
            ->execute();
    }

    /**
     * Check the activation code for the given user id
     * @param $code
     * @return bool
     */
    public function checkActivationCode($code)
    {
        if (!empty($code)) {

            $check_code = $this->newBuilder()
                ->select('*')
                ->from('users')
                ->where('activation_code = :code')
                ->setParameter('code', $code)
                ->execute();

            if ($check_code->rowcount() > 0) {

                $user_data = $check_code->fetch();

                if ($user_data['activation_code'] == $code) {

                    $update_user = $this->newBuilder()
                        ->update('users')
                        ->set('activation_code', 'NULL')
                        ->set('active', 1)
                        ->set('activation_created', 'NULL')
                        ->where('id = :id')
                        ->setParameter('id', $user_data['id'])
                        ->execute();

                    if ($update_user === 1) {
                        $this->setMessage('success', ADVANCEDLOGINSCRIPT_USER_ACTIVATED_SUCCESS);
                        return true;
                    } else {
                        $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_ACTIVATED_FAIL);
                    }
                } else {
                    $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_ACTIVATED_INVALID);
                }
            } else {
                $this->setMessage('error', ADVANCEDLOGINSCRIPT_USER_ACTIVATED_NO_ID);
            }
        }
        return false;
    }


    /**
     * Send new activation code
     * @param $userid
     * @return bool
     * @throws Exception
     */
    public function sendActivationCode($userid)
    {
        $get_link = $this->newBuilder()
            ->select('*')
            ->from('users')
            ->where('id = :id')
            ->setParameter('id', $userid)
            ->execute();

        if ($get_link->rowcount() > 0) {
            $data = $get_link->fetch();
            //Replace the {code} and {id} tag with the input activation code and userid
            $link = str_replace("{code}", $data['activation_code'], ADVANCEDLOGINSCRIPT_ACTIVATION_LINK_LOCATION);

            $title = "Account activation";
            $message = "Please click the following link to complete your account activation for " . ADVANCEDLOGINSCRIPT_EMAIL_DOMAIN . "<br>\n";
            $message .= "<a href='" . $link . "'>" . $link . "</a><br>\n<br>\n";
            $message .= "If your account has not been activated within 24 hours we reserve the right to temporarily remove your account and registration.";

            $targets[] = array('name' => $data['username'], 'email' => $data['email']);

            if ($this->sendMail($message, $title, $targets)) {
                $this->setMessage('success', ADVANCEDLOGINSCRIPT_EMAIL_SEND_SUCCESS . $data['email']);
            } else {
                $this->setMessage('error', ADVANCEDLOGINSCRIPT_EMAIL_SEND_FAIL . $data['email']);
            }

        }
        return false;
    }


    /* ======================= QR CODE ========================== */

    /**
     * Leave param2 empty if you want to generate the qrcode yourself using the returned data
     * @param bool $returnimage
     * @return array
     * @throws \Endroid\QrCode\Exceptions\ImageFunctionUnknownException
     */
    public function createQrCode($returnimage = false)
    {
        // delete old qr codes
        $this->newBuilder()
            ->delete('qr_activation')
            ->where('ip = :ip')
            ->setParameter('ip', filter_input(INPUT_SERVER, 'REMOTE_ADDR'))
            ->execute();

        // Random code
        $new_code = \SecureFuncs\SecureFuncs::randomString(64);

        // insert qr code into the database
        $this->newBuilder()
            ->insert('qr_activation')
            ->values(
                array(
                    'ip' => ':ip',
                    'qr_code' => ':qr',
                    'expires' => ':expires'
                )
            )
            ->setParameter(':qr', $new_code)
            ->setParameter(':ip', filter_input(INPUT_SERVER, 'REMOTE_ADDR'))
            ->setParameter(':expires', date('Y-m-d H:i:s', strtotime('+30seconds')))
            ->execute();

        if ($returnimage === true && !headers_sent()) {

            header('Content-type: image/png');

            $link = ADVANCEDLOGINSCRIPT_QR_PAGE;
            $link = str_replace('{code}', $new_code, $link);

            $qr_image = new \Endroid\QrCode\QrCode();
            $qr_image
                ->setText($link)
                ->setSize(300)
                ->setPadding(20)
                ->setErrorCorrection('high')
                ->setForegroundColor(array('r' => 0, 'g' => 0, 'b' => 0, 'a' => 0))
                ->setBackgroundColor(array('r' => 255, 'g' => 255, 'b' => 255, 'a' => 0))
                ->setLabel('Valid for 30 seconds')
                ->setLabelFontSize(16)
                ->render();

        } else {
            $qr_image = false;
        }

        $_SESSION[ADVANCEDLOGINSCRIPT_QR_COOKIEKEY]['qr'] = $new_code;

        $this->destroyOldQrCodes();

        return array(
            'qr' => $new_code,
            'qr_image' => $qr_image
        );
    }

    /**
     * @param $code
     * @return bool
     */
    public function verifyQrCode($code)
    {

        $get_user = $this->newBuilder()
            ->select('*')
            ->from('qr_activation')
            ->where('qr_code = :qr AND expires > now()')
            ->setParameter('qr', $code)
            ->execute();

        if ($get_user->rowcount() === 1) {

            $update_user = $this->newBuilder()
                ->update('qr_activation')
                ->where('qr_code = :qr')
                ->set('activated', '1')
                ->set('user_id', ':id')
                ->setParameter('id', parent::$loggedIn)
                ->setParameter('qr', $code)
                ->execute();

            if ($update_user === 1) {
                return true;
            }

        }
        return false;
    }

    /**
     * @param $code
     * @return bool
     */
    public function checkQrActivated($code)
    {
        if (!empty($code)) {
            $get_user = $this->newBuilder()
                ->select('*')
                ->from('qr_activation')
                ->where('qr_code = :qr AND activated = 1 AND ip = :ip')
                ->setParameter('qr', $code)
                ->setParameter('ip', filter_input(INPUT_SERVER, 'REMOTE_ADDR'))
                ->execute();
            if ($get_user->rowcount() === 1) {
                return $get_user->fetch();
            }
        }
        return false;
    }

    public function destroyOldQrCodes()
    {
        $this->newBuilder()
            ->delete('qr_activation')
            ->where('expires < now()')
            ->execute();
    }

}
