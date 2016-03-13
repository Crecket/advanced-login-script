<?php
// Move this outside off your vendor folder. It will get overwritten if you update this repo!

// Debug mode
define('ADVANCEDLOGINSCRIPT_DEBUG', true);

// Mysql settings
define('ADVANCEDLOGINSCRIPT_DB_HOST', 'localhost');
define('ADVANCEDLOGINSCRIPT_DB_NAME', 'login_script_db_advanced');
define('ADVANCEDLOGINSCRIPT_DB_USER', 'root');
define('ADVANCEDLOGINSCRIPT_DB_PASS', '1234');

// Cookie settings
define('ADVANCEDLOGINSCRIPT_COOKIE_FOLDER', '/');
define('ADVANCEDLOGINSCRIPT_COOKIE_DOMAIN', NULL);
define('ADVANCEDLOGINSCRIPT_COOKIE_SSL', NULL);
define('ADVANCEDLOGINSCRIPT_COOKIE_HTTP_ONLY', false);
define('ADVANCEDLOGINSCRIPT_COOKIE_STORE_DURATION', strtotime( '+14 days' ));
define('ADVANCEDLOGINSCRIPT_REMEMBER_ME_COOKIE', 'remember_me');

// Forgotpassword link template
define('ADVANCEDLOGINSCRIPT_RESETPASSWORD_LINK_LOCATION', 'http://advanced-login-script/demo/forgot_password.php?code={code}');
define('ADVANCEDLOGINSCRIPT_ACTIVATION_LINK_LOCATION', 'http://advanced-login-script/demo/activate.php?code={code}');

// A random key
define('ADVANCEDLOGINSCRIPT_SECRET_KEY', '5k8oIubGTOnIfTmkGGNAnWHZQxzHw2g9OTz1W3ApMHwxDbGqzVzT4BIa30yvYiyD');
// Enable JWT Tokens
define('ADVANCEDLOGINSCRIPT_ENABLE_JWT', false);

// QR code page
define('ADVANCEDLOGINSCRIPT_QR_PAGE', 'http://advanced-login-script/demo/checkQR.php?code={code}');
// QR code cookie key
define('ADVANCEDLOGINSCRIPT_QR_COOKIEKEY', 'qrcode_verification');
// The key where all messages will be stored in the session
define('ADVANCEDLOGINSCRIPT_MESSAGE_KEY', 'login_system_messages');
// Email settings
define('ADVANCEDLOGINSCRIPT_EMAIL_HOST', 'smtp.gmail.com');
// If your server has issues with ipv6 try to use:
// define('ADVANCEDLOGINSCRIPT_EMAIL_HOST', gethostbyname('smtp.gmail.com'));
define('ADVANCEDLOGINSCRIPT_EMAIL_USERNAME', 'email@mail.com');
define('ADVANCEDLOGINSCRIPT_EMAIL_PASSWORD', '1234');
define('ADVANCEDLOGINSCRIPT_EMAIL_FROM_NAME', 'your name');
define('ADVANCEDLOGINSCRIPT_EMAIL_FROM_EMAIL', 'emailthat@willbeshown.com');
define('ADVANCEDLOGINSCRIPT_EMAIL_DOMAIN', 'https://example.com');
// Send activation code, true if you want to use activation system

// Translations
define('ADVANCEDLOGINSCRIPT_USER_ALREADY_LOGGED_IN', 'You\'re already logged in!');
define('ADVANCEDLOGINSCRIPT_USER_FAILED_ATTEMPTS', 'You have to many failed login attempts in the last 15 minutes!');
define('ADVANCEDLOGINSCRIPT_USER_LOGGEDOUT', 'You have been logged out');
define('ADVANCEDLOGINSCRIPT_INVALID_LOGIN', 'Invalid login attempt.');
define('ADVANCEDLOGINSCRIPT_USER_INACTIVE', 'You account is no longer active. You will now get logged out.');
define('ADVANCEDLOGINSCRIPT_USER_BANNED', 'You account has been banned. You will now get logged out.');
define('ADVANCEDLOGINSCRIPT_USER_LOGGED_IN', 'You have logged in as: ');
define('ADVANCEDLOGINSCRIPT_REGISTER_EMPTY_NAME', 'Please enter a valid username');
define('ADVANCEDLOGINSCRIPT_REGISTER_INVALID_NAME', 'The username you entered contains ilegal characters');
define('ADVANCEDLOGINSCRIPT_REGISTER_EMPTY_PASSWORDS', 'Please fill in a password in both input fields');
define('ADVANCEDLOGINSCRIPT_REGISTER_SHORT_PASSWORDS', 'Please enter a password off at atleast 8 characters.');
define('ADVANCEDLOGINSCRIPT_REGISTER_BOTH_PASSWORDS_SAME', 'The first password is different from the second. Please enter the same password twice.');
define('ADVANCEDLOGINSCRIPT_REGISTER_NAME_MINIMUM_LENGTH', 'Please enter a username with a 2 to 30 characters');
define('ADVANCEDLOGINSCRIPT_REGISTER_USERNAME_TAKEN', 'This username is already taken. Already have a account? <a href="login.php">Click here</a> to log in.');
define('ADVANCEDLOGINSCRIPT_REGISTER_EMAIL_TAKEN', 'This email is already taken. Already have a account? <a href="login.php">Click here</a> to log in.');
define('ADVANCEDLOGINSCRIPT_REGISER_SUCCESS', 'Your account has been created and a activation message has been sent.');
define('ADVANCEDLOGINSCRIPT_REGISER_SUCCESS_NOMAIL', 'Your account has been created, you can now log in.');
define('ADVANCEDLOGINSCRIPT_USER_ACTIVATED_SUCCESS', 'User has been activated succesfully');
define('ADVANCEDLOGINSCRIPT_USER_ACTIVATED_FAIL', 'User has not been succesfully activated');
define('ADVANCEDLOGINSCRIPT_USER_PASSWORD_UPDATE', 'Password has succesfully been updated');
define('ADVANCEDLOGINSCRIPT_USER_PASSWORD_UPDATE_FAIL', 'Password has not been updated');
define('ADVANCEDLOGINSCRIPT_USER_ACTIVATED_INVALID', 'This code is invalid or no longer active');
define('ADVANCEDLOGINSCRIPT_USER_ACTIVATED_NO_ID', 'No in-active user found for this ID!');
define('ADVANCEDLOGINSCRIPT_EMAIL_SEND_FAIL', 'A email was not succesfully sent to ');
define('ADVANCEDLOGINSCRIPT_EMAIL_SEND_SUCCESS', 'A email was succesfully sent to ');
define('ADVANCEDLOGINSCRIPT_PASSWORD_RESET_EMAIL_NOTFOUND', 'We couldn\'t find a user for the email you gave us.');
define('ADVANCEDLOGINSCRIPT_PASSWORD_RESET_EMAIL_TOFAST', 'Please wait before requesting a new password request email.');
