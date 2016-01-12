# advanced-login-script

[![License](https://poser.pugx.org/crecket/advanced-login-script/license)](https://packagist.org/packages/crecket/advanced-login-script)
## Content
1. Introduction
2. Features
3. Requirements
4. Examples
5. Installation
6. Todo
7. License

## Introduction
Advanced-login-script features a bunch of basic and more advanced options to manage your users.

## Features
1. Login/Registration
2. Usergroups and session control
3. SMTP mails over ssl
4. QRCode login
5. Config file to manage settings

## Requirements
1. Php version >= 5.5
2. PHPMailer 
3. crecket/secure-functions
3. doctrine/dbal
4. endroid/qrcode


## Installation
#### Composer
1. Require the repo ```composer require crecket/advanced-login-script```
2. Copy the config file from `/vendor/crecket/advanced-login-script/src/configfiles/config.php` and place it somewhere else. (If you don't do this, updating this plugin with composer will reset your config!
3. Call the class and add config location in the first parameter
```PHP
require_once '/config/config.php'; // include the config file
$login = new Crecket\AdvancedLogin\Login(); // call the class
```

##### Config setup

For both composer and manual installation you have to setup the config file. Make sure to update your secret key and to change any settings. This can be done manually by editing the config file or the setConfig function. For a example view setup_file.php in the demo folder. Once you've created a new key make sure it stays the same or all old cookies will become invalid.

For the activation link and resetpassword link {code} will get replaced with the appropriate reset code
If you want to use a clean URL simply change it to something like this:

`http://localhost.dev/forgot_password/{code}`

or a normal URL could be something like this:

`http://localhost.dev/forgot_password.php?code={code}`

##### Notifications

If you wish to disable or change a notification you can do so by editing the loginScriptTranslations.php file. 
If you wish to disable the message all together and handle the message systme yourself, simply remove the message.

```PHP
define('LOGINSCRIPT_USER_ALREADY_LOGGED_IN', ''); // disable the 'already logged in message' like this
```

##### Database setup

Run the sql file includded with the project files function. In total, 5 tables will be created
- Users
The basic userinfo is stored in here
- Usergroups
All usergroups
- Qr_activation
Qr_activation codes are stored in here, this will be empty for the most part since they are only valid for 30 seconds
- Login_attempts
Login attempts, the type will show how the user activated a session or if someone entered a invalid password
- User_auth  
Remember_me cookie values

## Examples

#### Log in a user through login form
```PHP
$loginScript->login($_POST['username'], $_POST['password'], $_POST['remember_me']);
```

#### Verify if user is logged in

```PHP
if (Crecket\AdvancedLogin\Core::$loggedIn !== false) {
    // Logged in
}
// Also, if a user is logged in. The session will be stored in $_SESSION['currentuser']
```

#### Register a new user
```PHP
$loginScript->register($username, $email, $password, $repeat_password);
```

#### Secure a form with a token
```PHP
if(isset($_POST['somedata']){
  if(\SecureFuncs\SecureFuncs::getFormToken('updatedata'.$_POST['userid'], $_POST['formtoken'])){
    // valid submission
  }else{
    // $_POST['formtoken'] has a different value than the original one that was sent with the form data
  }
}
$userid = 59348534;
$formtoken = \SecureFuncs\SecureFuncs::setToken('updatedata'.$userid);
?>

<form action="/target.php" method="post">
	<input type="hidden" name="userid" value="<?php echo $userid; ?>">
	<input type="hidden" name="formtoken" value="<?php echo $formtoken; ?>">

	<input type="text" name="somedata">
</form>
```
In this example somedata has to be updated for user '59348534'. In order to secure this, you add the id to the token generator. After that you add both the token and the id to a hidden form.

If the id is different when the post request is received, the formtoken will block it.

#### Logout the current user
```PHP
$loginScript->logout();
```

#### QR login
In order to understand this have a look at the demo files. 

If the user is logged in on a phone, they can scan the QR code. Once you open the page, the token that is added to the link will activate the session for the user on the PC. The example is still very basic so you should be careful with how you use this.

Creating a QR code is simple:
```PHP
// Create a QR code on your device
$login->createQrCode(true); // Returns a PNG image + headers

$login->createQrCode(); // Returns a array with the ID, Code and Image, you'll need to generate the QR code yourself
```
All QR codes are valid for 30 seconds

Verify a QR code
```PHP
// Verify this with a QR code reader, you'll need to be logged in to the website in order to activate the code
if ($login->verifyQrCode(@$_GET['code'])) {
    echo "Activated!";
} else {
    echo "Not Activated!";
}
```

```PHP
// checkLoggedIn() will verify the QR code, it is automatically run atleast once when you create the Login class
$login = new Crecket\AdvancedLogin\Login();

// Or run the following 
$login->checkLoggedIn();
```

## Todo
1. **Travis testing**
2. User meta data
3. Replace normal queries with querybuilder
4. Better QR example (Using ajax?)
5. Configurable default values (E.G. Default usergroup)


## License
            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.

