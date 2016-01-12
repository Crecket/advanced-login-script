<?php
session_start();

// Run composer install before trying these!
require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/src/configfiles/config.php';

$login = new Crecket\AdvancedLogin\Login();

if (Crecket\AdvancedLogin\Core::$loggedIn !== false) {
    header('Location: index.php');
}

if (!empty($_POST['username']) && \SecureFuncs\SecureFuncs::getFormToken('login', $_POST['form_token']) !== false) {
    if ($login->login($_POST['username'], $_POST['password'], @$_POST['rememberme']) === true) {
        header('Location: index.php');
    }
}
$loginAttempts = $login->checkFailedLogins();
$formToken = \SecureFuncs\SecureFuncs::setFormtoken('login');
?>
<!DOCTYPE html>
<html>
<head>
    <title>LoginScript - Login</title>
</head>
<body>
<div class="header">
    <pre>
<?php
print_r($_SESSION[ADVANCEDLOGINSCRIPT_MESSAGE_KEY]);
unset($_SESSION[ADVANCEDLOGINSCRIPT_MESSAGE_KEY]);
?>
    </pre>
</div>
<div class="body">
    <?php if ($loginAttempts > 0) {
        echo "You currently have reached " . $loginAttempts . " out of 3 attempts. If you have forgotten your password <a href='forgot_password.php'>click here</a>.";
    } ?>
    <form method="post" action="login.php">
        <input type="hidden" name="form_token" value="<?php echo $formToken; ?>">
        <table>
            <tr>
                <td>Username</td>
                <td><input type="text" name="username" required></td>
            </tr>
            <tr>
                <td>Password</td>
                <td><input type="password" name="password" required></td>
            </tr>
            <tr>
                <td>Remember me</td>
                <td><input type="checkbox" name="rememberme"></td>
            </tr>
            <tr>
                <td>
                    <button>Login</button>
                </td>
            </tr>
        </table>
    </form>
    <a href="forgot_password.php">Forgotten password?</a><br>
    <a href="register.php">Register a new account</a>
</div>
</body>
</html>
