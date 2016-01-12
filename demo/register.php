<?php
session_start();

// Run composer install before trying these!
require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/src/configfiles/config.php';

$login = new Crecket\AdvancedLogin\Login();

if (Crecket\AdvancedLogin\Core::$loggedIn !== false) { // check if use is logged in
    header('Location: index.php');
}

if (!empty($_POST['username']) && \SecureFuncs\SecureFuncs::getFormToken('register', $_POST['form_token']) !== false) {
    if ($login->register($_POST['username'], $_POST['email'], $_POST['password'], $_POST['repeat_password'])) {
        header('Location: index.php');
    }
}
$formToken = \SecureFuncs\SecureFuncs::setFormtoken('register');

?>
<!DOCTYPE html>
<html>
<head>
    <title>LoginScript - Register</title>
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
    <form method="post" action="register.php">
        <input type="hidden" name="form_token" value="<?php echo $formToken; ?>">
        <table>
            <tr>
                <td>Username</td>
                <td><input type="text" name="username" required></td>
            </tr>
            <tr>
                <td>Email</td>
                <td><input type="email" name="email" required><br></td>
            </tr>
            <tr>
                <td>Password</td>
                <td><input type="password" name="password" required></td>
            </tr>
            <tr>
                <td>Repeat password</td>
                <td><input type="password" name="repeat_password" required></td>
            </tr>
            <tr>
                <td>
                    <button>Register</button>
                </td>
            </tr>
        </table>
    </form>
    <a href="index.php">Return home</a>
</div>
</body>
</html>