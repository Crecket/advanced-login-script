<?php
session_start();

require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/src/configfiles/config.php';

$login = new Crecket\AdvancedLogin\Login();
$login->checkLoggedIn();

if ($login->checkLoggedIn()) {
    header('Location: index.php');
}

if (!empty($_GET['code'])) {
    $login->checkActivationCode($_GET['code']);
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>advanced-login-script | Activate</title>
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
    <a href="index.php">Return home</a><br>
    <a href="login.php">Or click here to log in</a><br>
</div>
</body>
</html>