<?php
session_start();

require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/src/configfiles/config.php';

$login = new Crecket\AdvancedLogin\Login();

?>
<!DOCTYPE html>
<html>
<head>
    <title>LoginScript - Home</title>
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
    <?php if (Crecket\AdvancedLogin\Core::$loggedIn !== false): ?>
        You're currently logged in as <?php echo $_SESSION['currentuser']['username']; ?>.<br>
        <a href="logout.php">Click here to log out</a><br>
        <a href="remember_me.php">Test the remember_me function</a>
    <?php else: ?>
        You're currently not logged in.<br>
        <a href="login.php">Click here to log in</a><br>
        <a href="register.php">Click here to register a account</a>
    <?php endif; ?>

</div>
</body>
</html>
