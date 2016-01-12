<?php
session_start();
session_destroy();
session_start();

// Run composer install before trying these!
require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/src/configfiles/config.php';

$login = new Crecket\AdvancedLogin\Login();

?>
<!DOCTYPE html>
<html>
<head>
    <title>LoginScript - Remember Me Test</title>
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
        <p>If you see this it means that you've been logged in after your session was destroyed using a cookie.</p>
    <?php else: ?>
        <p>If you see this it means that you've NOT logged in.</p>
    <?php endif; ?>

    <br>
    <a href="index.php">Home</a>
</div>
</body>
</html>