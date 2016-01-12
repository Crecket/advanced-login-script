<?php
session_start();

// Run composer install before trying these!
require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/src/configfiles/config.php';


$login = new Crecket\AdvancedLogin\Login();
$login->logout();
?>

<!DOCTYPE html>
<html>
<head>
    <title>LoginScript - Logout</title>
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
    <a href="index.php">Return home</a>
</div>
</body>
</html>