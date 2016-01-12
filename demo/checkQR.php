<?php
session_start();

// Run composer install before trying these!
require_once $_SERVER['DOCUMENT_ROOT'] . '/vendor/autoload.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/src/configfiles/config.php';

$login = new Crecket\AdvancedLogin\Login();

if ($login->verifyQrCode(@$_GET['code'])) {
    echo "Activated!";
} else {
    echo "Not Activated!";
}




