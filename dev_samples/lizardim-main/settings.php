<?php
session_start();

if(!isset($_SESSION['isLogged']) || $_SESSION['isLogged']!=1) header('location: login/');

$_SESSION['user_computer'] = 0;
$appInDev = false;

include("data.php");
?>
