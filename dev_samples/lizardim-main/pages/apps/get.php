<?php
$url = $_REQUEST['u'];

$prefix = 'pages/apps/';
if (substr($url, 0, strlen($prefix)) == $prefix) {
    $url = substr($url, strlen($prefix));
} 

if(!isset($_REQUEST['nophp'])) $url .= ".php";

include('sdk.php');
include($url);
?>
