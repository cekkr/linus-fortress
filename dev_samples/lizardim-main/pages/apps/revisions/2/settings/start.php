<?php
$items = menuAddItem("Computers","Add and manage your computer","computer");
$items .= menuAddItem("Account","Manage your account","account");
menuGenerate("Settings",$items);
?>