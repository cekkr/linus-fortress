<?php
$sql = "INSERT INTO `connectino` (`user`, `pc-user`, `ip`, `password`, `name`)  
VALUES('". $_SESSION['user_id'] ."', '".inj($_REQUEST['user'])."', '".inj($_REQUEST['ip']).
	"', '".inj($_REQUEST['password'])."', '".inj($_REQUEST['name'])."')";

mysql_query($sql) or die ("Connessione non riuscita: " . mysql_error());
?>