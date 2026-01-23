<?php
$sqlUpdate = "UPDATE connectino
SET name='".inj($_REQUEST['name'])."', `pc-user`='".inj($_REQUEST['user'])."',password='".inj($_REQUEST['password'])."'
WHERE id='".inj($_REQUEST['id'])."'";

mysql_query($sqlUpdate) or die ("Connessione non riuscita: " . mysql_error());
?>