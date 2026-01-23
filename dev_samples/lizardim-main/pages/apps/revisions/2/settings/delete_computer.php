<?php

$sql = "DELETE FROM connectino WHERE id='".inj($_REQUEST['id'])."'";

mysql_query($sql) or die ("Connessione non riuscita: " . mysql_error());

?>

