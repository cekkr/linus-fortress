<?php
$path = inj($_REQUEST['path']);

$sql = "INSERT INTO `apps` (`id`, `path`, `name`, `desc`, `position`, `owner`) 
VALUES (NULL, '".$path."', '".inj($_REQUEST['name'])."', '".inj($_REQUEST['descr'])."', '0', '".$_SESSION['user_id']."');";
$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());

$src = realpath(dirname(__FILE__)) . "/../custom/";
$dest = realpath(dirname(__FILE__)) . "/../" . $path."/";

copyfolder($src, $dest);

createRevision($src, $path, '0.1', inj($_REQUEST['descr']));
?>