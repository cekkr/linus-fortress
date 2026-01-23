<?php 
$myFile = "../../".$_REQUEST['file'];
$fh = fopen($myFile, 'w') or die("can't open file");
$stringData = $_POST['text'];
fwrite($fh, $stringData);
fclose($fh);

//Se è il file info
if (strpos($_REQUEST['file'],'/info.php') !== false)
{
	include("../../../../settings.php");
	include($myFile);
	
	$path = explode("/", $_REQUEST['file']);
	$path = $path[0];

	if(!isset($app_name)) $app_name = "";
	if(!isset($app_desc)) $app_desc = "";
	
	$sql = "UPDATE `apps` SET `name` = '".$app_name."',
		`desc` = '".$app_desc."' WHERE `path` ='".$path."'";
	mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
}
?>