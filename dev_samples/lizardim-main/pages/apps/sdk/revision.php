<?php
function getRevisionNumber()
{
	$getrand = rand(0,99).rand(0,99).rand(0,99).rand(0,99).rand(0,99);
	echo $getrand . "<br>";
	
	$sql = 'SELECT * FROM `revisions` WHERE rev='.$getrand;
	$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
	
	$ex = 0;
	while ($row = mysql_fetch_array($results)) {
		$ex=1;
	}
	
	if($ex == 0) return $getrand;
	else return getRevisionNumber();
}

function createRevision($from, $app, $ver, $desc)
{
	$getRev = getRevisionNumber();
	
	$revfolder = $_SESSION['absoluteAppsPath'] . 'revisions/' . $getRev . '/';
	if (!file_exists($revfolder)) mkdir($revfolder);
	
	$revfolder = $revfolder . $app . '/';
	if (!file_exists($revfolder)) mkdir($revfolder);
	
	copyfolder($from,  $revfolder);

	$sql = "SELECT id FROM `apps` WHERE path='".$app."'";
	$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
	
	while ($row = mysql_fetch_array($results)) {
		$idapp = $row['id'];
	}
	
	$sql = "INSERT INTO `lizard`.`revisions` (`id`, `rev`, `app`, `ver`, `desc`) 
	VALUES (NULL, '".$getRev."', '".$idapp."', '".$ver."', '".$desc."');";
	
	$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());

}
?>