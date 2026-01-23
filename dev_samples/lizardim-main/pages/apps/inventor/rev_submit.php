<?php
if($_REQUEST['r']=="dup")
{
	$sql = "SELECT ver FROM `revisions` WHERE app='".$_REQUEST['app']."'";
	$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
	while ($row = mysql_fetch_array($results)) {
		$ver = $row['ver'];
	}
	$ver += 0.1;
		
	$sql = "SELECT path FROM `apps` WHERE id='".$_REQUEST['app']."'";
	$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
	while ($row = mysql_fetch_array($results)) {
		$path = $row['path'];
	}
	
	$revfolder = $_SESSION['absoluteAppsPath'] . 'revisions/' . $_REQUEST['rev'] . '/' . $path . '/';
	echo $revfolder;
	
	createRevision($revfolder, $path, $ver, '');
}

if($_REQUEST['r']=="del")
{	
	$sql = "SELECT ver FROM `revisions` WHERE app='".$_REQUEST['app']."'";
	$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
	
	$num=0;
	while ($row = mysql_fetch_array($results)) {
		$num++;
	}
	
	if($num>1)
	{
		$sql = "DELETE FROM `revisions` WHERE rev='".$_REQUEST['rev']."'";
		$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
	}
	
	/*
	$revfolder = $_SESSION['absoluteAppsPath'] . 'revisions/' . $_REQUEST['rev'] ;
	deleteDir($revfolder);
	*/
}

if($_REQUEST['r']=="sub")
{
	$pid = pcntl_fork();
	if ($pid == -1) {
	     die('could not fork');
	} else if ($pid) {
	     // we are the parent
	     //pcntl_wait($status); //Protect against Zombie children
	} else { //Children
	     	$revfolder = $_SESSION['absoluteAppsPath'] . 'revisions/' . $_REQUEST['rev'] . '/' . $_REQUEST['app'];
		$appfolder = $_SESSION['absoluteAppsPath'] . $_REQUEST['app'] . '/';
		
		if (!file_exists($appfolder)) mkdir($appfolder);
		
		deleteDir($revfolder);
		copyfolder($revfolder,  $appfolder);
	}
}
?>