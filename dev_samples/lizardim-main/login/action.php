<?php
session_start();
include('../data.php');

if($_REQUEST['login']==1)
{
	$results = mysql_query("SELECT id FROM user WHERE email='".inj($_POST['email'])."' AND password='".inj($_POST['password'])."'") or die("Connessione non riuscita: " . mysql_error());
	while ($row = mysql_fetch_array($results)) {
		$_SESSION['isLogged'] = 1;
		$_SESSION['user_id'] = $row['id'];
		$_SESSION['user_email'] = $_POST['email'];
		
		$results = mysql_query('SELECT id FROM connectino WHERE user='.$_SESSION['user_id'] . ' LIMIT 1') or die("Connessione non riuscita: " . mysql_error());
		while ($row = mysql_fetch_array($results)) {
			$pcId = $row['id'];
		}
		
		header('location: ../?pc='. $pcId);
	}
	
	if($_SESSION['isLogged']!=1) header('location: index.php?info=Email or password are incorrect!');
}
?>