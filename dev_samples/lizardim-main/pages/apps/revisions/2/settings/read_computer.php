<style type="text/css">
.buttonDelete {
	-moz-box-shadow:inset 0px 1px 0px 0px #ffffff;
	-webkit-box-shadow:inset 0px 1px 0px 0px #ffffff;
	box-shadow:inset 0px 1px 0px 0px #ffffff;
	background:-webkit-gradient( linear, left top, left bottom, color-stop(0.05, #fa0303), color-stop(1, #c42f59) );
	background:-moz-linear-gradient( center top, #fa0303 5%, #c42f59 100% );
	filter:progid:DXImageTransform.Microsoft.gradient(startColorstr='#fa0303', endColorstr='#c42f59');
	background-color:#fa0303;
	-moz-border-radius:6px;
	-webkit-border-radius:6px;
	border-radius:6px;
	border:1px solid #dcdcdc;
	display:inline-block;
	color:white;
	font-family:arial;
	font-size:15px;
	font-weight:bold;
	padding:6px 24px;
	text-decoration:none;
	text-shadow:0px 0px 0px #ffffff;
}.buttonDelete:hover {
	background:-webkit-gradient( linear, left top, left bottom, color-stop(0.05, #c42f59), color-stop(1, #fa0303) );
	background:-moz-linear-gradient( center top, #c42f59 5%, #fa0303 100% );
	filter:progid:DXImageTransform.Microsoft.gradient(startColorstr='#c42f59', endColorstr='#fa0303');
	background-color:#c42f59;
}.buttonDelete:active {
	position:relative;
	top:1px;
}
</style>



<?php
$sql= "SELECT name, password, `pc-user` AS username, ip FROM connectino WHERE id=".$_REQUEST['pc']; 
$results = mysql_query($sql) or die(mysql_error());
while($row = mysql_fetch_array($results))
{
	$ip	= $row['ip'];
	$name	= $row['name'];
	$password = $row['password'];
	$username = $row['username'];
}

echo '<!--';
$res = sshTester($ip,$username,$password);
echo '-->';

//1 == FUNZIONA
//-1 == QUANDO NON TROVA IL COMPUTER
//-2 == QUAND FALLISCE L'AUTENTICAZIONE

?>




<div style="display:table; width:1000px;">
	<div style="display:table-cell;text-align:center;vertical-align:middle"> 
		<?php 
		if($res==1)echo '<h2 style="background-color:green">Funziona</h2>';
		if($res==-1)echo '<h2 style="background-color:orange">Computer non trovato</h2>';
		if($res==-2)echo '<h2 style="background-color:red">Autenticazione fallita </h2>'; ?> <br>
		
		<button class="buttonDelete"onClick="deleteComputer()"> Remove Computer </button> 
	</div>
	<div style="display:table-cell;border-left-style:dashed;border-width:1px;border-color:grey;" >
		<h2>Edit Server Settings</h2>
		<?php 

		formStart('formUpdate');
		formAddItems_plus('name','Name','text', 'value="'.$name.'"');
		formAddItems_plus('username','Username','text', 'value="'.$username.'"');
		formAddItems_plus('password','Password','password', 'value="'.$password.'"');
		formEnd('Edit'); 
		
		?>
	</div>
</div>
	
	
<script> 
	function formUpdateEv()
	{
		//var req = 'password=' + document.forms['formCreate']['password'].value ;
		var req = 'name=' + document.forms['formUpdate']['name'].value + 
		'&user=' + document.forms['formUpdate']['username'].value +
		'&password=' + document.forms['formUpdate']['password'].value +
		'&id=<?php echo $_REQUEST['pc']; ?>';
		getNow('update_computer.php','updateRequested', req);
			
	}
	function updateRequested(req)
	{
		callNotify("Computer Updated");
		
		goPageBack(1);		
	}
	
	function deleteComputer()
	{	
		var req='id=<?php echo $_REQUEST["pc"]; ?>';
		
		getNow('delete_computer.php','deleteRequested', req);
				
	}
	
	function deleteRequested(res)
	{		
		callNotify("Deleted");
		goPageBack(1);		
	}
	
</script>