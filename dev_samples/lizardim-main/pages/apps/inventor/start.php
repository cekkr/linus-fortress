<!--<div class="list">
<span class="listTopTitle">Created Project</span>
<div class="listBody"> 
ciao<br>
mi<br>
chiamo<br>
</div>
</div>

<div style="float:left; padding:10px;">
<div style="color:gray; font-size:20px;">Created Project</div>
<div style="color:#444444; font-size:14px; padding:0px; padding-left:5px;">Hello World</div>
<div style="color:#444444; font-size:14px; padding:0px; padding-left:5px;">Apache Manager</div>
<div style="color:#444444; font-size:14px; padding:0px; padding-left:5px;">Note</div>

</div>
<div style="float:right">
-->

<style type="text/css">
.newProject
{
-webkit-border-radius: 5px;
-moz-border-radius: 5px;
border-radius: 5px;

padding:3px;
cursor:pointer;
}

.newProject:hover   
{
background-color: #EEEEEE
}
</style>

<div style="margin-left:auto; margin-right:auto; text-align:center; padding:0px;">
<h1>App Creator</h1>

<div style="text-align:left; position:relative;">
	<span style="color:gray; font-size:20px; position:absolute; left:2px; padding:3px;">Created Project</span>
	<span style="color:gray; font-size:20px; position:absolute; right:2px;" class="newProject" onClick="openPage('createproject', 'Create New Project')">+ New Project</span>
</div>

<table class="listTable" style="margin-top:30px;">
<tr>
<?php
$results = mysql_query('SELECT id, name, path FROM apps WHERE owner='.$_SESSION['user_id'].' ORDER BY position') or die("Connessione non riuscita: " . mysql_error());

$numb = 0;
while ($row = mysql_fetch_array($results)) {
	if($numb%4==0) echo '</tr><tr>';	
	//echo '<td onClick="openPage(\'writeapp.php&nophp=1&appath='.$row['path'].'\',\''.$row['name'].'\')"><div class="listTableNumber">'.($numb+1).'.</div> '.$row['name'].'</td>';	
	echo '<td onClick="openPage(\'revisions.php&nophp=1&idapp='.$row['id'].'&pathapp='.$row['path'].'\',\''.$row['name'].'\')"><div class="listTableNumber">'.($numb+1).'.</div> '.$row['name'].'</td>';	
	
	$numb++;		
}

if(($rest= $numb%4)!=0) for(;$rest<4; $rest++) echo '<td></td>';

if($numb==0) echo '<br>No created project, nobody love you.';
?>
</tr>

</table>
</div>