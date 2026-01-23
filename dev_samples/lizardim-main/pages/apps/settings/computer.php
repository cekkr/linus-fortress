<?php gotReload(); ?>

<h2>Computers</h2>
<link rel="stylesheet" type="text/css" href="/pages/apps/settings/style.css">
<div style="text-align:center">
	<button onClick="openPage('add_computer','Add Computer');" style="margin-left:auto; margin-right:auto;" >
		Add Computer
	</button>  
</div>

<div>
	<?php
	$sql= "SELECT id, name, ip, 'pc-user' FROM connectino WHERE user=".$_SESSION['user_id']; 
	$results = mysql_query($sql) or die(mysql_error());?>
	<div  class="table" style="display:table; margin-left: auto;
		margin-right: auto;  border-collapse:collapse;">
		<?php 
			while($row = mysql_fetch_array($results))
			{
				echo '<div class="change" onClick="openPage(\'read_computer.php&nophp=1&pc='.$row['id'].'\', \''.$row['name'].'\')" style="display:table-row;">';
				echo '<div  style="display:table-cell">' .$row['name']. '</div>';
				echo '<div style="display:table-cell">(' . $row['ip'] . "@" . $row['pc-user'] . ')</div>';
				echo '</div>';
			}
		?>		
	</div>				
</div>