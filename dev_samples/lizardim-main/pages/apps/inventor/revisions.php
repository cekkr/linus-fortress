<?php
$idapp = inj($_REQUEST['idapp']);

$results = mysql_query('SELECT rev FROM store WHERE app='.$idapp) or die("Connessione non riuscita: " . mysql_error());

$numb = 0;
while ($row = mysql_fetch_array($results)) {
	$numb++;
}

?>
<style type="text/css">
.tdiv{
text-align:center;
display:table-cell;
}

.clickIn
{
	cursor:pointer;
}
.clickInRow:hover
{
background-color: rgba(0, 0, 0, 0.1);
}
</style>

<script>
function submitRev(rev, app)
{
	var thisUrl = '/pages/apps/get.php?u=../../<?php echo getAppPath(); ?>rev_submit.php&nophp=1&ssh=<?php echo $_REQUEST["ssh"]; ?>&r=sub&rev='+rev+'&app='+app;

	$.get(thisUrl, function(data){
		reloadThisPage();
		callNotify("Revision duplicated!");
	});
}

function duplicateRev(rev, app)
{
	var thisUrl = '/pages/apps/get.php?u=../../<?php echo getAppPath(); ?>rev_submit.php&nophp=1&ssh=<?php echo $_REQUEST["ssh"]; ?>&r=dup&rev='+rev+'&app='+app;

	$.get(thisUrl, function(data){
		reloadThisPage();
		callNotify("Revision duplicated!");
	});
}

function deleteRev(rev, app)
{
	var thisUrl = '/pages/apps/get.php?u=../../<?php echo getAppPath(); ?>rev_submit.php&nophp=1&ssh=<?php echo $_REQUEST["ssh"]; ?>&r=del&rev='+rev+'&app='+app;

	$.get(thisUrl, function(data){
		reloadThisPage();
		callNotify("Revision deleted!");
	});
}
</script>

<div style="display:table; margin-left:auto; margin-right:auto;">
	<div style="display:table-row;  padding:0px;">
		<div style="display:table-cell; text-align:right;">Submitted:</div>
		<div style="display:table-cell;">
			<?php
				if($numb==0) echo '<span style="color:red;">None</span>';	
			?>
		</div>
	</div>
	<?php if($numb!=0) { ?>
	<div style="display:table-row; padding:0px;">
		<div style="display:table-cell; text-align:right;">In Submit:</div>
		<div style="display:table-cell;">
			<?php
				if($numb==0) echo '<span style="color:red;">None</span>';	
			?>
		</div>
	</div>
	<?php } ?>
</div>

<div style="display:table; margin-left:auto; margin-right:auto;">
	<div style="display:table-row; padding:0px;">
		<div class="tdiv">ID Rev</div>
		<div class="tdiv">Version</div>
		<div class="tdiv">Description</div>
		<div class="tdiv">Men&ugrave</div>
		<div class="tdiv">Submit</div>
		<div class="tdiv">Duplicate</div>
		<div class="tdiv">Delete</div>
	</div>
	<?php
	$sql = 'SELECT * FROM `revisions` WHERE app='.$idapp;
	$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
	
	while ($row = mysql_fetch_array($results)) {
		$onclick = "onClick=\"openPage('writeapp.php&nophp=1&appath=revisions/". $row['rev'] .'/'. $_REQUEST['pathapp'] ."','".$_REQUEST['pathapp'] . ' - ' . $row['ver']."')\"";
		
		?>
		<div style="display:table-row; padding:0px;" class="clickInRow">
			<div class="tdiv clickIn" <?php echo $onclick; ?>><?php echo $row['rev'];?></div>
			<div class="tdiv clickIn" <?php echo $onclick; ?>><?php echo $row['ver'];?></div>
			<div class="tdiv clickIn" <?php echo $onclick; ?>><?php echo $row['desc'];?></div>
			<div class="tdiv"><input type="checkbox" name="inMenu" value="yes"/></div>
			<div class="tdiv"><button style="padding:2px;" onClick="submitRev('<?php echo $row['rev'];?>', '<?php echo $row['app'];?>')">Submit</button></div>
			<div class="tdiv"><button style="padding:2px;" onClick="duplicateRev('<?php echo $row['rev'];?>', '<?php echo $row['app'];?>')">Duplicate</button></div>
			<div class="tdiv"><button style="padding:2px;" onClick="deleteRev('<?php echo $row['rev'];?>', '<?php echo $row['app'];?>')">Delete</button></div>
		</div>
		<?php
	}
	?>
</div>
