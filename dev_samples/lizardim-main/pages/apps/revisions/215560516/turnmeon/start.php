<style type="text/css">
	.menuAppPreTurn{
		display:table; 
		
		-webkit-border-radius: 4px;
		-moz-border-radius: 4px;
		border-radius: 4px;
		
		border:1px solid silver;
		
		width:220px;
		
		
		margin:5px;
		
		
		background-color:#EEEEEE;
	}
		
	.menuAppIconTurn{
		display:table-cell;
		vertical-align:top;
		border-collapse: collapse;
		width:70px;	
		padding:0px;
		padding-left:2px;
		padding-right:5px;
		
	}
		
	.menuAppTitleBlackTurn{
		display:inline;
		weight:bold;
		padding:0px;	
		color:black;
		
	}
	.boxPlayStopEcc
	{
		display:inline;
		font-size:10px;
		padding:2px;
		padding-left:7px;
		padding-right:7px;
			
		border-style:solid;
		border-width:1px;
			
		-webkit-border-radius: 5px;
		-moz-border-radius: 5px;
		border-radius: 5px;
		
		margin-top:5px;
		margin:1px;
		cursor:pointer;
		
		opacity:0.3;
	}
	
	.startTurn
	{
		background-color:rgba(0,255,0,0.5);
		border-color:rgb(0,255,0);
	}
	.startTurn:hover
	{
		background-color:rgba(0,255,0,0.8);
	}	
	
	.restartTurn
	{
		background-color:rgba(255,137,0,0.5);
		border-color:rgb(255,137,0);
	}
	.restartTurn:hover
	{
		background-color:rgba(255,137,0,0.8);
	}
		
	.stopTurn
	{
		background-color:rgba(255,0,0,0.5);
		border-color:rgb(255,0,0);
	}
	.stopTurn:hover
	{
		background-color:rgba(255,0,0,0.8);
	}
	
	.pointTurn
	{
		height:3px;
		width:3px;
		
		max-width:3px;
		max-height:3px;
		min-width:3px;
		min-height:3px;
		
		-webkit-border-radius: 10px;
		-moz-border-radius: 10px;
		border-radius: 10px;
		border-style:solid;
		border-width:1px;
		
		margin-top:5px;
		
	}
	
	.pointTurnRed
	{
		background: #f85032; /* Old browsers */
		background: -moz-linear-gradient(top,  #f85032 0%, #f16f5c 50%, #f6290c 51%, #f02f17 71%, #e73827 100%); /* FF3.6+ */
		background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#f85032), color-stop(50%,#f16f5c), color-stop(51%,#f6290c), color-stop(71%,#f02f17), color-stop(100%,#e73827)); /* Chrome,Safari4+ */
		background: -webkit-linear-gradient(top,  #f85032 0%,#f16f5c 50%,#f6290c 51%,#f02f17 71%,#e73827 100%); /* Chrome10+,Safari5.1+ */
		background: -o-linear-gradient(top,  #f85032 0%,#f16f5c 50%,#f6290c 51%,#f02f17 71%,#e73827 100%); /* Opera 11.10+ */
		background: -ms-linear-gradient(top,  #f85032 0%,#f16f5c 50%,#f6290c 51%,#f02f17 71%,#e73827 100%); /* IE10+ */
		background: linear-gradient(to bottom,  #f85032 0%,#f16f5c 50%,#f6290c 51%,#f02f17 71%,#e73827 100%); /* W3C */
		filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#f85032', endColorstr='#e73827',GradientType=0 ); /* IE6-9 */
	
	}
	
	.pointTurnGreen
	{
		background: #9dd53a; /* Old browsers */
		background: -moz-linear-gradient(top,  #9dd53a 0%, #a1d54f 50%, #80c217 51%, #7cbc0a 100%); /* FF3.6+ */
		background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#9dd53a), color-stop(50%,#a1d54f), color-stop(51%,#80c217), color-stop(100%,#7cbc0a)); /* Chrome,Safari4+ */
		background: -webkit-linear-gradient(top,  #9dd53a 0%,#a1d54f 50%,#80c217 51%,#7cbc0a 100%); /* Chrome10+,Safari5.1+ */
		background: -o-linear-gradient(top,  #9dd53a 0%,#a1d54f 50%,#80c217 51%,#7cbc0a 100%); /* Opera 11.10+ */
		background: -ms-linear-gradient(top,  #9dd53a 0%,#a1d54f 50%,#80c217 51%,#7cbc0a 100%); /* IE10+ */
		background: linear-gradient(to bottom,  #9dd53a 0%,#a1d54f 50%,#80c217 51%,#7cbc0a 100%); /* W3C */
		filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#9dd53a', endColorstr='#7cbc0a',GradientType=0 ); /* IE6-9 */
	}
	
	.pointTurnWhite
	{
		background: #e2e2e2; /* Old browsers */
		background: -moz-linear-gradient(top,  #e2e2e2 0%, #dbdbdb 50%, #d1d1d1 51%, #fefefe 100%); /* FF3.6+ */
		background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#e2e2e2), color-stop(50%,#dbdbdb), color-stop(51%,#d1d1d1), color-stop(100%,#fefefe)); /* Chrome,Safari4+ */
		background: -webkit-linear-gradient(top,  #e2e2e2 0%,#dbdbdb 50%,#d1d1d1 51%,#fefefe 100%); /* Chrome10+,Safari5.1+ */
		background: -o-linear-gradient(top,  #e2e2e2 0%,#dbdbdb 50%,#d1d1d1 51%,#fefefe 100%); /* Opera 11.10+ */
		background: -ms-linear-gradient(top,  #e2e2e2 0%,#dbdbdb 50%,#d1d1d1 51%,#fefefe 100%); /* IE10+ */
		background: linear-gradient(to bottom,  #e2e2e2 0%,#dbdbdb 50%,#d1d1d1 51%,#fefefe 100%); /* W3C */
		filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#e2e2e2', endColorstr='#fefefe',GradientType=0 ); /* IE6-9 */
	}
	
</style>

<script>
	function readState(idser, filename)
	{
		var thisUrl = '/pages/apps/get.php?u=../../<?php echo getAppPath(); ?>read_state.php&nophp=1&ssh=<?php echo $_REQUEST["ssh"]; ?>&soft=' + filename;

		$.get(thisUrl, function(data) {
			if(data=="true")//acceso
			{
				$("#start"+idser).animate({opacity: 0.25},500, function(){});
				$("#restart"+idser).animate({opacity: 1},500, function(){});
				$("#stop"+idser).animate({opacity: 1},500, function(){});		
				
				$("#pointTurnWhite"+idser).hide();
				$("#pointTurnRed"+idser).hide();
				$("#pointTurnGreen"+idser).show();
			}
			if(data=="false")//spento
			{
				$("#start"+idser).animate({opacity: 1},500, function(){});
				$("#restart"+idser).animate({opacity: 0.25},500, function(){});
				$("#stop"+idser).animate({opacity: 0.25},500, function(){});
				
				$("#pointTurnWhite"+idser).hide();
				$("#pointTurnRed"+idser).show();
				$("#pointTurnGreen"+idser).hide();
			}
		});
	}
	
	function sendAppCommand(app,funz)
	{
		alert(app+" "+funz);
	}
		
</script>

<?php
function writeMenuApp($app,$nomeIcona, $filename, $start, $restart, $stop)
{
	$nomeIcona=getAppPath()."icon/".$nomeIcona;
	?>
<div style="display:table-cell;">
			<div class="menuAppPreTurn">
				<div class="menuAppIconTurn">
					<img width="64" height="64" src="<?php echo $nomeIcona?>">
				</div>
				<div class="menuAppTitleBlackTurn"> 
					<div style="display:table; padding:0px;"><div style="display:table-row; padding:0px;">
						<div style="display:table-cell; padding:0px;">
							<div id="pointTurnRed<?php echo $app; ?>" class="pointTurn pointTurnRed" style="display:none;"></div>
							<div id="pointTurnGreen<?php echo $app; ?>" class="pointTurn pointTurnGreen" style="display:none;"></div>
							<div id="pointTurnWhite<?php echo $app; ?>" class="pointTurn pointTurnWhite"></div></div>
						<div style="display:table-cell; padding:0px;"><div style="display:inline;vertical-align:text-top;"><?php echo $app ?></div></div>
					</div></div>
					
					<div id="start<?php echo $app; ?>" class="boxPlayStopEcc startTurn" onClick="sendAppCommand('<?php echo $app; ?>','<?php echo $start; ?>')">Start</div>
					<div id="restart<?php echo $app; ?>" class="boxPlayStopEcc restartTurn" onClick="sendAppCommand('<?php echo $app; ?>','<?php echo $restart; ?>')">Restart</div>
					<div id="stop<?php echo $app; ?>" class="boxPlayStopEcc stopTurn" onClick="sendAppCommand('<?php echo $app; ?>','<?php echo $stop; ?>')">Stop</div>
				</div>
			</div>
		</div>
	<?php
		
		echo '<script>readState("'.$app.'","'.$filename.'")</script>';
}

?>

<div style="display:table;margin-left:auto;margin-right:auto;">
	<div style="display:table-row">	<!--prima fila di icone-->		
		<?php 
		writeMenuApp("MySQL","mysql.png", "mysqld", "start", "restart","stop");
		writeMenuApp("Apache","apache.png", "apache2", "start", "restart","stop");
		writeMenuApp("OpenSSH","ssh.gif", "openssh", "start", "restart","stop");
		writeMenuApp("FTPd","ftpd.png", "ftpd", "start", "restart","stop");
		?>
	</div>
	<div style="display:table-row">	<!--seconda fila di icone-->		
		<?php 
		writeMenuApp("lighttpd","lighttpd.png", "lighttpd", "start", "restart","stop");	
		?>
	</div>
	
	
</div>

