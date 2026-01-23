<div id="cont-Main">
<?php
?>
</div>
Vabbuo per ora non è che l'editor funzioni molto, ma fin qui ci arriva almeno. ok. <br>
L'editor salva ogni 5 secondi spero che bastino. E continua a lampeggiare l"'ok saved" sotto. <br><br>
Vado a dormire. Punto.

<script>
</script>

<?php
echo '<br><br>'. getAppPath() . '<br><br>';

startStreamSSH();

// execute a command
if (!($stream = ssh2_exec($_SESSION['pc_sshs'], "ls -al" ))) {
	echo "fail: unable to execute command\n";
} else {
	// collect returning data from command
	stream_set_blocking($stream, true);
	$data = "";
	while ($buf = fread($stream,4096)) {
		$data .= $buf;
	}
	fclose($stream);
	
	echo $data;
}


?>
























