<?php
$command = $_REQUEST['command'];

startStreamSSH();

if (!($stream = ssh2_exec($_SESSION['pc_sshs'], $command ))) {
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