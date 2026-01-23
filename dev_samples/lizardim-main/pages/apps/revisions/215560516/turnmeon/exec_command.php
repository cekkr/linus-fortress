<?php 
$soft = $_REQUEST['soft'];
$command = $_REQUEST['command'];

startStreamSSH();

$thereIsATrue = 'false';
if (!($stream = ssh2_exec($_SESSION['pc_sshs'], $soft ." ". $command))) {
	echo "fail: unable to execute command\n";
} else {
	// collect returning data from command
	stream_set_blocking($stream, true);
	$data = "";
	while ($buf = fread($stream,4096)) {
		$data .= $buf;
	}
	fclose($stream);
	
	$string = str_replace(array("\r"), "\n", $data); 
	
	echo $string;
}




?>