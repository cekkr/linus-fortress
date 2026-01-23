<?php 
$soft = $_REQUEST['soft'];

startStreamSSH();

$thereIsATrue = 'false';
if (!($stream = ssh2_exec($_SESSION['pc_sshs'], "ps aux" ))) {
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
	
	while(strpos($string,'  ') !== false)
	{
		$string = str_replace(array("  "), " ", $string); 
	}
	
	//echo $string;
	
	$piecesLine = explode("\n", $string);
	
	for ($i = 0; $i < count($piecesLine); $i++) {
    	$pieceComp = explode(" ", $piecesLine[$i]);

		$cmd = "";
		for($j = 10; $j < count($pieceComp); $j++)
		{
			$cmd .= $pieceComp[$j] . " ";
		}
		
		
		if(strpos($cmd, $soft) !== false) $thereIsATrue = 'true';			
	}
}

echo $thereIsATrue;


?>