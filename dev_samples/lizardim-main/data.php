<?php
/* OLD STYLE WITH SqLite
$path = "data";
$db = new SQLite3($path);*/

include("_mysql2mysqli.php");

// Create connection
$dbl=mysql_connect("localhost","root","");
mysql_select_db("lizardim");

//Anti inj
function inj($input){
    $pulito=strip_tags(addslashes(trim($input)));
    $pulito=str_replace("'","\'",$pulito);
    $pulito=str_replace('"','\"',$pulito);
    $pulito=str_replace(';','\;',$pulito);
    $pulito=str_replace('--','\--',$pulito);
    $pulito=str_replace('+','\+',$pulito);
    $pulito=str_replace('(','\(',$pulito);
    $pulito=str_replace(')','\)',$pulito);
    $pulito=str_replace('=','\=',$pulito);
    $pulito=str_replace('>','\>',$pulito);
    $pulito=str_replace('<','\<',$pulito);
    
   
        
    
    return $pulito;
}
?>
