<style type="text/css">
.fileList
{
/*
background-color:#F0F0F0;

border-bottom-style:solid;
border-bottom-color:black;
border-bottom-size:1px;

-webkit-border-radius: 5px;
-moz-border-radius: 5px;
border-radius: 5px;
*/

font-size:12px;

cursor:pointer;

border:0px solid gray;
-webkit-border-radius: 5px;
-moz-border-radius: 5px;
border-radius: 5px
}

.fileList:hover
{
background-color:#FEFEFE;
}

.fileListTitle
{
-webkit-border-radius: 5px;
-moz-border-radius: 5px;
border-radius: 5px;

font-size:14px;
color:white;
text-align:center;

background-color:rgba(0,0,0,0.7);
padding:5px;

margin-left: 20px;
margin-bottom:5px;

cursor:pointer;
}

.fileListTitle:hover
{
background-color:rgba(0,0,0,1);
}

.fileListAll
{
background-color:#F5F5F5;

-webkit-border-radius: 5px;
-moz-border-radius: 5px;
border-radius: 5px;
}
</style>

<?php 
if ($handle = opendir('../../'. $_REQUEST['req'])) { 
    echo '<div class="fileListTitle" onClick="openFileManager()">File Manager</div>'; 

   /* Questa è la maniera corretta di eseguire un loop all'interno di una
directory. */ 
?>
<div class="fileListAll" id="fileListAll">
<?php
   while (false !== ($file = readdir($handle))) {  
		if ((strpos($file,'.php') !== false) || (strpos($file,'.js') !== false) || (strpos($file,'.css') !== false) || (strpos($file,'.html') !== false) || (strpos($file,'.ini') !== false) || (strpos($file,'.txt') !== false))
		{		
			$fileId = str_replace(".", "", $file);
			echo '<div class="fileList" id="fileListed'.$fileId.'" onClick="reloadIFrame(\''.$file.'\'); drugAddict(\''.$fileId.'\');">'.$file. '</div>'; 
		}
   } 

   closedir($handle);  
} 
?>  
</div>

<script>
var oldSelectedFile = "";
function drugAddict(url)
{	
	if(oldSelectedFile!="")
	{
		$(oldSelectedFile).animate({
			borderWidth: "0px"
		}, 100, function() {
		// Animation complete.
		});
	}

	oldSelectedFile = "#fileListed"+url;
	$(oldSelectedFile).animate({
		borderWidth: "3px"
	}, 100, function() {
	});
}

setTimeout("drugAddict('startphp');", 1000);

</script>