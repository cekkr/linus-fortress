<?php
$appInDev = true;
?>

<style type="text/css">
#inventorLeftBar
{
width:200px;
height:80%;

top:10%;
left:0px;

position:fixed;

-webkit-border-top-right-radius: 10px;
-webkit-border-bottom-right-radius: 10px;
-moz-border-radius-topright: 10px;
-moz-border-radius-bottomright: 10px;
border-top-right-radius: 10px;
border-bottom-right-radius: 10px;

border:1px solid silver;

background-color:white;
z-index:1000;
}

#inventorRightBar
{
width:200px;
height:80%;

top:10%;
right:0px;

position:fixed;

-webkit-border-top-left-radius: 10px;
-webkit-border-bottom-left-radius: 10px;
-moz-border-radius-topleft: 10px;
-moz-border-radius-bottomleft: 10px;
border-top-left-radius: 10px;
border-bottom-left-radius: 10px;

border:1px solid silver;

background-color:white;
z-index:1000;
}

.frameEditor
{
width:1000px;

margin-left:auto; margin-right:auto;
border-style:none;
}

.accord
{
font-size:25px;
cursor:pointer;
padding:2px;
padding-left:3px;
padding-right:3px;
}

.completeFileManager
{
position:fixed;

width:1000px;
height:800px;

top: 50%;
left: 50%;
margin-top: -250px;
margin-left: -500px;

-webkit-border-radius: 10px;
-moz-border-radius: 10px;
border-radius: 10px;

z-index:1501;

display:none;
opacity:0;
}

.frameFileManager
{
width:1000px;
height:420px;

margin-left:auto; margin-right:auto;
border-style:none;
}

.blackRetro
{
background-color:rgba(0,0,0,0.8);

position:fixed;
width:100%;
height:100%;
top:0px;
left:0px;

z-index:1500;

margin:0px;

display:none;
opacity:0;
}

#helpMoreInfo
{
width:0px;
height:70%;

position:fixed;
left:211px;
top:15%;

z-index:1001;

border:1px solid silver;
border-left-style:none;

padding:0px;
margin:0px;
background-color:white;

display:none;

-webkit-border-top-right-radius: 5px;
-webkit-border-bottom-right-radius: 5px;
-moz-border-radius-topright: 5px;
-moz-border-radius-bottomright: 5px;
border-top-right-radius: 5px;
border-bottom-right-radius: 5px;
}

.settingsTitle
{
-webkit-border-radius: 5px;
-moz-border-radius: 5px;
border-radius: 5px;

font-size:14px;
color:white;
text-align:center;

background-color:rgba(128,0,0,0.7);
padding:5px;

margin-top:5px;
margin-right: 20px;
margin-bottom:5px;

cursor:pointer;
}

.settingsTitle:hover
{
background-color:rgba(128,0,0,1);
}

</style>

<script>


//alert('<?php echo $_REQUEST["appath"]; ?>');
</script>

<div id="inventorLeftBar">
	<div style="padding:0px;"><div id="accorcLeft" onClick="openCloseBar('Left')" class="accord" style="float:right;">&laquo;</div></div>
	
	<div class="settingsTitle" onClick="openHelpMoreInfo('')">Settings</div>
	<br>
	<span onClick="openHelpMoreInfo('')">Informazioni utili</span>
</div>
<div id="inventorRightBar">
	<div style="padding:0px;"><div id="accorcRight" onClick="openCloseBar('Right')" class="accord" style="float:left;">&raquo;</div></div>
	
	<div id="fileTree">
	</div>
</div>

<div id="fileInDeveloping">
	<iframe src="pages/apps/inventor/readfile/codemirror/mode/php/index.php?file=<?php echo $_REQUEST["appath"]; ?>/start.php" class="frameEditor" id="iframeFileInDeveloper" border="0">
	  <p>Your browser does not support iframes.</p>
	</iframe>
</div>

<script>
    function ohCoglioneQuantoESpessoLEditor()
    {
    	var theHeight = ($(window).height() - $('#fileInDeveloping').offset().top -30);
    	
    	$('#iframeFileInDeveloper').height(theHeight);
    	
    	setTimeout("ohCoglioneQuantoESpessoLEditor()",200);
    }
	$(document).ready(function() {
		ohCoglioneQuantoESpessoLEditor();
	});
    
    var lastFileListLoad = '';
    function loadFileList(name)
    {
		$.get('pages/apps/inventor/readfile/filelist.php?req=' + name, function(data) {
 			 $('#fileTree').html(data);
		});    
		
		lastFileListLoad = name;
    }
    loadFileList('<?php echo $_REQUEST["appath"]; ?>');
    
	//iFrame code
	var scrollPages = new Array();
	var iframeNowUrl = '';
	var deviframe = $('#iframeFileInDeveloper');
    function reloadIFrame(url)
    {
		//scrollPages[iframeNowUrl] = $deviframe.scrollTop();
		//iframeNowUrl = url.replace(".", "-").replace("/", "-");
		
 	    if (deviframe.length) {
      	  deviframe.attr('src','pages/apps/inventor/readfile/codemirror/mode/php/index.php?file=<?php echo $_REQUEST["appath"]; ?>/' + url);   
   		}		
    }	
	$('#iframeFileInDeveloper').load(function(){
		//deviframe.scrollTop(scrollPages[iframeNowUrl]);
	})
	
	
	var bars = new Array();
	bars['Left'] = 1;
	bars['Right'] = 1;
	function openCloseBar(bar)
	{
		if(bars[bar]==1)
		{
			if(bar=="Left")
			{
				$('#inventor'+bar+'Bar').animate({
					left:'-180'
				}, 500, function() {
				// Animation complete.
				});
				
				$('#accorc'+bar).html('&raquo;');
			}
			else
			{
				$('#inventor'+bar+'Bar').animate({
					right:'-180'
				}, 500, function() {
				// Animation complete.
				});
				
				$('#accorc'+bar).html('&laquo;');
			}

			bars[bar]=0;
		}
		else
		{
			if(bar=="Left")
			{
				$('#inventor'+bar+'Bar').animate({
					left:'0'
				}, 500, function() {
				// Animation complete.
				});
				
				$('#accorc'+bar).html('&laquo;');
			}
			else
			{
				$('#inventor'+bar+'Bar').animate({
					right:'0'
				}, 500, function() {
				// Animation complete.
				});
				
				$('#accorc'+bar).html('&raquo;');
			}
			bars[bar]=1;
		}
	}
	
	if(v$(window).width()<1420) openCloseBar("Left");
	
	
	function openFileManager()
	{
		//Ricarica frame
		var $iframe = $('#iframeFileManager');
 	    if ($iframe.length) {
      	  $iframe.attr('src','/elfinder/elfinder.php?path=<?php echo $_REQUEST["appath"]; ?>');   
   		}
   		
   		//Visaulizza frame
		$('#blackRetro').show();
		$('#completeFileManager').show();
		
		$('#blackRetro').animate({
			opacity:'1'
		}, 300, function() {
			// Animation complete.
		});
		
		$('#completeFileManager').animate({
			opacity:'1'
		}, 300, function() {
			// Animation complete.
		});
	}
	
	function closeFileManager()
	{
		$('#blackRetro').animate({
			opacity:'0'
		}, 300, function() {
			$('#blackRetro').hide();
		});
		
		$('#completeFileManager').animate({
			opacity:'0'
		}, 300, function() {
			$('#completeFileManager').hide();
		});
		
		loadFileList(lastFileListLoad);
	}
	
	//Gestione HelpMoreInfo
	function openHelpMoreInfo(info)
	{
		$('#helpMoreInfo').show();
		
		$('#helpMoreInfo').animate({
			width: '800px'
		}, 500, function() {
		// Animation complete.
		});
		
	}
	
	function closeHelpMoreInfo()
	{
		$('#helpMoreInfo').animate({
			width: '0px'
		}, 300, function() {
			$('#helpMoreInfo').hide();
		});
		
	}
</script>

<div id="completeFileManager" class="completeFileManager">
	<iframe src="/elfinder/elfinder.php?path=<?php echo $_REQUEST["appath"]; ?>" class="frameFileManager" id="iframeFileManager" border="0">
 	 <p>Your browser does not support iframes.</p>
	</iframe>
</div>
<div id="blackRetro" class="blackRetro" onClick="closeFileManager()"></div>

<div id="helpMoreInfo">
<div onClick="closeHelpMoreInfo()">close</div>
</div>