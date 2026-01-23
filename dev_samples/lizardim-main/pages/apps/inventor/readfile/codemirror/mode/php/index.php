<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>CodeMirror: PHP mode</title>
    <link rel="stylesheet" href="../../lib/codemirror.css">
    <script src="../../lib/codemirror.js"></script>
    <script src="../../addon/edit/matchbrackets.js"></script>
    <script src="../htmlmixed/htmlmixed.js"></script>
    <script src="../xml/xml.js"></script>
    <script src="../javascript/javascript.js"></script>
    <script src="../css/css.js"></script>
    <script src="../clike/clike.js"></script>
    <script src="php.js"></script>
    <style type="text/css">.CodeMirror {border-top: 1px solid gray; border-bottom: 1px solid gray; height:100%}</style>
    <link rel="stylesheet" href="../../doc/docs.css">
    
    <!-- jQuery -->
	<link href="../../../../../../../css/ui-lightness/jquery-ui-1.10.1.custom.css" rel="stylesheet">
	<script src="../../../../../../../js/jquery-1.9.1.js"></script>
	<script src="../../../../../../../js/jquery-ui-1.10.1.custom.js"></script>
  </head>
  <body>

<style type="text/css">
#code
{
width:1000px;
height:1000px;
}

body
{
padding:0px;
margin:0px;

height:100%;
}

html
{
height:100%;
}

.okSaved
{
display:none;
opacity:0;

background-color:rgba(0,0,0,0.8);
color:white;
font-size:12px;
padding:5px;

-webkit-border-radius: 10px;
-moz-border-radius: 10px;
border-radius: 10px;

position:fixed;
bottom:5px;
left:45%;

z-index:1000;
}

.save
{
background-color:rgba(0,0,0,0.8);
color:white;
font-size:12px;
padding:5px;

cursor:pointer;

position:absolute;
top:-15px:
left:45%;

-webkit-border-bottom-right-radius: 5px;
-webkit-border-bottom-left-radius: 5px;
-moz-border-radius-bottomright: 5px;
-moz-border-radius-bottomleft: 5px;
border-bottom-right-radius: 5px;
border-bottom-left-radius: 5px;

z-index:1000;
}
</style>

<form id="formCode"><textarea id="code" name="code">
<?php
readfile("../../../../../".$_REQUEST['file']);
?>
</textarea></form>

    <script>
      var editor = CodeMirror.fromTextArea(document.getElementById("code"), {
        lineNumbers: true,
        matchBrackets: true,
        mode: "application/x-httpd-php",
        indentUnit: 4,
        indentWithTabs: true,
        enterMode: "keep",
        tabMode: "shift"
      });
      
      
      function resizeEditor()
      {
      	var divHeight = window.innerHeight-2;

      	document.getElementById('formCode').style.height = divHeight+'px';
      }
      setInterval("resizeEditor()",200);
      
      var lastText = editor.getValue();
      function autoSave(showEverNot)
      {
      	var textNow = editor.getValue();
      	if(lastText != textNow)
      	{
      		$.post("/pages/apps/inventor/readfile/writefile.php?file=<?php echo $_REQUEST['file']; ?>",
 			{
    			'text': textNow
  			},
  			function(data,status){
				showOkSaved();
  			});
  			
  			lastText = textNow;
  		}
		else if(showEverNot==1) showOkSaved();
      }
      setInterval("autoSave(0)",30000);
      
	  function showOkSaved()
	  {
		$('#okSaved').show();
		$('#okSaved').animate({
			opacity: 1,
		}, 500, function() {
		 setTimeout("closeOkSaved()", 1500);
		});
	  }
	  
      function closeOkSaved()
      {
        $('#okSaved').animate({
    		opacity: 0,
  		}, 2000, function() {
   			 $('#okSaved').hide();
 		});
      }
	  
    </script>
    
	<div class="save" id="save" style="opacity:0px;" onClick="autoSave(1)">Save Now</div>
    <div class="okSaved" id="okSaved">Ok, Saved!</div>
	
	<script>
		$("div#save").mouseover(function(){
			$('#save').animate({
    		top: '0px'
  		}, 100, function() {
 		});
		}).mouseout(function(){
			$('#save').animate({
    		top: '-15px'
  		}, 100, function() {
 		});
		});
		
		$(document).ready(function() {
			$('#save').animate({
				top: '-15px',
				left: '45%',
				opacity: '1'
			}, 1, function() {
			});
		});
	</script>
  </body>
</html>
