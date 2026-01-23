<?php 
include("settings.php");
include("pages/menu.php");
//if($_SESSION['login'] != 1) header('location: login.php');

//Select PC if it's not selected
if(!isset($_REQUEST['pc']))
{
	$results = mysql_query('SELECT * FROM connectino WHERE user='.$_SESSION['user_id'] . ' LIMIT 1') or die("Connessione non riuscita: " . mysql_error());
	while ($row = mysql_fetch_array($results)) {				
		header('location: /?pc='.$row['id']);
	}
}
?>
<!DOCTYPE html>
<html>
  <head>
  	<meta charset="utf-8">
  	
	<link rel="stylesheet" type="text/css" href="style/style.css" />
	
	<link href='http://fonts.googleapis.com/css?family=Roboto:400,900italic,900,700italic,700,500italic,500,400italic,300italic,300,100italic,100' rel='stylesheet' type='text/css'>
	
	<!-- PHP / JAVASCRIPT / CSS / HTML Code Editor -->
	<script src="http://rawgithub.com/ajaxorg/ace-builds/master/src-noconflict/ace.js" type="text/javascript" charset="utf-8"></script>
	<!--<link rel="stylesheet" href="js/editor/lib/codemirror.css">
    <script src="js/editor/lib/codemirror.js"></script>
    <script src="js/editor/addon/edit/matchbrackets.js"></script>
    <script src="js/editor/mode/htmlmixed/htmlmixed.js"></script>
    <script src="js/editor/mode/xml/xml.js"></script>
    <script src="js/editor/mode/javascript/javascript.js"></script>
    <script src="js/editor/mode/css/css.js"></script>
    <script src="js/editor/mode/clike/clike.js"></script>
    <script src="js/editor/mode/php.js"></script>
    <style type="text/css">.CodeMirror {border-top: 1px solid black; border-bottom: 1px solid black;}</style>
    <link rel="stylesheet" href="js/editor/doc/docs.css">-->
		
	<!-- jQuery -->
	<link href="css/ui-lightness/jquery-ui-1.10.1.custom.css" rel="stylesheet">
	<script src="js/jquery-1.9.1.js"></script>
	<script src="js/jquery-ui-1.10.1.custom.js"></script>
	
	<!-- Javascript -->
	<script>		
		var openedMoreInfo = -1;
		function openMoreInfoApp(app)
		{
			if(openedMoreInfo == -1)
			{
				$('#menuAppPreBlack'+ app).animate({
					opacity: 1,
					}, 300, function() {
					$('#menuAppPreBlack'+ app).animate({
					      height: '71px'
					    }, 100, "linear");
				});
				var riga = Math.floor(app/4);
				$(function () {
					$('#appMoreInfo'+ riga).show();
					$('#appMoreInfo'+ riga).animate({
						opacity: 1
						}, { duration: 300, queue: false });
					
					$('#appMoreInfo'+ riga).animate({
						height:'260px'
						}, { duration: 400, queue: false });
				});
				//Ridefinisci colore contenitore app
				$('#menuAppPre'+app).animate({borderBottomColor:"white"},200);
				
				openedMoreInfo = app;
				
				//Caricamento schermata more-info con ajax
				$('#inAppMoreInfo'+riga).show();
				$('#inAppMoreInfo'+riga).css("opacity", 0);
				$.get('pages/apps/get_more-info.php?p='+arrayApps[app] + '&ssh=<?php echo $_REQUEST['pc']; ?>', function(data) {
					$('#inAppMoreInfo'+riga).html(data);
					
					$('#inAppMoreInfo'+ riga).animate({
						opacity:1
						}, 200);
				});
			}
			else
			{				
				var aaaaaahhhThisApp = app;
				if(openedMoreInfo != app) setTimeout(function() {
				  openMoreInfoApp(aaaaaahhhThisApp);
				}, 500);
				
				app = openedMoreInfo;
				
				$('#menuAppPreBlack'+ app).animate({
					height: '69px'
					}, 100, "linear", function() {
					$('#menuAppPreBlack'+ app).animate({
					      opacity: 0
					    }, 300);
				});
					
				var riga = Math.floor(app/4);
				$('#appMoreInfo'+ riga).animate({
					height:'0px'
					}, { duration: 400, queue: false }, function() {
						
				});
				
				setTimeout(function() {
				    $('#appMoreInfo'+ riga).animate({
					opacity: 0
					}, { duration: 300, queue: false }, function() {
					
				    });
				}, 100);
				
				
				setTimeout(function() {
					$('#inAppMoreInfo'+ riga).html("");
				}, 400);
				
				//Ridefinisci colore contenitore app
				setTimeout(function() {
				  $('#menuAppPre'+app).animate({borderBottomColor:"silver"},200);
				}, 200);
				openedMoreInfo = -1;
			}
		}
		
		var inPhaseOfChangePage = 0;
		var pageNow = 0;
		var erContentPos;
		var erContentWidth;
		var pages = new Array();
		pages[pageNow + '.cont'] = 0;
		pages[pageNow + '.0.url'] = '';
		
		function openPage(url, name)
		{
			inPhaseOfChangePage = 1;
			var contNow = pages[pageNow + '.cont'];	
			url = pages[pageNow + '.appPath'] + '/' + url;
			//Create or manage new div
			contNow++;
			pages[pageNow + '.cont'] = contNow;
			
			var contName = 'content-'+ pageNow+'-'+contNow;
			var progressIn = '<div style="margin:10px; text-align:center;">Loading...<br><img style="margin-left:auto; margin-right:auto;" src="/style/image/ajax-loader.gif"></div>';
			var newContent = $("#pagesCont").html() + '<div id="'+contName+'" class="content" style="opacity:0; position:absolute; right:0px; top:'+erContentPos.top+'px;width:'+erContentWidth+'px;">'+progressIn+'</div>';
			if(pages['ex.'+contName]!=1 && !$('#'+contName)[0])
			{
				$("#pagesCont").html(newContent);
				pages['ex.'+contName] = 1;
			}
			else
			{
				$('#'+contName).html(progressIn);
			}
			
			//Make animation
			$('#'+contName).show();
			$('#'+contName).animate({
			    opacity: "1",
			    left:erContentPos.left+"px"
			    }, 500, function() {
			    inPhaseOfChangePage = 0;
			});
			
			$('#content-'+ pageNow+'-'+(contNow-1)).animate({
			    opacity: "0",
			    left:"0px"
			    }, 500, function() {
			    $('#content-'+ pageNow+'-'+(contNow-1)).hide();
			});
			
			if($('html, body').scrollTop>300)
			{
			  $('html, body').animate({
			      scrollTop: 0
			  }, 500);
			}
			
			//Carica i contenuti
			$.get('pages/apps/get.php?u='+url+ '&ssh=<?php echo $_REQUEST['pc']; ?>', function(data) {
				$('#content-'+ pageNow+'-'+contNow).html(data);
			});
			
			//Aggiungi contenitore a menù
			var exMenu = $('#whereNav-'+pageNow+'-'+(contNow-1));
			var widfhcasd = (exMenu.position().left+exMenu.width()) + 5;
			
			contName = 'whereNav-'+pageNow+'-'+contNow;
			var newContent = $("#nav-"+pageNow).html() + '<span id="'+contName+'" onClick="closePage('+contNow+')" style="position:absolute; opacity:0; left:0px; top:'+exMenu.position().top+'px"> &raquo <span id="'+contName+'-text" class="whereNav">'+name+'</span></div>';
			if(pages['ex.'+contName]!=1 && !$('#'+contName)[0]) 
			{
				$("#nav-"+pageNow).html(newContent);
				pages['ex.'+contName] = 1;
			}
			else
			{
				$('#'+contName).css('opacity','0');
				$('#'+contName).css('left','0px');
				$('#'+contName).css('top',exMenu.position()+'px');
				
				$('#'+contName+"-text").html("lol");
				$('#'+contName+"-text").html(name);
			}
			
			$('#'+contName).show();
			$('#'+contName).animate({
			    opacity: "1",
			    left:(widfhcasd) + "px"
			    }, 500, function() {
			    // Animation complete.
			});
			//Aggiorna titolo
			document.title = "Lizard - " + name;
	
			//Gestisci contenitore
			pages[pageNow + '.' + contNow + '.url'] = url;
			pages[pageNow + '.' + contNow + '.name'] = name;
			pagesToReload[url.replace('/','').replace('.','')] = 0;
		}
		
		function openApp(url, name)
		{
			pages[pageNow + '.appPath'] = url;
			openPage('start', name);
		}
		
		function closePage(page)
		{
			closePage(page, 0);
		}
		
		function closePage(page, reload)
		{	
			var contNow = pages[pageNow + '.cont'];
				
			if(page < contNow)
			{
				inPhaseOfChangePage = 1;
			
				for(i=contNow; i>page; i--)
				{
				  $('#whereNav-'+pageNow+'-'+i).animate({
				    opacity: "0",
				    left:"1024px"
				    }, { duration: 500, queue: false }, function() {
				    // Animation complete.
				  });
				}
				
				$('#content-'+ pageNow+'-'+contNow).animate({
				    opacity: "0",
				    left:($(window).width()-1024)+"px"
				    }, 500, function() {
				    $('#content-'+ pageNow+'-'+contNow).hide();
					inPhaseOfChangePage = 0;
				});
				
				//Ricarica il contenuto della pagina
				var url = pages[pageNow + '.' + page + '.url'];
				if(reload==1 || pagesToReload[url.replace('/','').replace('.','')] == 1) 
				{
					$.get('pages/apps/get.php?u='+pages[pageNow + '.' + page + '.url'], function(data) {
						$('#content-'+ pageNow+'-'+page).html(data);
					});
				}
				
				$('#content-'+ pageNow+'-'+page).show();
				$('#content-'+ pageNow+'-'+page).animate({
				    opacity: "1",
				    left:$("#absoluteTitle").position().left+"px"
				    }, 500, function() {
				    // Animation complete.
				});
				
				pages[pageNow + '.cont'] = page;
				//Aggiorna titolo
				var contNowChk = contNow-1;
				if(contNowChk>0) document.title = "Lizard - " + pages[pageNow + '.' + contNowChk + '.name'];
				else document.title = "Lizard";
			}
		}
		function goPageBack()
		{
			goPageBack(0);
		}
		function goPageBack(reload)
		{
			closePage(pages[pageNow + '.cont']-1, reload);
		}
		
		//Controlla l'attuale posizione left della div del momento
		function controlPagePosition() {
		  if(inPhaseOfChangePage==0)
		  {	
			var pos = $("#absoluteTitle").position();
            
            var pagNow = '#content-'+ pageNow+'-'+pages[pageNow + '.cont'];
			$(pagNow).css("left",pos.left+"px");
            $('#nav-'+pageNow).css("left",pos.left+"px");
		  }
		}
		setInterval("controlPagePosition()",50);
		
		//General function
		function loadInDiv(url, div)
		{
		  $.get(url, function(data) {
		    $(div).html(data);
		    
		     $(div).animate({
			opacity: 1
		      }, 300, function() {
		      });
		  });
		}
		
		function getNow(url, fun, request)
		{
			$.get('pages/apps/get.php?nophp=1&u=' + pages[pageNow + '.appPath'] + '/' + url + '&' + request, function(data) {
				var stocazzo = data.replace(/(\r\n|\n|\r)/gm,"");
				eval(fun+'("'+stocazzo+'")');
			});
		}
		
		function selectedComputer()
		{
			window.location.href = "/?pc=" + $('#selectComputer').val();
		}
		
		var pagesToReload = new Array();
		function addToReloadPages(page)
		{
			pagesToReload[page.replace('/','').replace('.','')] = 1;
		}
		
		function reloadThisPage()
		{
			$.get('pages/apps/get.php?u='+pages[pageNow + '.' + pages[pageNow + '.cont'] + '.url'], function(data) {
				$('#content-'+ pageNow+'-'+pages[pageNow + '.cont']).html(data);
			});
		}
	</script>
	<script type="text/javascript" src="js/sdk.js"></script>
	
    <title>Lizard</title>
  </head>
  <body>
	<div style="position: absolute; left: 50%;">
		<div id="notifyDiv" class="notifyStyle">
		</div>
	</div>
  
    <div class="body">
		<div id="absoluteTitle" class="title">
			<img src="style/image/logo.png"> 
			
			<div style="float:right; font-size:16px; text-align:right;">
				<div>
					<span style="font-size:11px;"><?php echo $_SESSION['user_email']; ?></span> <a class="boxSmallBut boxSmallButRed" href="login/logout.php">Logout</a>
				</div>
				
				<select id="selectComputer" onChange="selectedComputer()">
					<?php
						$results = mysql_query('SELECT * FROM connectino WHERE user='.$_SESSION['user_id']) or die("Connessione non riuscita: " . mysql_error());
						while ($row = mysql_fetch_array($results)) {
							$selected = "";
							if($_REQUEST['pc']==$row['id']) $selected = "selected";
						
							echo '<option value="'. $row['id'].'" '.$selected.' class="selectComputerOption">'. $row['name'] .' ('. $row['ip'].'@'.$row['pc-user'].')</option>';
						}
					?>
					
					<option value="add">Add Computer</option>
				</select> 
			</div>
		</div>
	
		<div class="nav" id="nav-0">
			<span id="whereNav-0-0" onClick="closePage(0)"><span class="whereNav">Home</span></span> 
		</div>
		<div id="pagesCont" style="padding:0px">
		
			<div class="content" id="content-0-0">
				<?php echo writeMenu(); ?>
			</div>
		</div>
	</div>	
  </body>
</html>
<!-- Ed infine... -->
<script> 
	//Trasforma in absolute il container fondatore
	function initiErContentAbsolute()
	{
		var el = $('#content-0-0');
		erContentPos = el.offset();
		erContentWidth = el.width();
		
		el.css({ position: "absolute",
		marginLeft: 0, marginTop: 0,
		top: erContentPos.top, left: erContentPos.left });
		
		el.width(erContentWidth);
		
		//Gestione barra di navigazione
		var nav = $('#nav-0');
		var navHeight = nav.height();
		var navWidth = nav.width();
		
		pos = nav.offset();
		
		nav.css({ position: "absolute",
		marginLeft: 0, marginTop: 0,
		top: pos.top, left: pos.left });
		
		nav.height(navHeight);
		nav.width(navWidth);
		
		//Gestione whereNav
		var el = $('#whereNav-0-0');
		pos = el.position();
		
		el.css({ position: "absolute",
		marginLeft: 0, marginTop: 0,
		top: pos.top, left: pos.left });
		
		el.css({"z-index":"1"});
	}
	setTimeout("initiErContentAbsolute()",500);
</script>
