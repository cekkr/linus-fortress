<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8" />
        
        <title>Lizard - Manage your server via SSH</title>
        
        <!-- Our CSS stylesheet file -->
        <link rel="stylesheet" href="assets/css/styles.css" />
        
        <!--[if lt IE 9]>
          <script src="http://html5shiv.googlecode.com/svn/trunk/html5.js"></script>
        <![endif]-->
		
		<style type="text/css">
			.title
			{
				margin-left:auto;
				margin-right:auto;
				
				font-size:20px;
				
				-webkit-border-radius: 10px;
				-moz-border-radius: 10px;
				border-radius: 10px;
					
				background: #cdeb8e; /* Old browsers */
				background: -moz-linear-gradient(top,  #cdeb8e 0%, #a5c956 100%); /* FF3.6+ */
				background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#cdeb8e), color-stop(100%,#a5c956)); /* Chrome,Safari4+ */
				background: -webkit-linear-gradient(top,  #cdeb8e 0%,#a5c956 100%); /* Chrome10+,Safari5.1+ */
				background: -o-linear-gradient(top,  #cdeb8e 0%,#a5c956 100%); /* Opera 11.10+ */
				background: -ms-linear-gradient(top,  #cdeb8e 0%,#a5c956 100%); /* IE10+ */
				background: linear-gradient(to bottom,  #cdeb8e 0%,#a5c956 100%); /* W3C */
				filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#cdeb8e', endColorstr='#a5c956',GradientType=0 ); /* IE6-9 */
				
				width:400px;
				text-align:center;
				padding:5px;
				margin-top: 15px;
				
				text-shadow: -1px 0 black, 0 1px black, 1px 0 black, 0 -1px black;
			}
			
			.button
			{
				-webkit-border-radius: 5px;
				-moz-border-radius: 5px;
				border-radius: 5px;
				
				background: #a4b357; /* Old browsers */
				background: -moz-linear-gradient(top,  #a4b357 0%, #75890c 100%); /* FF3.6+ */
				background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,#a4b357), color-stop(100%,#75890c)); /* Chrome,Safari4+ */
				background: -webkit-linear-gradient(top,  #a4b357 0%,#75890c 100%); /* Chrome10+,Safari5.1+ */
				background: -o-linear-gradient(top,  #a4b357 0%,#75890c 100%); /* Opera 11.10+ */
				background: -ms-linear-gradient(top,  #a4b357 0%,#75890c 100%); /* IE10+ */
				background: linear-gradient(to bottom,  #a4b357 0%,#75890c 100%); /* W3C */
				filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#a4b357', endColorstr='#75890c',GradientType=0 ); /* IE6-9 */

				color:white;

				padding:5px;
				padding-left:10px; padding-right:10px;
				font-weight:bold;
				margin:5px;
				
				border-style:solid;
				border-width:1px;
				border-color:black;
			}
			
			td
			{
				vertical-align:middle;
				padding:3px;
				font-size:20px;
			}
			
			input
			{
				padding:3px;
			}
		</style>
    </head>
    
    <body>

        <!--<header>
            <h1></h1>
        </header>
        -->
		
		<div class="title">
			<!--<div style="display:table; margin-left:auto; margin-right:auto;">
				<div style="display:table-cell; vertical-align:middle; padding-right:30px;"><img src="/style/image/logo-big.png" height="100"></div>
				<div style="display:table-cell; vertical-align:middle; font-size:70px; padding-right:100px; padding-bottom:10px; letter-spacing:5px; ">Lizard.im</div>
			</div>-->
			
			<img src="/style/image/logo-big.png" height="150">
			<div style="font-size:35px; letter-spacing:5px;">Lizard<span style="color:silver;">.im</span></div>
		</div>
		
        <nav id="filter"></nav>
		<div style="background-color:rgba(255,0,0,0.6); text-align:center; color:white; font-size:16px; margin-bottom:10px; margin-top:0px;"><?php if(isset($_REQUEST['info'])) echo $_REQUEST['info']; ?></div>
        <section id="container">
        	<ul id="stage">
            	<li data-tags="Login" style="margin-left:200px;">
					<form method="post" action="action.php?login=1"> <div style="text-align:center">
							<input placeholder="Email" type="text" name="email" class="textboxStyle">
							<input placeholder="Password" type="password" name="password" class="textboxStyle">
							<input type="submit" value="Login" class="button">
						</div>
						</table>
					</form>
				</li>
				<form>
                <li data-tags="Registrazione" style="margin-left:200px; display:none;" id="liRegistrazione">
					<form>
					<div style="text-align:center">
						<table style="margin-left:auto; margin-right:auto;">
							<tr><td align="right"><div class="textInput">Email:</div></td><td><input type="text" name="email"class="textboxStyle"></td></tr>
							<tr><td align="right"><div class="textInput">Password:</div></td><td><input type="password" name="password" class="textboxStyle"></td></tr>
							<tr><td align="right"><div class="textInput">Repeat Password:</div></td><td><input type="password" name="repeatpass" class="textboxStyle"></td></tr>
							<tr><td align="right"><div class="textInput">Accept contract:</div></td><td style="text-aling:left; padding-top:8px;"><input type="checkbox" name="condizione" class="textboxStyle" style="padding:0px; margin:0px;"></td></tr>
							<tr><td align="right"></td><td><input type="submit" value="Registrati" class="button"></td></tr>
						</table>
						</div>
					</form>
				</li>        
            </ul>
        </section>
		
		 
        <footer>
	        <h3>Lizard Copyright 2013.Tutti i diritti riservati.</h3>
                   </footer>
        
        <script src="http://ajax.googleapis.com/ajax/libs/jquery/1.6.1/jquery.min.js"></script>
        <script src="assets/js/jquery.quicksand.js"></script>
        <script src="assets/js/script.js"></script>
    
		<script type="text/javascript">	
			function showReg()
			{
				$('#liRegistrazione').show();
			}
			setTimeout("setTimeout('showReg()',500)", 500);
		</script>
    </body>
</html>
