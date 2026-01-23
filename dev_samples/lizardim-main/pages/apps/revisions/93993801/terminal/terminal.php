<html style="margin:0px; padding:0px;">

<head>
    <meta charset="utf-8" />
    <title>JSON-RPC Demo for JQuery Terminal Emulator</title>
    <meta name="author" content="Jakub Jankiewicz - jcubic@onet.pl"/>
    <meta name="Description" content="Demonstration for JQuery Terminal Emulator using call automaticly JSON-RPC service (in php) with authentication."/>
    <link rel="sitemap" type="application/xml" title="Sitemap" href=""/>
    <link rel="shortcut icon" href="favicon.ico"/>
	<script src="<?php echo getAppPathFromLinkUrl(); ?>js/jquery-1.7.1.min.js"></script>
    <script src="<?php echo getAppPathFromLinkUrl(); ?>js/jquery.mousewheel-min.js"></script>
    <script src="<?php echo getAppPathFromLinkUrl(); ?>js/jquery.terminal-min.js"></script>
    <link href="<?php echo getAppPathFromLinkUrl(); ?>css/jquery.terminal.css" rel="stylesheet"/>
  </head>
	<body style="margin:0px; padding:0px;">

<script>
	function makeHigh()
	{
		$('#terminal').height($(window).height()-20); 
	}
	
	setInterval("makeHigh();",100);
	
jQuery(document).ready(function($) {
    var id = 1;
    $('#terminal').terminal(function(command, term) {		
		$.get("<?php echo getUrlWithGet('send_command.php') ?>&command="+command, function(data) {
			term.echo(data);
		});
		
		/*if (command == 'help') {
            term.echo("available commands are mysql, js, test");
		} else if (command == 'test'){
            term.push(function(command, term) {
                if (command == 'help') {
                    term.echo('if you type ping it will display pong');
                } else if (command == 'ping') {
                    term.echo('pong');
                } else {
                    term.echo('unknown command ' + command);
                }
            }, {
                prompt: 'test> ',
                name: 'test'});
        } else if (command == "js") {
            term.push(function(command, term) {
                var result = window.eval(command);
                if (result != undefined) {
                    term.echo(String(result));
                }
            }, {
                name: 'js',
                prompt: 'js> '});
        } else if (command == 'mysql') {
            term.push(function(command, term) {
                term.pause();
                $.jrpc("mysql-rpc-demo.php",
                       id++,
                       "query",
                       [command],
                       function(data) {
                           term.resume();
                           if (data.error) {
                               term.error(data.error.message);
                           } else {
                               if (typeof data.result == 'boolean') {
                                   term.echo(data.result ? 'success' : 'fail');
                               } else {
                                   var len = data.result.length;
                                   for(var i=0;i<len; ++i) {
                                       term.echo(data.result[i].join(' | '));
                                   }
                               }
                           }
                       },
                       function(xhr, status, error) {
                           term.error('[AJAX] ' + status +
                                      ' - Server reponse is: \n' +
                                      xhr.responseText);
                           term.resume();
                       });
            }, {
                greetings: "This is example of using mysql from terminal\n\
you are allowed to execute: select, insert, update and delete from/to table:\n\
    table test(integer_value integer, varchar_value varchar(255))",
                prompt: "mysql> "});
        } else {
            term.echo("unknow command " + command);
        }
		*/}, {
        greetings: "Welcome in your terminal",
			height: 200,
			prompt: 'ssh> ',
        onBlur: function() {
            // prevent loosing focus
            return false;
        }
    });
});

</script>

	<div id="terminal" style="overflow:auto; height:100%; width:985px;"></div>	
</body>
</html>
