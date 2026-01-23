<?php
function writeMenu()
{
?>
	<div id="menu">
		<div id="list">
			<?php
				$listOfVarJavascript = "var arrayApps = new Array(); ";
			
				$appPerRow = 4;
				$rowPerPage = 5;
				$ip = 0;
				echo '<div class="page" id="page0">'; //Apertura pagina
				echo '<div class="row" id="row0">'; //Apertura riga
				$results = mysql_query('SELECT * FROM apps'. /*'WHERE owner='.$_SESSION['user_id'].*/ ' ORDER BY position') or die("Connessione non riuscita: " . mysql_error());
				while ($row = mysql_fetch_array($results)) {
					//Inizio gestione regione app
					echo '<div class="menuApp" id="menuApp'.$ip .'" onClick="openMoreInfoApp('.$ip.')"><div style="position:relative; padding-bottom:0px;">'; //Inizio riga
						//								
						//WHITE VERSION	
						//							
						echo '<div class="menuAppPre" id="menuAppPre'.$ip .'">';
						echo '<div class="menuAppIcon"><img width="64" height="64" src="pages/apps/'.$row['path'].'/icon.png"/></div>'; //Gestione icona
						//Gestione titolo e sottotitolo
						echo '<div class="menuAppTitleDescr">';	
						echo '<div class="menuAppTitle">' . $row['name'] . '</div>'; //Scrivi nome
						echo '<div class="menuAppDescription">' . $row['desc'] . '</div>'; //Scrivi descrizione			
						echo '</div>';					
						echo '</div>'; //Chiusura menuAppPre
						//
						//BLACK VERSION
						//
						echo '<div class="menuAppPreBlack" id="menuAppPreBlack'.$ip .'">';
						echo '<div class="menuAppIcon"><img width="64" height="64" src="pages/apps/'.$row['path'].'/icon.png"/></div>'; //Gestione icona
						//Gestione titolo e sottotitolo
						echo '<div class="menuAppTitleDescrBlack">';	
						echo '<div class="menuAppTitleBlack">' . $row['name'] . '</div>'; //Scrivi nome
						echo '<div class="menuAppDescriptionBlack">' . $row['desc'] . '</div>'; //Scrivi descrizione			
						echo '</div>';					
						echo '</div>'; //Chiusura menuAppPre
					echo '</div></div>'; //Chiusura menuApp 
					
					//Aggiunta app alle variabili javascript
					$listOfVarJavascript .= "arrayApps[".$ip."]='".$row['path']."'; ";
					//Fine controllo regione app
					$ip++; //Incrementa
					if(($ip % $appPerRow) == 0){ //Morta una riga se fa un'altra
						echo '</div>';
						
						$thisRow = ((int)(($ip-1)/$appPerRow));
						echo '<div id="appMoreInfo'.$thisRow.'" class="appMoreInfo"><div id="inAppMoreInfo'.$thisRow.'">'; //Creazione riga di moreInfo
						echo '</div></div>';
						
						echo '<div class="row" id="row' . ((int)(($ip)/$appPerRow)) . '">';
					}
					if(($ip % ($appPerRow*$rowPerPage)) == 0) //Morta una pagina se ne fa un'altra
					{
						echo '</div>';
						echo '<div class="page" id="page'.((int)($ip/($appPerRow*$rowPerPage))).'">';
					}
				}
				echo '</div>'; //Chiudi ultima riga
				
				$thisRow = ((int)(($ip)/$appPerRow));
				echo '<div id="appMoreInfo'.$thisRow.'" class="appMoreInfo"><div id="inAppMoreInfo'.$thisRow.'">'; //Creazione riga di moreInfo
				echo '</div></div>';
				
				echo '</div>'; //Chiudi ultima pagina
				
				//Stampa javascript con le variabili
				echo '<script>'. $listOfVarJavascript . '</script>';
			?>
		</div>
	</div>
<?php
}

function writeMenuDeveloper()
{
?>
	<!--<div style="text-align:center; color:red; font-size:16px;">Developer Men&uacute; </div>-->
	
	<div id="menu">
		<div id="list">
			<?php
				$listOfVarJavascript = "var arrayApps = new Array(); ";
			
				$appPerRow = 4;
				$rowPerPage = 5;
				$ip = 0;
				echo '<div class="page" id="page0">'; //Apertura pagina
				echo '<div class="row" id="row0">'; //Apertura riga
				
				$sql = 'SELECT a.path AS path, a.name AS name, a.`desc` AS `desc`, r.rev AS `idrev`, r.desc AS `descrev`, r.ver AS `verrev` FROM revisions r, apps a WHERE a.owner='.$_SESSION['user_id'].' AND r.app = a.id ORDER BY a.position';

				$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
				while ($row = mysql_fetch_array($results)) {
					//Inizio gestione regione app
					echo '<div class="menuApp" id="menuApp'.$ip .'" onClick="openMoreInfoApp('.$ip.')"><div style="position:relative; padding-bottom:0px;">'; //Inizio riga
						//								
						//WHITE VERSION	
						//							
						echo '<div class="menuAppPre" style="background-color:rgba(255,0,0,0.1);" id="menuAppPre'.$ip .'">';
						echo '<div class="menuAppIcon"><img width="64" height="64" src="pages/apps/revisions/'.$row['idrev'].'/'.$row['path'].'/icon.png"/></div>'; //Gestione icona
						//Gestione titolo e sottotitolo
						echo '<div class="menuAppTitleDescr">';	
						echo '<div class="menuAppTitle">' . $row['name'] . '</div>'; //Scrivi nome
						echo '<div class="menuAppDescription">Ver: '. $row['verrev'] .' - ' . $row['idrev'] . '<br> '. $row['descrev'] .'</div>'; //Scrivi descrizione			
						echo '</div>';					
						echo '</div>'; //Chiusura menuAppPre
						//
						//BLACK VERSION
						//
						echo '<div class="menuAppPreBlack" id="menuAppPreBlack'.$ip .'">';
						echo '<div class="menuAppIcon"><img width="64" height="64" src="pages/apps/revisions/'.$row['idrev'].'/'.$row['path'].'/icon.png"/></div>'; //Gestione icona
						//Gestione titolo e sottotitolo
						echo '<div class="menuAppTitleDescrBlack">';	
						echo '<div class="menuAppTitleBlack">' . $row['name'] . '</div>'; //Scrivi nome
						echo '<div class="menuAppDescriptionBlack">' . $row['desc'] . '</div>'; //Scrivi descrizione			
						echo '</div>';					
						echo '</div>'; //Chiusura menuAppPre
					echo '</div></div>'; //Chiusura menuApp 
					
					//Aggiunta app alle variabili javascript
					$listOfVarJavascript .= "arrayApps[".$ip."]='revisions/".$row['idrev'].'/'.$row['path']."'; ";
					//Fine controllo regione app
					$ip++; //Incrementa
					if(($ip % $appPerRow) == 0){ //Morta una riga se fa un'altra
						echo '</div>';
						
						$thisRow = ((int)(($ip-1)/$appPerRow));
						echo '<div id="appMoreInfo'.$thisRow.'" class="appMoreInfo"><div id="inAppMoreInfo'.$thisRow.'">'; //Creazione riga di moreInfo
						echo '</div></div>';
						
						echo '<div class="row" id="row' . ((int)(($ip)/$appPerRow)) . '">';
					}
					if(($ip % ($appPerRow*$rowPerPage)) == 0) //Morta una pagina se ne fa un'altra
					{
						echo '</div>';
						echo '<div class="page" id="page'.((int)($ip/($appPerRow*$rowPerPage))).'">';
					}
				}
				echo '</div>'; //Chiudi ultima riga
				
				$thisRow = ((int)(($ip)/$appPerRow));
				echo '<div id="appMoreInfo'.$thisRow.'" class="appMoreInfo"><div id="inAppMoreInfo'.$thisRow.'">'; //Creazione riga di moreInfo
				echo '</div></div>';
				
				echo '</div>'; //Chiudi ultima pagina
				
				//Stampa javascript con le variabili
				echo '<script>'. $listOfVarJavascript . '</script>';
			?>
		</div>
	</div>
<?php
}
?>