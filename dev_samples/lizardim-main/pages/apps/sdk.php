<?php
session_start();

//Vars
$_SESSION['absoluteAppsPath'] = '/var/www/pages/apps/';

//Include database
include("../../data.php");

//Manage ssh2
include("ssh_access.php");

//Include revisions function
include("sdk/revision.php");

////////////////SSH STREAMING//////////////////////
function startStreamSSH()
{
	$sql = "SELECT * FROM connectino WHERE id='". $_REQUEST['ssh'] ."' AND user='".$_SESSION['user_id'] . "' LIMIT 1";
	$results = mysql_query($sql) or die("Connessione non riuscita: " . mysql_error());
	
	while ($row = mysql_fetch_array($results)) {				
		$pc_user = $row['pc-user'];
		$ip = $row['ip'];
		$password = $row['password'];
	}
	
	if (!function_exists("ssh2_connect")) die("function ssh2_connect doesn't exist");
	// log in at server1.example.com on port 22
	
	if(!($con = ssh2_connect($ip, 22))){
		//echo "fail: unable to establish connection\n";
		return -1;
	}
	else {
		// try to authenticate with username root, password secretpassword
		if(!ssh2_auth_password($con, $pc_user, $password)) {
			return -2;
		}
		else
		{
			$_SESSION['pc_sshs'] = $con;
			return 1;
		}
	}
}

function sshTester($ip, $user, $password)
{
	if (!function_exists("ssh2_connect")) die("function ssh2_connect doesn't exist");
	if(!($con = ssh2_connect($ip, 22))){
		return -1; //CONNECTION FAILED
	}
	else {
		if(!ssh2_auth_password($con, $user, $password)) {
			return -2; //AUTH FAILED
		}
		else
		{
			return 1; //SUCCESS
		}
	}
}

/////////////////FILE FUNCTIONS////////////////////
function recurse_copy($src,$dst) {
    $dir = opendir($src);
    @mkdir($dst);
    while(false !== ( $file = readdir($dir)) ) {
        if (( $file != '.' ) && ( $file != '..' )) {
            if ( is_dir($src . '/' . $file) ) {
                recurse_copy($src . '/' . $file,$dst . '/' . $file);
            }
            else {
                copy($src . '/' . $file,$dst . '/' . $file);
            }
        }
    }
    closedir($dir);
} 

function copyfolder($src,$dst) { 
    $dir = opendir($src); 
    @mkdir($dst); 
    while(false !== ( $file = readdir($dir)) ) { 
        if (( $file != '.' ) && ( $file != '..' )) { 
            if ( is_dir($src . '/' . $file) ) { 
                recurse_copy($src . '/' . $file,$dst . '/' . $file); 
            } 
            else { 
                copy($src . '/' . $file,$dst . '/' . $file); 
            } 
        } 
    } 
    closedir($dir); 
} 

//Delete dir
function deleteDir($path) {
    $path = rtrim($path, '/').'/';
    $handle = opendir($path);
    while(false !== ($file = readdir($handle))) {
        if($file != '.' and $file != '..' ) {
            $fullpath = $path.$file;
            if(is_dir($fullpath)) deleteDir($fullpath); else unlink($fullpath);
        }
    }
    closedir($handle);
    rmdir($path);
}

/////////////////////////////////////////////////////////////
///////////////////////MENU'/////////////////////////////////
/////////////////////////////////////////////////////////////

$GLOBALS["itemsnum"] = 0;
function menuAddItem($title, $desc, $url)
{
	$GLOBALS["itemsnum"]++;	
	$colorBack = '#EEEEEE';
	if($GLOBALS["itemsnum"]%2) $colorBack = '#E0E0E0';
	
	$ret = '<div class="inappMenuItems" style="background-color:'.$colorBack.'" onClick="'."openPage('".$url."', '".$title."')".'">';
	$ret .= '<div class="inappMenuTitle">'.$title.'</div>';
	$ret .= '<div class="inappMenuDesc">'.$desc.'</div>';
	$ret .= '<div class="inappMenuFrecce"><img src="style/image/frecce.png"/></div>'; /*&raquo*/
	$ret .= '</div>';
	
	return $ret;
}

function menuGenerate($title,$items)
{
	echo '<div class="inappMenu">';
	echo '<div class="inappMenuTop">'.$title.'</div>';
	echo $items;
	echo '<div class="inappMenuFinal"></div>';
	echo '</div>';
	
	$GLOBALS["itemsnum"] = 0;
}

/////////////////////////////////////////////////////////////
///////////////////////WIZARD////////////////////////////////
/////////////////////////////////////////////////////////////
$GLOBALS["wizarditemsnum"] = 0;
function wizardAddItem($title, $id)
{
	$num = $GLOBALS["wizarditemsnum"];
	$GLOBALS["wizarditem-title-" . $num] = $title;
	$GLOBALS["wizarditem-id-" . $num] = $id;
	
	$GLOBALS["wizarditemsnum"]++;
}

function wizardGenerate()
{
	$varSteps = "var listStepsId = new Array(); var wizardNumStep=".$GLOBALS["wizarditemsnum"].";";

	echo '<div class="inappWizard">';
	echo '<div class="inappWizardMenu">';
	echo '<div class="inappWizardMenuList">';
		for($it=0; $it<$GLOBALS["wizarditemsnum"]; $it++)
		{
			$varSteps .= 'listStepsId['. $it . ']="'.$GLOBALS["wizarditem-id-" . $it].'";';

			echo '<div class="inappWizardMenuStep" id="step'. $GLOBALS["wizarditem-id-" . $it] .'">&middot; '. $GLOBALS["wizarditem-title-" . $it] . '</div>';
		}
	echo '</div>';
	echo '</div>';

	echo '<script>' . $varSteps . ' startWizard();</script>';
	
	echo '<div class="inappWizardContent">';
	echo '<div id="inappWizardContent"></div>';
	echo '<div id="wizardNavigate"><div style="display:table-cell; width:150px; text-align:left;"><button id="wizardBack" style="display:none;" onClick="wizardBack()">Back</button></div>  <div style="display:table-cell; width:150px; text-align:right;"><button id="wizardNext" onClick="wizardNext()">Next</button></div></div>';
	echo '</div>';
	echo '</div>';

	?>
	<div id="endOfWizard" style="display:none;">
		<div style="text-align:center;">
			<div id="endOfWizardTitle">Elaborazione in corso...</div>
			<div id="endOfWizardErr"></div>
		</div>
	</div>
	<?php	

	$GLOBALS["wizarditemsnum"] = 0;
}


/////////////////////////////////////////////////////////////
///////////////////////FORM MGMT/////////////////////////////
/////////////////////////////////////////////////////////////
function formStart($onSub)
{
	echo '<form name="'.$onSub.'" class="formDiv" onsubmit="'.$onSub.'Ev(); return false;"><table class="formTable">';
}

function formAddItems($name, $capt, $type)
{
	formAddItems_plus($name, $capt, $type, "");
}

function formAddItems_plus($name, $capt, $type, $plus)
{
	echo '<tr>';
	echo '<td class="tdName">'.$capt.':</td>';
	
	$input = '<input type="'.$type.'" id="'.$name.'" name="'.$name.'" '.$plus.'/>';
	echo '<td class="tdInput">'. $input .'</td>';
}

function formEnd($value)
{
	echo '<tr><td></td><td><input type="submit" value="'.$value.'"></td></tr>';
	echo '</table></form>';
}

/* ========= RAPID APPS SCROUCHT ============ */
function getAppPath()
{
	$pieces = explode("/", $_REQUEST['u']); 
	$path = str_replace($pieces[count($pieces)-1], "", $_REQUEST['u']);
	return "pages/apps/" . $path;
}

function getAppPathFromLinkUrl()
{
	$pieces = explode("/", $_REQUEST['u']); 
	$path = str_replace($pieces[count($pieces)-1], "", $_REQUEST['u']);
	
	$prefix = 'pages/apps/';
	if (substr($path, 0, strlen($prefix)) == $prefix) {
		$path = substr($path, strlen($prefix));
	} 

	return $path;
}

function gotReload()
{
	echo '<script>addToReloadPages("'. $_REQUEST['u'] .'")</script>';
}

function getUrlWithGet($url)
{
	return "/pages/apps/get.php?u=". getAppPathFromLinkUrl() . $url ."&nophp=1&ssh=". $_REQUEST["ssh"];
}
/* ========= END RAPID ===================*/
?>
