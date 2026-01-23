<?php
wizardAddItem("Wei wei", "wizard1");
wizardAddItem("Wooooooo", "wizard2");
wizardAddItem("Fine di sta storia", "wizard3");
wizardAddItem("Veramente suo", "wizard4");
wizardGenerate();
?>

<div id="wizard1">
<form>
Come ti chiami: <input type="text">
</form>
</div>

<div id="wizard2"> Stepp due!</div>
<div id="wizard3"> Ehiii!</div>
<div id="wizard4"> Barra bay!</div>

<script>
function endOfWizard()
{
	setTimeout(function(){ 
		$('#endOfWizardTitle').html("Fatto!"); 
		$('#endOfWizardErr').html("Errore, cazzo!"); 

		setTimeout('goPageBack()',1000);
	},2000);

}

function wizardNextStep(page)
{

}
</script>

