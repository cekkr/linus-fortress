/////////////// NOTIFY /////////////
function callNotify(text)
{
	$('#notifyDiv').html(text);
	$('#notifyDiv').css({'opacity':'0'});
	$('#notifyDiv').show();
	
	$('#notifyDiv').animate({
		opacity: 1
	}, 400, function() {
	// Animation complete.
	});
	
	setTimeout("closeNotify()",3000);
}

function closeNotify()
{
	$('#notifyDiv').animate({
		opacity: 0,
	}, 2000, function() {
		$('#notifyDiv').hide();
	});
}

////////////////////////////////////
////////WIZARD JAVASCRIPT///////////
////////////////////////////////////
var numStep = 0;
function startWizard()
{
	numStep = 0;
	$('#step'+listStepsId[0]).animate({
		backgroundColor: "#3AA0FF"
		}, 100, function() {

			var listDiv = "";
			for(step=0; step<wizardNumStep; step++)
			{
				$('#' + listStepsId[step]).hide();
				listDiv +=  '<div style="display:none; opacity:0;" id="form'+listStepsId[step]+'" >'+$('#'+listStepsId[step]).html()+'</div>';
			}

			$('#inappWizardContent').html(listDiv);

			$('#form' + listStepsId[0]).show();
			$('#form' + listStepsId[0]).css('opacity','1');
		});

}

function wizardNext()
{
		if(numStep>=(wizardNumStep-1))
		{
			$('#inappWizardContent').html($('#endOfWizard').html());

			$('#wizardNavigate').animate({
			opacity:0
			}, 100, function() {
				$('#wizardNavigate').hide();
			});

			$('#step'+listStepsId[numStep]).animate({
			backgroundColor: "#448844",
			opacity:0.8
			}, 300, function() {
			});

			endOfWizard();
		}
		else
		{
			//Preoccupati del vecchio step
			$('#step'+listStepsId[numStep]).animate({
			backgroundColor: "#888888",
			opacity:0.6
			}, 300, function() {
			});

			//Step successivo
			numStep++;
			$('#step'+listStepsId[numStep]).animate({
			backgroundColor: "#3AA0FF",
			opacity:1
			}, 300, function() {
			});

			$('#form'+listStepsId[numStep-1]).animate({
				opacity:0
			}, 100, function() {
				$('#form'+listStepsId[numStep-1]).hide();
				$('#form'+listStepsId[numStep]).show();

				$('#form'+listStepsId[numStep]).animate({
					opacity:1
				}, 100, function() {
				});
			});

			wizardNextStep(numStep);

			//Gestione pulsante
			if(numStep>0) $('#wizardBack').show("fast");
			if(numStep==(wizardNumStep-1)) $('#wizardNext').html("Finish");
		}
}

function wizardBack()
{
		//Preoccupati del vecchio step
		$('#step'+listStepsId[numStep]).animate({
		backgroundColor: "#888888",
		opacity:0.4
		}, 300, function() {
		});

		//Step precedente
		numStep--;
		$('#step'+listStepsId[numStep]).animate({
		backgroundColor: "#3AA0FF",
		opacity:1
		}, 300, function() {
		});

		$('#form'+listStepsId[numStep+1]).animate({
			opacity:0
		}, 100, function() {
			$('#form'+listStepsId[numStep+1]).hide();
			$('#form'+listStepsId[numStep]).show();

			$('#form'+listStepsId[numStep]).animate({
				opacity:1
			}, 100, function() {
			});
		});

		//Gestione pulsante
		if(numStep==0) $('#wizardBack').hide("fast");
		if(numStep<(wizardNumStep-1)) $('#wizardNext').html("Next");
}