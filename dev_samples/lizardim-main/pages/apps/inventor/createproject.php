<h2>Create New Project</h2>

<?php
formStart('formCreate');

formAddItems('name', 'Name', 'text');
formAddItems('path', 'Path', 'text');
formAddItems('descr', 'Description', 'text');

formEnd('Add Project');
?>

<script>
function formCreateEv()
{
	var req = 'name=' + document.forms["formCreate"]["name"].value + '&descr=' + document.forms["formCreate"]["descr"].value + '&path=' + document.forms["formCreate"]["path"].value;
	getNow('get_addproject.php', 'createRequested', req);
}

function createRequested(data)
{
	callNotify("Project created!");
	goPageBack(1);
}

</script>