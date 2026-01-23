<h2> Add the computer </h2>
<?php
formStart('formCreate');
formAddItems('name','Name Computer','text');
formAddItems('ip','IP Computer','text');
formAddItems('user','Username','text');
formAddItems('password','Password','password');
formEnd('Add Computer');
?>

<script> 
function formCreateEv()
{
	var req = 'name=' + document.forms['formCreate']['name'].value + 
		'&ip=' + document.forms['formCreate']['ip'].value +
		'&user=' + document.forms['formCreate']['user'].value +
		'&password=' + document.forms['formCreate']['password'].value ;
	getNow('get_addcomputer.php','createRequested', req);
		
}
function createRequested(res)
{
	callNotify("Computer Added");
	goPageBack(1);		
}
function deleteComputer()
{
	
}
</script>