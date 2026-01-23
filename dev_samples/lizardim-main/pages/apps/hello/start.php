<?php 
$items = menuAddItem("Directory", "Imposta l'url directory e annessi connessi", "test");
$items .= menuAddItem("Wizard", "Il nostro prima wizard!", "wizard");
$items .= menuAddItem("Torna Catalessi", "Torna, torna catalessi... falli tutti fessi ...TOOOORNAAA SCEGLI LA CATENA", "test");
menuGenerate("Opzioni Apache",$items);
?>