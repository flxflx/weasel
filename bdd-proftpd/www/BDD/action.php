<?php
$Part = $_POST['part'];

$File = "test" . $Part . ".txt"; 
$Handle = fopen($File, 'wb');

$Data = $_POST['name'];
fwrite($Handle, $Data); 

fclose($Handle); 
?>