<?php

// Validate IP-Address
function validateIpAddress($ip_addr)
{
  //first of all the format of the ip address is matched
  if(preg_match("/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/",$ip_addr))
  {
    //now all the intger values are separated
    $parts=explode(".",$ip_addr);
    //now we need to check each part can range from 0-255
    foreach($parts as $ip_parts)
    {
      if(intval($ip_parts)>255 || intval($ip_parts)<0)
      return false; //if number is not within range of 0-255
    }
    return true;
  }
  else
    return false; //if format of ip address doesn't matches
}

// Setting up the MySQL Connection
$mysqlhost="localhost"; // MySQL-Host angeben
$mysqluser="bdd"; // MySQL-User angeben
$mysqlpwd="bdd"; // Passwort angeben
$mysqldb="bot"; // Gewuenschte Datenbank angeben

$connection=mysql_connect($mysqlhost, $mysqluser, $mysqlpwd) or die ("Verbindungsversuch fehlgeschlagen");
mysql_select_db($mysqldb, $connection) or die("Konnte die Datenbank nicht waehlen.");

// Get IP-Address
$ip = $_SERVER['REMOTE_ADDR'];

// Is the POST-Variable "init" set?
if (validateIpAddress($ip) && isset($_POST['init']) && intval($_POST['init']) === 1)
{
	$sql = "SELECT * FROM active WHERE ip ='" . $ip . "'";
	$adressen_query = mysql_query($sql) or die("Anfrage nicht erfolgreich");
	$anzahl = mysql_num_rows($adressen_query);
	
	// Es existiert bereits ein Eintrag mit dieser IP, also Updaten...
	if ($anzahl === 1)
	{
		$sql = "UPDATE active SET last_keep_alive = NOW() WHERE ip = '" . $ip . "'";
	}
	else
	{
		$sql = "INSERT INTO active (ip, init_keep_alive, last_keep_alive) VALUES ('" . $ip . "', NOW(), NOW())";
	}
	
	$adressen_query = mysql_query($sql) or die("Anfrage nicht erfolgreich");
}
else
{
	echo "Error";
}

?>
