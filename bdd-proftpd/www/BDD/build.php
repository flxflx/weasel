<?php

$counter = 0;
// Create a new file in binary-mode
$fileName = $_GET["name"];

if (isset($fileName))
{
	$ptr = fopen($fileName, 'wb');
	
	// Path to directory to scan
	$directory = "";
	
	// Get all files with a .txt extension.
	$files = glob("" . $directory . "*.txt");
	
	// Count the files
	foreach($files as $data)
	{
		$counter++;
	}
	
	for ($i = 0; $i < $counter; $i++)
	{
		$temp = "test" . $i . ".txt";
		
		// Open file
		$fh = fopen($temp, "rb");
		
		// Read the whole file
		$data = fread($fh, filesize($temp));
		
		// Close handle
		fclose($fh);
		
		// Get handle
		$ptr = fopen($fileName, 'ab+');
		
		// Write data
		fwrite($ptr, $data);
		
		// Close handle
		fclose($ptr);	
		
		// Delete file
		unlink($temp);
	}
}

?>