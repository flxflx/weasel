#!/bin/bash

port=$(grep Port ~/BDD_LE/Samples/proftpd/rootfs/etc/proftpd_backdoor.conf | awk '{print $2}')
zenity --info --title="Test" --text="Your FTP server listens on port: ${port}" 
