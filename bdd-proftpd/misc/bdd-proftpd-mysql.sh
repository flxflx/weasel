#!/bin/bash

if [ $# -ne 1 ]; then
	echo "usage: $0 <mysql root pass>"
	exit 1
fi

echo "Creating mysql database \"bot\""
mysql --user=root --pass=$1 -e "CREATE DATABASE IF NOT EXISTS bot; GRANT ALL ON *.* TO 'bdd'@'localhost' IDENTIFIED BY 'bdd'; FLUSH PRIVILEGES;"

echo "Creating mysql tables for database \"bot\""
mysql --user=root --pass=$1 bot < /usr/share/bdd-proftpd-common/misc/bdd-proftpd-bot.sql
