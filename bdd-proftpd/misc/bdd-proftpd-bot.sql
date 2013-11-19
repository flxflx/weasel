-- phpMyAdmin SQL Dump
-- version 3.4.5deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Erstellungszeit: 08. Jul 2012 um 20:36
-- Server Version: 5.1.61
-- PHP-Version: 5.3.6-13ubuntu3.6

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Datenbank: `bot`
--

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `active`
--

CREATE TABLE IF NOT EXISTS `active` (
  `ip` varchar(15) NOT NULL,
  `init_keep_alive` datetime NOT NULL,
  `last_keep_alive` datetime NOT NULL,
  `status` varchar(7) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `config`
--

CREATE TABLE IF NOT EXISTS `config` (
  `ip` varchar(15) NOT NULL,
  `fakedownload` int(1) NOT NULL,
  `category` varchar(5) NOT NULL,
  `filename_good` varchar(1000) NOT NULL,
  `filename_evil` varchar(1000) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

--
-- Daten für Tabelle `config`
--

INSERT INTO `config` (`ip`, `fakedownload`, `category`, `filename_good`, `filename_evil`) VALUES
('127.0.0.1', 1, 'local', '/usr/share/bdd-proftpd-common/home/bddtestuser/testcases/goodboy.test', '/usr/share/bdd-proftpd-common/home/bddtestuser/testcases/badboy.test');

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `login`
--

CREATE TABLE IF NOT EXISTS `login` (
  `ip` varchar(15) NOT NULL,
  `user` varchar(25) NOT NULL,
  `pass` varchar(25) NOT NULL,
  `auth_type` varchar(6) NOT NULL,
  `last_login` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
