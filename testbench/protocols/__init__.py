from ftp import FTP
from irc import IRC
from ssh import AUTH as SSH_AUTH
from telnet import Telnet as TELNET

protocols = {"IRC" : IRC, "FTP": FTP, "SSH-AUTH" : SSH_AUTH, "TELNET-SKIPINIT" : TELNET}