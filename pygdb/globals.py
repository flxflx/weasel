'''
Created on 27.03.2012

@author: Felix
'''
import os


# logging
class DEBUG_LEVEL:
    ALL = 1
    SOME = 2
    IMPORTANT = 3
    NONE = 4

## flags
DEBUG = DEBUG_LEVEL.ALL
LOG_FILE = file("mylog.txt", "wb")
TIGHT_SYNC_LOG_FILE = False

def log(level, s):
    if DEBUG <= level:
        print s
        if LOG_FILE != None:
            LOG_FILE.write(s)
            LOG_FILE.write("\r\n")
            if TIGHT_SYNC_LOG_FILE:
                LOG_FILE.flush()
                os.fsync(LOG_FILE)
