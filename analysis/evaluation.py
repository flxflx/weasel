'''
Created on 26.10.2012

@author: Felix
'''

from pygdb import environment
from pygdb.globals import log, DEBUG_LEVEL
from results import FunctionPointerTableCandidate

class Live:

    # maximum size of entry, in nativeRegisterWidth/8
    ENTRY_SIZE_THRESHOLD = 15

    # minimum number of entries in (suspected) function tables
    ENTRY_COUNT_MINIMUM = 4

    # boolean value, True: collects all possible entry sizes for the function
    # pointer table of a given function pointer
    COLLECT_ALL_SUSPECTS = False

    @staticmethod
    def getFunctionPointerTableCandidates(gdb, functionPointers):
        """
        Tries to find possible function pointer tables in the debugees address
        space.
        @param gdb: A halted but active pygdb debugging instance.
        @param functionPointers: Known function pointers to look for.
        @type functionPointers: List
        @return: Suspect function pointer tables
        @type: List of FunctionPointerTableCandidate
        """
        import tools
        ptrSize = gdb.cpu.getNativeRegisterWidth()
        
        # get image boundaries, number of sections
        imageEnd = gdb.environment.getEndAddrImage(gdb)
        imageStart = gdb.environment.getStartAddrImage(gdb)

        # TODO: we are extracting the section from ELF files and thus we need
        # to be in a Posix environment. adjust for PE{32,64}(+)/DWARF later.
        assert isinstance(gdb.environment, environment.Posix), \
            'Environment is not Posix.'

        sections = Live._extractSectionTable(gdb)

        # collect ranges we are going to scan for function pointer tables
        # contains tuples Int -> Int: (RangeBegin, RangeSize)
        ranges = []
        if isinstance(gdb.environment, environment.Posix):# and False:
            # TODO: gdb does not seem to be able to correctly scan these
            # sections. disabled for now.
            # TODO: exclude common sections which are known to contain data
            # we're not interested in (compiler stuff etc)
            # ranges = sections
            # now splits sections in several pages (seemingly necessary?) and scans each of them
            pageSize = gdb.cpu.getPageSize()
            for (begin, size) in sections:
                whole = [(begin + i * pageSize, pageSize) for i in range(size / pageSize)]
                tail  = size % pageSize
                if tail != 0:
                    whole.append((begin + (size - tail), tail))
                ranges.append(whole)
                
            ranges = [x for xs in ranges for x in xs]
        else:
            # we simply search one page at a time. we might get overlapping
            # issues (though unlikely), we're better of scanning whole sections
            ranges = [(i, gdb.cpu.getPageSize()) for i in \
                range(imageStart, imageEnd, gdb.cpu.getPageSize())]

        # map each function pointer to the section it lies in
        # Int -> (Int, Int): funcPtr -> (RangeBegin, RangeSize)
        # TODO: we remain silent if funcPtr got no section (it is ignored)
        fpSections = {}
        for sec in sections:
            begin = sec[0]
            end = begin + sec[1]

            for fp in functionPointers:
                if fp >= begin and fp < end:
                    fpSections[fp] = sec

        # set of FunctionPointerTableCandidate
        # several passed fps might be part of the same table, TODO: checking
        # worth the effort?
        candids = set()
        for fp in functionPointers:
            for begin, length in ranges:
                loc = gdb.searchMemory(begin, length, tools.intToByteStr(fp, ptrSize, tools.ENDIANESS.LITTLE))
                if loc is not None:

                    # guess the table from current table pointer
                    log(DEBUG_LEVEL.SOME, "[x] Found fp %x at %x!" % (fp, loc))
                    curSection = fpSections[fp]
                    candids |= set(Live._guessTableCandidatesFromPointer(gdb, \
                                        loc, curSection))

        for c in candids:
            log(DEBUG_LEVEL.SOME, str(c))
        return list(candids)

    @staticmethod
    def _guessTableCandidatesFromPointer(gdb, fpLoc, curSection,
                                        entrySizeLimit = ENTRY_SIZE_THRESHOLD):
        """
        Guesses a function pointer table candidate from the current pointer,
        assuming all pointers to point to the same section as the candidate.
        Increases entry size up to given limit. Tables with less than
        ENTRY_COUNT_MINIMUM entries arediscarded.
        @param gdb: A halted but active pygdb debugging instance.
        @param fpLoc: The position of a valid function pointer.
        @param curSection: Section the function pointer resides in, as tuple
        (Begin, Size), Int -> Int.
        @param entrySizeLimit: Maximum size of an entry in the table.
        """

        import operator
        import tools

        # get register width from gdb.cpu (assumed to == pointer width)
        ptrSize = gdb.cpu.getNativeRegisterWidth() / 8

        # helper to check if a given fp is in the same section as the
        # one used as reference
        def _checkRange(fp):
            return fp >= curSection[0] and fp < (curSection[0] + curSection[1])

        # helper to collect all the pointers for a given entrySize
        def _collectFps(loc, entrySize, direction):
            fps, curLoc = [], loc

            while True:
                curLoc = direction(curLoc, entrySize * ptrSize)
                curPtr = gdb.readMemory(curLoc, ptrSize)
                curPtr = tools.byteStrToInt(curPtr, tools.ENDIANESS.LITTLE)#struct.unpack("<I", curPtr)[0]

                if _checkRange(curPtr):
                    fps.append(curPtr)
                else:
                    break
            return fps

        entrySize = 1
        start = end = fpLoc
        candidates = []

        while True:
            # collect all the pointers before and after the reference fp
            # direction to search is given by third argument
            fpBack = _collectFps(fpLoc, entrySize, operator.sub)
            fpForw = _collectFps(fpLoc, entrySize, operator.add)
            nrBack, nrForw = len(fpBack), len(fpForw)

            # check if we collected at least ENTRY_COUNT_MINIMUM entries
            if nrBack + nrForw >= Live.ENTRY_COUNT_MINIMUM:
                start = fpLoc - nrBack * entrySize * ptrSize
                end = fpLoc + nrForw * entrySize * ptrSize
                fps = fpBack + fpForw

                # we got a fp table candidate, save and continue, if specified
                candidates.append(FunctionPointerTableCandidate(start, end,
                                                                entrySize, fps))
                if not Live.COLLECT_ALL_SUSPECTS:
                    return candidates

            # try to collect fps using a larger entrySize and abort eventually
            entrySize += 1
            if entrySize > entrySizeLimit:
                break
        return candidates

    @staticmethod
    def _extractSectionTable(gdb):
        """
        Extracts the section table from an ELF file. Expects Posix environment.
        @param gdb: A halted but active pygdb debugging instance.
        @return: List of sections, given as (sectionAddr, sectionSize).
        @type: List of (Int, Int) tuples
        """

        # check our environment. we need to be in Posix env so code using ELF
        # actually makes sense
        sections = []
        env = gdb.environment
        assert isinstance(env, environment.Posix), 'Environment is not Posix.'

        # simply collect all necessary section fields and rebase
        for sec in env.elf.iter_sections():
            if not sec.header.sh_addr or not sec.header.sh_size:
                continue

            addr = env.rebaseCodeAddr(gdb, sec.header.sh_addr)
            sections.append((addr, sec.header.sh_size))
        return sections
