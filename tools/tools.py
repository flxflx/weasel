'''
Created on 11.05.2012

@author: Felix
'''

class Function:
    
    def __init__(self, addr, size, name):
        self.addr = addr
        self.size = size
        self.name = name

def getELFFromPathOrObject(pathOrElfObject):
    
    from elftools.elf.elffile import ELFFile
    if isinstance(pathOrElfObject, ELFFile):
        elf = pathOrElfObject
    else:
        f = file(pathOrElfObject, "rb")
        elf = ELFFile(f)
        
    return elf

def getLoadedImageSizeELF(pathOrElfObject):
    # TODO: For ELF headers with absolute addresses not the size but the end addr of the loaded image is calculated.
    elf = getELFFromPathOrObject(pathOrElfObject)
    from elftools import elf as ELF
    size = 0
    for sect in elf.iter_sections():
        if not isinstance(sect, ELF.sections.NullSection):
            v = sect.header.sh_offset + sect.header.sh_size  
            if v > size:
                size = v
    return size

def getLoadedImageStartELF(pathOrElfObject):
    elf = getELFFromPathOrObject(pathOrElfObject)
    from elftools import elf as ELF
    minAddr = None
    for sect in elf.iter_sections():
        if not isinstance(sect, ELF.sections.NullSection):
            if (minAddr is None or (sect.header.sh_addr < minAddr)) and sect.header.sh_addr != 0:  
                minAddr = sect.header.sh_addr
    return minAddr

def getLoadedImageEndELF(pathOrElfObject):
    elf = getELFFromPathOrObject(pathOrElfObject)
    from elftools import elf as ELF
    maxAddr = None
    for sect in elf.iter_sections():
        if not isinstance(sect, ELF.sections.NullSection):
            v = sect.header.sh_size + sect.header.sh_addr
            if maxAddr is None or v > maxAddr:  
                maxAddr = v
    return maxAddr

def extractFunctionsFromELF(pathOrElfObject, blackList=[]):
    """
    Extracts all functions from an ELF files using embedded symbols. Requires pydevtools to be installed.
    @param pathOrElfObject: Path to the ELF file to parse.
    @return: Dictionary {addr:name}
    """
    from elftools import elf as ELF
    
    names = {}
    elf = getELFFromPathOrObject(pathOrElfObject)
    
    sectionsWithSymbols = []
    for s in elf.iter_sections():
        if isinstance(s,ELF.sections.SymbolTableSection):
            sectionsWithSymbols.append(s)
    
    for s in sectionsWithSymbols:     
        for symbol in s.iter_symbols():
            name = symbol.name
            blackListed = False
            for blackListItem in blackList:
                if blackListItem in name:
                    blackListed = True
                    break
            
            if blackListed:
                continue
            symType = symbol.entry['st_info'].get('type')
            addr = symbol.entry['st_value']
            size = symbol.entry['st_size']
            
            if symType == "STT_FUNC" and addr != 0:
                names[addr] = Function(addr, size, name)
            
    return names

def extractFunctionsFromExecutable(arg):
    # TODO: implement for formats other than ELF
    return extractFunctionsFromELF(arg)

def extractFunctionNamesFromELF(pathOrElfObject):
    """
    Convenience wrapper for extractFunctionsFromELF.
    @param path: Path to the ELF file to parse.
    @return: Dictionary {name:[addr0, addr1]}
    """
    funcs = extractFunctionsFromELF(pathOrElfObject)
    names = {}
    for func in funcs.values():
        if func.name not in names:
            names[func.name] = []
        
        names[func.name].append(func.addr)
            
    return names

def extractFunctionNamesFromExecutable(arg):
    # TODO: currently only ELF is supported
    return extractFunctionNamesFromELF(arg)

def writeNamedDotFileELF(digraph, pathOut, pathElf=None, colors=None, names=None):
    """
    @param digraph: The directed graph to write-out.
    @param colors: Optional colors of nodes.
    @param pathOut: The file to write to.
    @param pathElf: Optional path to the corresponding ELF file containing symbols to use. Requires pydevtools to be installed.
    """
    # fills names dict with symbol names
    if pathElf and names is None:
        try:
            names = extractFunctionsFromELF(pathElf)
        except ImportError:
            print "[e] Could not import pydevtools. Please install them if you want to use symbols."
        
    out = "digraph graphname {\r\n"
    # add all nodes
    for node in digraph.nodes():
        if node in names:
            name = names[node]
        else:
            name = "%08x" % node
        
        props = "label=\"%s\"" % name
        if colors:
            if node in colors:
                props += ",color=%s,style=filled" % (colors[node])
                
        attributes = digraph.node_attributes(node)
        comments = ""
        for name,value in attributes:
            comments += "%s:%s" % (str(name), str(value))
            
        props += ",comment=\"%s\"" % comments        
        out += "%d [%s];\r\n" % (node, props)
        
    # add all edges
    for edge in digraph.edges():
        label = digraph.edge_label(edge)
        out += "%d -> %d [label=\"%s\"];\r\n" % (edge[0], edge[1], label)
        
    out += "}"
    # write out
    f = file(pathOut, "wb")
    f.write(out)
    f.close()
    
def writeNamedDotFile(digraph, pathOut, pathElf=None, colors=None, names=None):
    # TODO: other exe-files than ELFtsu
    return writeNamedDotFileELF(digraph, pathOut, pathElf, colors, names)
    
# helper functions
class ENDIANESS:
    LITTLE = 0
    BIG = 1

def reverseEndianess(x, bits):
    """
    Reverses the endianess of the given integer.
    @param x: The integer.
    @param bits: Size in bits of the target integer
    @return: The integer in reverse endianess form.
    """
    out = 0
    i = 1
    while (i <= (bits / 8 / 2)):
        out |= ((x >> (bits - (i << 3))) & 0xFF) << ((i - 1) << 3) 
        i += 1
        
    i = 1
    while (i <= (bits / 8 / 2)):
        out |= (x >> ((i - 1) << 3) & 0xFF) << (bits - (i << 3))
        i += 1
        
    return out

def intToByteStr(i, bits, endianess):
    j = 0
    bStr = "" 
    while j < bits:
        if endianess == ENDIANESS.LITTLE:
            s = j
        else:
            s = bits - (j + 8)
        bStr += chr((i >> s) & 0xFF)
        j += 8
        
    return bStr

def byteStrToInt(bStr, endianess):
    i = 0
    j = (len(bStr) - 1) * endianess
    s = 0
    while j in range(len(bStr)):
        i |= ord(bStr[j]) << s
        s += 8
        j += 1 - 2 * endianess
    return i

def unsignedToSignedInt(i, bits):
    j = i & (~(1 << bits))
    if i >> (bits-1) == 1:
        return -j
    return j

def translateList(l, d):
    k = []
    for x in l:
        if x in d:
            k.append(d[x])
        else:
            k.append(x)
    return k

def sortDictionary(d):
    
    from algorithms import findItemInList
    values = []
    keys = []
    for key in d:
        value = d[key]
        i = findItemInList(values, value)[0]
        values = values[:i+1] + [value] + values[i+1:]
        keys = keys[:i+1] + [key] + keys[i+1:]
        
    return (keys, values)

def findFirst(l, itemValue=None, itemType=object, offset=0):
    
    for i in range(offset, len(l)):
        item = l[i]
        if isinstance(item, itemType) and (itemValue is None or (item == itemValue)):
            return i
        
    return -1

def findSubLists(l, startItemValue, endItemValue, startItemType=object, endItemType=object):
        """
        Finds all sub-list starting with the given start- and ending with the given end-item.
        @param startItemValue: The start-item
        @param endItemValue: The end-item
        @param startItemType: [OPTIONAL] The type of the start-item
        @param endItemType: [OPTIONAL] The type of the end-item
        @return: A list of sublists 
        """
        subLists = []
        i = 0
        while i in range(len(l)):
            iStart = findFirst(l, startItemValue, startItemType, i)
            if iStart == -1:
                break
                    
            iEnd = findFirst(l, endItemValue, endItemType, iStart) 
            if iEnd == -1:
                break
            
            subLists.append(l[iStart:iEnd+1])
            i = iEnd + 1
            
        return subLists
