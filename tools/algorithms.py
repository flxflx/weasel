'''
Created on 24.04.2012

@author: Felix

various algorithms (not necessarily tied to the pygdb library)
'''
def _findRepetition(lin, i):
    c = lin[i]
    j = 1
    found = False
    while j<=len(lin)-i+1 and not found:
        if lin[i-j] == c:
            if lin[i-j:i] == lin[i:i+j]:
                found = True
        j += 1
    if not found:
        return 0
    return j-1
            

def removeRepetitions(lin):
    """
    Removes repetitions of patterns in a given list. E.g.: ABCBCDEF -> ABCDEF
    @param lin A list in which repetitions of patterns are to be removed.
    @type lin List
    @return The stripped down version of the list
    """
    i = 1
    while i < len(lin):
        l = _findRepetition(lin,i)
        if l != 0:
            lin = lin[:i] + lin[i+l:]
        else:
            # only increment i if we no repetition was found (by collapsing repetitions we might get new repetitions)
            i += 1
    return lin

def findListsSplitIndex(l0, l1, ignoreRepetitions=False):
    """
    Finds the index to which two lists are the same.
    @param l0 The first list.
    @param l1 The second list.
    @param ignoreRepetitions Flag indicating whether repetitions should be ignored/skipped or not.
    @param type boolean
    @return A tuple containing the index of the first differing element for both lists.
    """
    i = 0
    offset0 = 0
    offset1 = 0
    while (i+offset0) in range(len(l0)) and (i+offset1) in range(len(l1)):
        if ignoreRepetitions and i >= 1:
            offset0 += _findRepetition(l0, i+offset0)
            offset1 += _findRepetition(l1, i+offset1)
        if l0[i+offset0] != l1[i+offset1]:
            break
        i += 1
    return (i+offset0, i+offset1)

def findItemInList(l, num):
    """
    Finds the index for a given number in a given list. If the number is not found, an index is returned of where to insert the number.
    @param l: The list to search in.
    @param num: The number to search for.
    @return: A tupel, (index,exactMatch) where exactMatch is a boolean value indication whether the number was actually found or not.
    """ 
    if len(l) == 0:
        return (0, False)
    
    l.sort()
    iLo = 0
    iHi = len(l) -1
    i = 0
    exactHit = False
    while True:
        i = (iHi - iLo)/2 + iLo
        if iHi < iLo:
            break
        
        if num == l[i]:
            exactHit = True
            break
        
        if num < l[i]:
            iHi = i-1
            
        if num > l[i]:
            iLo = i+1
    return (i, exactHit)