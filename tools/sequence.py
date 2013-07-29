'''
Created on 14.06.2012

@author: Felix
'''
from algorithms import findItemInList

class Sequence:
    
    def __len__(self):
        return len(self.rawSeq)
        
    def __init__(self, rawSeq):
        
        self.rawSeq = rawSeq
        self.len = len(rawSeq)
        self.indexed = False
            
    def _index(self):
        self.indexes = {}
        for i in range(len(self.rawSeq)):
            item = self.rawSeq[i]
            if item not in self.indexes:
                self.indexes[item] = []
            self.indexes[item].append(i)
            
        self.indexed = True
        
    def containsItem(self, item):
        """
        Checks if the given item is contained in the sequence.
        @param item: The item to check for.
        @return: A boolean value
        """
        try:
            self.rawSeq.index(item)
            return True
        except ValueError:
            return False
        
    def containsSeq(self, s):
        """
        Checks if the sequence contains a given sequence.
        @param s: The sequence to check.
        @return: A boolean value
        """
        cr = self.getCommonRanges(s)
        cr1 = cr[1]
        if len(cr1) != 1:
            return False
        
        return cr1[0] == range(len(s))
        
    def removeAll(self, item):
        newSeq = []
        for x in self.rawSeq:
            if x != item:
                newSeq.append(x)
        self.rawSeq = newSeq
        
    def getCommonRanges(self, s):
        """
        Gets the ranges in two sequences that are common. 
        @param s: The sequence to compare to.
        @return: A tuple containing the consecutive common ranges for both sequences. Example:
                S0 = [1,2,3,4,4,5,4,7,4,7,8,9]
                S1 = [1,2,3,0,0,7,8,9,5]
                
                return = ([range(0,3), range(9,12)], [range(0,3), range(5,8)])
                
                Note how the common sub-sequences [5] and [7] are not taken into account. 
        """
        # get common sub-sequences
        commonSubSeqs = self.findCommonSubSequences(s)
        # now sort them according to their order of appearance in both sequences
        subSeqsPrimary = {}
        subSeqsSecondary = {}
        
        for commonSubSeq in commonSubSeqs:
            for indexPrimary in commonSubSeq.indexesParent:
                if indexPrimary not in subSeqsPrimary or subSeqsPrimary[indexPrimary].len < commonSubSeq.len:
                    subSeqsPrimary[indexPrimary] = commonSubSeq
                    
            for indexSecondary in commonSubSeq.indexesOther:
                if indexSecondary not in subSeqsSecondary or subSeqsSecondary[indexSecondary].len < commonSubSeq.len:
                    subSeqsSecondary[indexSecondary] = commonSubSeq
                
        indexesPrimary = subSeqsPrimary.keys()
        indexesSecondary = subSeqsSecondary.keys()
        indexesPrimary.sort()
        indexesSecondary.sort()
        
        rangesPrimary = []
        rangesSecondary = []
        
        i = 0
        j = 0
        while i in range(len(indexesPrimary)) and j in range(len(indexesSecondary)):
            while i in range(len(indexesPrimary)) and j in range(len(indexesSecondary)):
                indexPrimary = indexesPrimary[i]
                indexSecondary = indexesSecondary[j]
                
                subSeqPrimary = subSeqsPrimary[indexPrimary]
                subSeqSecondary = subSeqsSecondary[indexSecondary]
                
                if subSeqPrimary == subSeqSecondary:
                    # everything is fine
                    rangesPrimary.append(range(indexPrimary, indexPrimary + subSeqPrimary.len))
                    rangesSecondary.append(range(indexSecondary, indexSecondary + subSeqSecondary.len))
                    break
                    
                elif len(subSeqPrimary) > len(subSeqSecondary):
                    j += 1
                else:
                    i += 1
                
            # update indexes
            i, exactMatch = findItemInList(indexesPrimary, indexPrimary + subSeqPrimary.len)
            if not exactMatch:
                i += 1
                
            j, exactMatch = findItemInList(indexesSecondary, indexSecondary + subSeqSecondary.len)
            if not exactMatch:
                j += 1
            
        return (rangesPrimary, rangesSecondary)
            
    def findCommonSubSequences(self, s):
        """
        Finds common successive sub-sequences in two given sequences.
        @param s: The sequence to compare to.
        @return: A list of SubSequence objects.
        """
        s._index()
        seq0 = self.rawSeq
        seq1 = s.rawSeq
        commonSeqs = []
        currSeq = []
        indexes1 = [0]
        j = 0
        while j < len(seq0):
            item = seq0[j]
            newIndexes1 = []
            for i in range(len(indexes1)):
                index1 = indexes1[i]
                if index1 < len(seq1) and item == seq1[index1]:
                    newIndexes1.append(indexes1[i] + 1)
                
            if len(newIndexes1) > 0:
                currSeq.append(item)
                j += 1
            else:
                if len(currSeq) > 0:
                    commonSeqs.append(SubSequence(currSeq, [j-len(currSeq)], [i-len(currSeq) for i in indexes1]))
                currSeq = []
                newIndexes1 = []
                while j in range(len(seq0)):
                    if seq0[j] in seq1:
                        newIndexes1 = s.indexes[seq0[j]]
                        break
                    j += 1
            indexes1 = newIndexes1
        # check if currSeq still contains items
        if len(currSeq) > 0:
            commonSeqs.append(SubSequence(currSeq, [j-len(currSeq)], [i-len(currSeq) for i in indexes1]))
        return commonSeqs
    
    def findLargestCommonSubSequence(self, s):
        """
        Finds the largest common sub-sequence shared with the given sequence
        @param s: The sequence to compare to.
        @return: The largest common sub-sequence
        """
        commonSubSeqs = self.findCommonSubSequences(s)
        if len(commonSubSeqs) == 0:
            return None
        maxSubSeq = commonSubSeqs[0]
        for ss in commonSubSeqs[1:]:
            if ss.len > maxSubSeq.len:
                maxSubSeq = ss
        return maxSubSeq
 
class SubSequence(Sequence):        
    def __init__(self, rawSeq, indexesParent, indexesOther, parentSeq=None):
        Sequence.__init__(self, rawSeq)
        self.indexesOther = indexesOther
        self.indexesParent = indexesParent
        self.parentSeq = parentSeq
        
    def __str__(self):
        s = ""
        s += "Primary indexes: " + str(self.indexesParent) + " , secondary indexes: " + str(self.indexesOther) + ", sequence: " + str(self.rawSeq)
        return s
        
class SubSequenceContainer:
    def __init__(self):
        self.ranges = {}
        self.items = []
        
    def add(self, subSeq):
        for indexParent in subSeq.indexesParent:
            if not indexParent in self.ranges:
                self.ranges[indexParent] = []
            
            if not subSeq.len in self.ranges[indexParent]:
                self.ranges[indexParent].append(subSeq.len)
            
        self.items.append(subSeq)
            
    def hasSeq(self, start, length):
        """
        Checks whether a sequence starting at a given index with a given length is stored in the container.
        @param start: The starting index to look for.
        @param length: The length to look for 
        @return: A boolean flag indicating the condition.
        """
        tmp = findItemInList(self.ranges.keys(), start)
        if not tmp[1]:
            return False
        
        if not length in self.ranges[self.ranges.keys()[tmp[0]]]:
            return False
        
        return True
        
        
        