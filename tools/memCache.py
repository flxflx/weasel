'''
Created on Jan 4, 2013

@author: felix
'''

from algorithms import findItemInList

class MemCache:
    
    class MemRange:
        
        def __init__(self, offset, data):
            self.offset = offset
            self.update(data)
            
        def update(self, data):
            self.data = data
            self.size = len(data)
            
        @staticmethod
        def sortRanges(rangeA, rangeB):
            
            if rangeA.offset < rangeB.offset:
                return (rangeA, rangeB)
            
            return (rangeB, rangeA)
                
            
        def merge(self, newerMemRange):
            """
            Merge with other mem-range. The other mem-range is considered as newer. 
            """
            mergedData = newerMemRange.data
            diffStart = newerMemRange.offset - self.offset
            if diffStart > 0:
                
                if diffStart > self.size:
                    return None
                
                mergedData = self.data[:diffStart] + mergedData
                mergedOffset = self.offset
            else:
                mergedOffset = newerMemRange.offset
                
            diffEnd = (self.offset + self.size) - (newerMemRange.offset + newerMemRange.size) 
            if  diffEnd > 0:
                
                if diffEnd > self.size:
                    return None
                
                mergedData = mergedData + self.data[self.size-diffEnd:]
                    
            return MemCache.MemRange(mergedOffset, mergedData)
                
        def contains(self, otherMemRange):
            return self.containsRange(otherMemRange.offset, otherMemRange.size)
        
        def clips(self, otherMemRange):
            
            loRange, hiRange = self.sortRanges(self, otherMemRange)
            return (loRange.offset + loRange.size) >= hiRange.offset
        
        def containsRange(self, offset, size):
            return (offset >= self.offset) and ((offset + size) <= (self.offset + self.size))
        
        def getRange(self, offset, size):
            if not self.containsRange(offset, size):
                return None
            
            relOffset = offset-self.offset
            return self.data[relOffset:relOffset+size]
    
    def __init__(self):
        self.ranges = {}
    
    def getRange(self, offset, size):
        
        index, rangeOffsets = self._findRange(offset)
        if index == -1 or len(rangeOffsets) == 0:
            return None
              
        rangeOffset = rangeOffsets[index]
        return self.ranges[rangeOffset].getRange(offset, size)
        
    def setRange(self, offset, data):
        
        newMemRange = self.MemRange(offset, data)
        index, rangeOffsets = self._findRange(offset)
        # check ranges left and right if a merge is possible
        loIndex = index > 0 and index-1 or 0
        hiIndex = index + 2
        rangeOffsetsOfInterest = rangeOffsets[loIndex:hiIndex] # get all three adjacent ranges and check whether merging is possible
        for rangeOffset in rangeOffsetsOfInterest:
            mergedMemRange = self.ranges[rangeOffset].merge(newMemRange)
            if mergedMemRange is not None:
                self.ranges.pop(rangeOffset)
                newMemRange = mergedMemRange
                
        self.ranges[newMemRange.offset] = newMemRange
        
    def _findRange(self, offset):
        rangeOffsets = self.ranges.keys()
        rangeOffsets.sort()
        index = findItemInList(rangeOffsets, offset)[0]
        return index, rangeOffsets