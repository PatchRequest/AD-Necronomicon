from __future__ import division
from __future__ import print_function
import random
import inspect
from struct import pack, unpack_from, calcsize
from six import with_metaclass, PY3

from libs import LOG
from libs.dcerpc.v5.enum import Enum
from libs.uuid import uuidtup_to_bin

  
  
  
  
  

class NDR(object):
    """
    This will be the base class for all DCERPC NDR Types and represents a NDR Primitive Type
    """
    referent       = ()
    commonHdr      = ()
    commonHdr64    = ()
    structure      = ()
    structure64    = ()
    align          = 4
    item           = None
    _isNDR64       = False

    def __init__(self, data = None, isNDR64 = False):
        object.__init__(self)
        self._isNDR64 = isNDR64
        self.fields = {}

        if isNDR64 is True:
            if self.commonHdr64 != ():
                self.commonHdr = self.commonHdr64
            if self.structure64 != ():
                self.structure = self.structure64
            if hasattr(self, 'align64'):
                self.align = self.align64

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
            if self.isNDR(fieldTypeOrClass):
               self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64)
            elif fieldTypeOrClass == ':':
               self.fields[fieldName] = b''
            elif len(fieldTypeOrClass.split('=')) == 2: 
               try:
                   self.fields[fieldName] = eval(fieldTypeOrClass.split('=')[1])
               except:
                   self.fields[fieldName] = None
            else:
               self.fields[fieldName] = []

        if data is not None:
            self.fromString(data)

    def changeTransferSyntax(self, newSyntax): 
        NDR64Syntax = uuidtup_to_bin(('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
        if newSyntax == NDR64Syntax:
            if self._isNDR64 is False:
                  
                self._isNDR64 = True
                for fieldName in list(self.fields.keys()):
                    if isinstance(self.fields[fieldName], NDR):
                        self.fields[fieldName].changeTransferSyntax(newSyntax)
                  
                if self.commonHdr64 != ():
                    self.commonHdr = self.commonHdr64
                if self.structure64 != ():
                    self.structure = self.structure64
                if hasattr(self, 'align64'):
                    self.align = self.align64
                  
                  
                  
                for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
                    if isinstance(self.fields[fieldName], NDR):
                        if fieldTypeOrClass != self.fields[fieldName].__class__ and isinstance(self.fields[fieldName], NDRPOINTERNULL) is False:
                            backupData = self[fieldName]
                            self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64)
                            if 'Data' in self.fields[fieldName].fields:
                                self.fields[fieldName].fields['Data'] = backupData
                            else:
                                self[fieldName] = backupData
  
        else:
            if self._isNDR64 is True:
                  
                raise Exception('Shouldn\'t be here')

    def __setitem__(self, key, value):
        if isinstance(value, NDRPOINTERNULL):
            value = NDRPOINTERNULL(isNDR64 = self._isNDR64)
            if isinstance(self.fields[key], NDRPOINTER):
                self.fields[key] = value
            elif 'Data' in self.fields[key].fields:
                if isinstance(self.fields[key].fields['Data'], NDRPOINTER):
                    self.fields[key].fields['Data'] = value
        elif isinstance(value, NDR):
              
              
            if self.fields[key].__class__.__name__ == value.__class__.__name__:
                self.fields[key] = value
            elif isinstance(self.fields[key]['Data'], NDR):
                if self.fields[key]['Data'].__class__.__name__ == value.__class__.__name__:
                    self.fields[key]['Data'] = value
                else:
                    LOG.error("Can't setitem with class specified, should be %s" % self.fields[key]['Data'].__class__.__name__)
            else:
                LOG.error("Can't setitem with class specified, should be %s" % self.fields[key].__class__.__name__)
        elif isinstance(self.fields[key], NDR):
            self.fields[key]['Data'] = value
        else:
            self.fields[key] = value

    def __getitem__(self, key):
        if isinstance(self.fields[key], NDR):
            if 'Data' in self.fields[key].fields:
                return self.fields[key]['Data']
        return self.fields[key]

    def __str__(self):
        return self.getData()

    def __len__(self):
          
        return len(self.getData())

    def getDataLen(self, data, offset=0):
        return len(data) - offset

    @staticmethod
    def isNDR(field):
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDR):
                return True
        return False

    def dumpRaw(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        ind = ' '*indent
        print("\n%s" % msg)
        for field in self.commonHdr+self.structure+self.referent:
            i = field[0] 
            if i in self.fields:
                if isinstance(self.fields[i], NDR):
                    self.fields[i].dumpRaw('%s%s:{' % (ind,i), indent = indent + 4)
                    print("%s}" % ind)

                elif isinstance(self.fields[i], list):
                    print("%s[" % ind)
                    for num,j in enumerate(self.fields[i]):
                       if isinstance(j, NDR):
                           j.dumpRaw('%s%s:' % (ind,i), indent = indent + 4)
                           print("%s," % ind)
                       else:
                           print("%s%s: {%r}," % (ind, i, j))
                    print("%s]" % ind)

                else:
                    print("%s%s: {%r}" % (ind,i,self[i]))

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print("%s" % msg, end=' ')
        for fieldName, fieldType in self.commonHdr+self.structure+self.referent:
            if fieldName in self.fields:
                if isinstance(self.fields[fieldName], NDR):
                    self.fields[fieldName].dump('\n%s%-31s' % (ind, fieldName+':'), indent = indent + 4),
                else:
                    print(" %r" % (self[fieldName]), end=' ')

    def getAlignment(self):
        return self.align

    @staticmethod
    def calculatePad(fieldType, soFar):
        if isinstance(fieldType, str):
            try:
                alignment = calcsize(fieldType.split('=')[0])
            except:
                alignment = 0
        else:
            alignment = 0

        if alignment > 0:
            pad = (alignment - (soFar % alignment)) % alignment
        else:
            pad = 0

        return pad

    def getData(self, soFar = 0):
        data = b''
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                  

                  
                  
                  
                  
                  
                  
                  
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xbf'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)

                data += res
                soFar += len(res)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def fromString(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                  

                  
                  
                  
                  
                  
                  
                  
                offset += self.calculatePad(fieldTypeOrClass, offset)

                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise
        return offset - offset0

    def pack(self, fieldName, fieldTypeOrClass, soFar = 0):
        if isinstance(self.fields[fieldName], NDR):
            return self.fields[fieldName].getData(soFar)

        data = self.fields[fieldName]
          
        if fieldTypeOrClass[:1] == '_':
            return b''

          
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            try:
                return self.pack(fieldName, two[0], soFar)
            except:
                self.fields[fieldName] = eval(two[1], {}, self.fields)
                return self.pack(fieldName, two[0], soFar)

        if data is None:
            raise Exception('Trying to pack None')

          
        if fieldTypeOrClass[:1] == ':':
            if hasattr(data, 'getData'):
                return data.getData()
            return data

          
        return pack(fieldTypeOrClass, data)

    def unpack(self, fieldName, fieldTypeOrClass, data, offset=0):
        if isinstance(self.fields[fieldName], NDR):
            return self.fields[fieldName].fromString(data, offset)

          
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            return self.unpack(fieldName, two[0], data, offset)

          
        if fieldTypeOrClass == ':':
            if isinstance(fieldTypeOrClass, NDR):
                return self.fields[fieldName].fromString(data, offset)
            else:
                dataLen = self.getDataLen(data, offset)
                self.fields[fieldName] =  data[offset:offset+dataLen]
                return dataLen

          
        self.fields[fieldName] = unpack_from(fieldTypeOrClass, data, offset)[0]

        return calcsize(fieldTypeOrClass)

    def calcPackSize(self, fieldTypeOrClass, data):
        if isinstance(fieldTypeOrClass, str) is False:
            return len(data)

          
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            return self.calcPackSize(two[0], data)

          
        if fieldTypeOrClass[:1] == ':':
            return len(data)

          
        return calcsize(fieldTypeOrClass)

    def calcUnPackSize(self, fieldTypeOrClass, data, offset=0):
        if isinstance(fieldTypeOrClass, str) is False:
            return len(data) - offset

          
        two = fieldTypeOrClass.split('=')
        if len(two) >= 2:
            return self.calcUnPackSize(two[0], data, offset)

          
        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            return len(data) - offset

          
        if fieldTypeOrClass[:1] == ':':
            return len(data) - offset

          
        return calcsize(fieldTypeOrClass)

  
class NDRSMALL(NDR):
    align = 1
    structure = (
        ('Data', 'b=0'),
    )

class NDRUSMALL(NDR):
    align = 1
    structure = (
        ('Data', 'B=0'),
    )

class NDRBOOLEAN(NDRSMALL):
    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print(msg, end=' ')

        if self['Data'] > 0:
            print(" TRUE")
        else:
            print(" FALSE")

class NDRCHAR(NDR):
    align = 1
    structure = (
        ('Data', 'c'),
    )

class NDRSHORT(NDR):
    align = 2
    structure = (
        ('Data', '<h=0'),
    )

class NDRUSHORT(NDR):
    align = 2
    structure = (
        ('Data', '<H=0'),
    )

class NDRLONG(NDR):
    align = 4
    structure = (
        ('Data', '<l=0'),
    )

class NDRULONG(NDR):
    align = 4
    structure = (
        ('Data', '<L=0'),
    )

class NDRHYPER(NDR):
    align = 8
    structure = (
        ('Data', '<q=0'),
    )

class NDRUHYPER(NDR):
    align = 8
    structure = (
        ('Data', '<Q=0'),
    )

class NDRFLOAT(NDR):
    align = 4
    structure = (
        ('Data', '<f=0'),
    )

class NDRDOUBLEFLOAT(NDR):
    align = 8
    structure = (
        ('Data', '<d=0'),
    )

class EnumType(type):
    def __getattr__(self, attr):
        return self.enumItems[attr].value

class NDRENUM(with_metaclass(EnumType, NDR)):
    align = 2
    align64 = 4
    structure = (
        ('Data', '<H'),
    )

      
      
      
      
    structure64 = (
        ('Data', '<L'),
    )
      
    class enumItems(Enum):
        pass

    def __setitem__(self, key, value):
       if isinstance(value, Enum):
           self['Data'] = value.value
       else:
           return NDR.__setitem__(self,key,value)

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print(msg, end=' ')

        print(" %s" % self.enumItems(self.fields['Data']).name, end=' ')

  
class NDRCONSTRUCTEDTYPE(NDR):
    @staticmethod
    def isPointer(field):
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDRPOINTER):
                return True
        return False

    @staticmethod
    def isUnion(field):
        if inspect.isclass(field):
            myClass = field
            if issubclass(myClass, NDRUNION):
                return True
        return False

    def getDataReferents(self, soFar = 0):
        data = b''
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
               data += self.fields[fieldName].getDataReferents(len(data)+soFar)
               data += self.fields[fieldName].getDataReferent(len(data)+soFar)
        return data

    def getDataReferent(self, soFar=0):
        data = b''
        soFar0 = soFar
        if hasattr(self,'referent') is False:
            return b''

        if 'ReferentID' in self.fields:
            if self['ReferentID'] == 0:
                return b''

        for fieldName, fieldTypeOrClass in self.referent:
            try:
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
                      
                      
                    if self._isNDR64:
                        arrayItemSize = 8
                        arrayPackStr = '<Q'
                    else:
                        arrayItemSize = 4
                        arrayPackStr = '<L'

                      
                      
                      
                      
                      
                      
                    pad0 = (arrayItemSize - (soFar % arrayItemSize)) % arrayItemSize
                    if pad0 > 0:
                        soFar += pad0
                        arrayPadding = b'\xef'*pad0
                    else:
                        arrayPadding = b''
                      
                    soFar += arrayItemSize
                    data = self.fields[fieldName].getData(soFar)
                    data = arrayPadding + pack(arrayPackStr, self.getArrayMaximumSize(fieldName)) + data
                else:
                    pad = self.calculatePad(fieldTypeOrClass, soFar)
                    if pad > 0:
                        soFar += pad
                        data += b'\xcc'*pad

                    data += self.pack(fieldName, fieldTypeOrClass, soFar)

                  
                if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                    data += self.fields[fieldName].getDataReferents(soFar0 + len(data))
                    data += self.fields[fieldName].getDataReferent(soFar0 + len(data))
                soFar = soFar0 + len(data)

            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def calcPackSize(self, fieldTypeOrClass, data):
        if isinstance(fieldTypeOrClass, str) is False:
            return len(data)

          
        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            answer = 0
            for each in data:
                if self.isNDR(self.item):
                    item = ':'
                else:
                    item = self.item
                answer += self.calcPackSize(item, each)
            return answer
        else:
            return NDR.calcPackSize(self, fieldTypeOrClass, data)

    def getArrayMaximumSize(self, fieldName):
        if self.fields[fieldName].fields['MaximumCount'] is not None and self.fields[fieldName].fields['MaximumCount'] > 0:
            return self.fields[fieldName].fields['MaximumCount']
        else:
            return self.fields[fieldName].getArraySize()

    def getArraySize(self, fieldName, data, offset=0):
        if self._isNDR64:
            arrayItemSize = 8
            arrayUnPackStr = '<Q'
        else:
            arrayItemSize = 4
            arrayUnPackStr = '<L'

        pad = (arrayItemSize - (offset % arrayItemSize)) % arrayItemSize
        offset += pad

        if isinstance(self.fields[fieldName], NDRUniConformantArray):
              
            arraySize = unpack_from(arrayUnPackStr, data, offset)[0]
        elif isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
              
              
            maximumCount = unpack_from(arrayUnPackStr, data, offset)[0]
              
            self.fields[fieldName].fields['MaximumCount'] = maximumCount
              
            arraySize = unpack_from(arrayUnPackStr, data, offset+arrayItemSize*2)[0]
        else:
              
            arraySize = unpack_from(arrayUnPackStr, data, offset+arrayItemSize)[0]

        return arraySize, arrayItemSize+pad

    def fromStringReferents(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                offset += self.fields[fieldName].fromStringReferents(data, offset)
                offset += self.fields[fieldName].fromStringReferent(data, offset)
        return offset - offset0

    def fromStringReferent(self, data, offset=0):
        if hasattr(self, 'referent') is not True:
            return 0

        offset0 = offset

        if 'ReferentID' in self.fields:
            if self['ReferentID'] == 0:
                  
                return 0

        for fieldName, fieldTypeOrClass in self.referent:
            try:
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
                      
                    arraySize, advanceStream = self.getArraySize(fieldName, data, offset)
                    offset += advanceStream

                      
                    self.fields[fieldName].setArraySize(arraySize)
                    size = self.fields[fieldName].fromString(data, offset)
                else:
                      
                    offset += self.calculatePad(fieldTypeOrClass, offset)

                    size = self.unpack(fieldName, fieldTypeOrClass, data, offset)

                if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                    size += self.fields[fieldName].fromStringReferents(data, offset+size)
                    size += self.fields[fieldName].fromStringReferent(data, offset+size)
                offset += size
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

        return offset-offset0

    def calcUnPackSize(self, fieldTypeOrClass, data, offset=0):
        if isinstance(fieldTypeOrClass, str) is False:
            return len(data) - offset

        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            return len(data) - offset
        else:
            return NDR.calcUnPackSize(self, fieldTypeOrClass, data, offset)

  
class NDRArray(NDRCONSTRUCTEDTYPE):
    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        ind = ' '*indent
        if msg != '':
            print(msg, end=' ')

        if isinstance(self['Data'], list):
            print("\n%s[" % ind)
            ind += ' '*4
            for num,j in enumerate(self.fields['Data']):
               if isinstance(j, NDR):
                   j.dump('%s' % ind, indent = indent + 4),
                   print(",") 
               else:
                   print("%s %r," % (ind,j))
            print("%s]" % ind[:-4], end=' ')
        else:
            print(" %r" % self['Data'], end=' ')

    def setArraySize(self, size):
        self.arraySize = size

    def getArraySize(self):
        return self.arraySize

    def changeTransferSyntax(self, newSyntax): 
          
          
        if hasattr(self, 'item') and self.item is not None:
            if self.isNDR(self.item):
                for item in self.fields['Data']:
                    item.changeTransferSyntax(newSyntax)
        return NDRCONSTRUCTEDTYPE.changeTransferSyntax(self, newSyntax)

    def getAlignment(self):
          
          
        align = 0
          
        if hasattr(self, "item") and self.item is not None:
            if self.isNDR(self.item):
                tmpAlign = self.item().getAlignment()
            else:
                tmpAlign = self.calcPackSize(self.item, b'')
            if tmpAlign > align:
                align = tmpAlign
        return align

    def getData(self, soFar = 0):
        data = b''
        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.structure:
            try:
                if self.isNDR(fieldTypeOrClass) is False:
                      
                      
                    pad = self.calculatePad(fieldTypeOrClass, soFar)
                    if pad > 0:
                        soFar += pad
                        data += b'\xca'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def pack(self, fieldName, fieldTypeOrClass, soFar = 0):
          
        two = fieldTypeOrClass.split('*')
        if len(two) == 2:
            answer = b''
            if self.isNDR(self.item):
                item = ':'
                dataClass = self.item
                self.fields['_tmpItem'] = dataClass(isNDR64=self._isNDR64)
            else:
                item = self.item
                dataClass = None
                self.fields['_tmpItem'] = item

            for each in (self.fields[fieldName]):
                pad = self.calculatePad(self.item, len(answer)+soFar)
                if pad > 0:
                    answer += b'\xdd' * pad
                if dataClass is None:
                    if item == 'c' and PY3 and isinstance(each, int):
                          
                        each = bytes([each])
                    answer += pack(item, each)
                else:
                    answer += each.getData(len(answer)+soFar)

            if dataClass is not None:
                for each in self.fields[fieldName]:
                    if isinstance(each, NDRCONSTRUCTEDTYPE):
                        answer += each.getDataReferents(len(answer)+soFar)
                        answer += each.getDataReferent(len(answer)+soFar)

            del(self.fields['_tmpItem'])
            if isinstance(self, NDRUniConformantArray) or isinstance(self, NDRUniConformantVaryingArray):
                  
                self.setArraySize(len(self.fields[fieldName]))
            else:
                self.fields[two[1]] = len(self.fields[fieldName])

            return answer
        else:
            return NDRCONSTRUCTEDTYPE.pack(self, fieldName, fieldTypeOrClass, soFar)

    def fromString(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                if self.isNDR(fieldTypeOrClass) is False:
                      
                      
                    offset += self.calculatePad(fieldTypeOrClass, offset)

                size = self.unpack(fieldName, fieldTypeOrClass, data, offset)
                offset += size
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise
        return offset - offset0

    def unpack(self, fieldName, fieldTypeOrClass, data, offset=0):
          
        two = fieldTypeOrClass.split('*')
        answer = []
        soFarItems = 0
        offset0 = offset
        if len(two) == 2:
            if isinstance(self, NDRUniConformantArray):
                  
                numItems = self.getArraySize()
            elif isinstance(self, NDRUniConformantVaryingArray):
                  
                  
                  
                numItems = self[two[1]]
            else:
                numItems = self[two[1]]

              
            if self.isNDR(self.item):
                item = ':'
                dataClassOrCode = self.item
                self.fields['_tmpItem'] = dataClassOrCode(isNDR64=self._isNDR64)
            else:
                item = self.item
                dataClassOrCode = None
                self.fields['_tmpItem'] = item

            nsofar = 0
            while numItems and soFarItems < len(data) - offset:
                pad = self.calculatePad(self.item, soFarItems+offset)
                if pad > 0:
                    soFarItems +=pad
                if dataClassOrCode is None:
                    nsofar = soFarItems + calcsize(item)
                    answer.append(unpack_from(item, data, offset+soFarItems)[0])
                else:
                    itemn = dataClassOrCode(isNDR64=self._isNDR64)
                    size = itemn.fromString(data, offset+soFarItems)
                    answer.append(itemn)
                    nsofar += size + pad
                numItems -= 1
                soFarItems = nsofar

            if dataClassOrCode is not None and isinstance(dataClassOrCode(), NDRCONSTRUCTEDTYPE):
                  
                answer2 = []
                for itemn in answer:
                    size = itemn.fromStringReferents(data, soFarItems+offset)
                    soFarItems += size
                    size = itemn.fromStringReferent(data, soFarItems+offset)
                    soFarItems += size
                    answer2.append(itemn)
                answer = answer2
                del answer2

            del(self.fields['_tmpItem'])

            self.fields[fieldName] = answer
            return soFarItems + offset - offset0
        else:
            return NDRCONSTRUCTEDTYPE.unpack(self, fieldName, fieldTypeOrClass, data, offset)

class NDRUniFixedArray(NDRArray):
    structure = (
        ('Data',':'),
    )

  
class NDRUniConformantArray(NDRArray):
    item = 'c'
    structure = (
          
        ('Data', '*MaximumCount'),
    )

    structure64 = (
          
        ('Data', '*MaximumCount'),
    )

    def __init__(self, data = None, isNDR64 = False):
        NDRArray.__init__(self, data, isNDR64)
          
        self.fields['MaximumCount'] = 0

    def __setitem__(self, key, value):
        self.fields['MaximumCount'] = None
        return NDRArray.__setitem__(self, key, value)


  
class NDRUniVaryingArray(NDRArray):
    item = 'c'
    structure = (
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)'),
        ('Data','*ActualCount'),
    )
    structure64 = (
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)'),
        ('Data','*ActualCount'),
    )

    def __setitem__(self, key, value):
        self.fields['ActualCount'] = None
        return NDRArray.__setitem__(self, key, value)

  
class NDRUniConformantVaryingArray(NDRArray):
    item = 'c'
    commonHdr = (
          
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)'),
    )
    commonHdr64 = (
          
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)'),
    )

    structure = (
        ('Data','*ActualCount'),
    )

    def __init__(self, data = None, isNDR64 = False):
        NDRArray.__init__(self, data, isNDR64)
          
        self.fields['MaximumCount'] = 0

    def __setitem__(self, key, value):
        self.fields['MaximumCount'] = None
        self.fields['ActualCount'] = None
        return NDRArray.__setitem__(self, key, value)

    def getData(self, soFar = 0):
        data = b''
        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xcb'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

  

  
class NDRVaryingString(NDRUniVaryingArray):
    def getData(self, soFar = 0):
          
          
          
        if self["Data"][-1:] != b'\x00':
            if PY3 and isinstance(self["Data"],list) is False:
                self["Data"] = self["Data"] + b'\x00'
            else:
                self["Data"] = b''.join(self["Data"]) + b'\x00'
        return NDRUniVaryingArray.getData(self, soFar)

    def fromString(self, data, offset = 0):
        ret = NDRUniVaryingArray.fromString(self, data, offset)
          
        self["Data"] = self["Data"][:-1] 
        return ret

  
class NDRConformantVaryingString(NDRUniConformantVaryingArray):
    pass

  
  
  
class NDRSTRUCT(NDRCONSTRUCTEDTYPE):
    def getData(self, soFar = 0):
        data = b''
        arrayPadding = b''
        soFar0 = soFar
          
          
          
          
          
          
          
          
          
          
          
          
        lastItem = (self.commonHdr+self.structure)[-1][0]
        if isinstance(self.fields[lastItem], NDRUniConformantArray) or isinstance(self.fields[lastItem], NDRUniConformantVaryingArray):
              
              
            if self._isNDR64:
                arrayItemSize = 8
                arrayPackStr = '<Q'
            else:
                arrayItemSize = 4
                arrayPackStr = '<L'

              
              
              
              
              
              
            pad0 = (arrayItemSize - (soFar % arrayItemSize)) % arrayItemSize 
            if pad0 > 0:
                soFar += pad0
                arrayPadding = b'\xee'*pad0
            else:
                arrayPadding = b''
              
            soFar += arrayItemSize
        else:
            arrayItemSize = 0

          
          
          
          
        alignment = self.getAlignment()

        if alignment > 0:
            pad = (alignment - (soFar % alignment)) % alignment
            if pad > 0:
                soFar += pad
                data += b'\xAB'*pad

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName], NDRUniConformantVaryingArray):
                    res = self.fields[fieldName].getData(soFar)
                    if isinstance(self, NDRPOINTER):
                        pointerData = data[:arrayItemSize]
                        data = data[arrayItemSize:]
                        data = pointerData + arrayPadding + pack(arrayPackStr ,self.getArrayMaximumSize(fieldName)) + data
                    else:
                        data = arrayPadding + pack(arrayPackStr, self.getArrayMaximumSize(fieldName)) + data
                    arrayPadding = b''
                    arrayItemSize = 0
                else:
                    res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data) + len(arrayPadding) + arrayItemSize
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

          
          
          
          
          
          

          
          
          
          
          
          
          
          
          
  
  
  
  
  
  
  
  
        return data

    def fromString(self, data, offset = 0 ):
        offset0 = offset
          
          
          
          
          
          
          
          
          
          
          
          
        lastItem = (self.commonHdr+self.structure)[-1][0]

          
          
          
        if isinstance(self, NDRPOINTER):
            structureFields = self.structure

            alignment = self.getAlignment()
            if alignment > 0:
                offset += (alignment - (offset % alignment)) % alignment

            for fieldName, fieldTypeOrClass in self.commonHdr:
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
        else:
            structureFields = self.commonHdr+self.structure

        if isinstance(self.fields[lastItem], NDRUniConformantArray) or isinstance(self.fields[lastItem], NDRUniConformantVaryingArray):
              
              
            if self._isNDR64:
                arrayItemSize = 8
                arrayUnPackStr = '<Q'
            else:
                arrayItemSize = 4
                arrayUnPackStr = '<L'

              
              
              
              
              
              
            offset += (arrayItemSize - (offset % arrayItemSize)) % arrayItemSize

              
            if isinstance(self.fields[lastItem], NDRUniConformantArray):
                  
                arraySize = unpack_from(arrayUnPackStr, data, offset)[0]
                self.fields[lastItem].setArraySize(arraySize)
            else:
                  
                maximumCount = unpack_from(arrayUnPackStr, data, offset)[0]
                self.fields[lastItem].fields['MaximumCount'] = maximumCount

            offset += arrayItemSize

          
          
          
          
        alignment = self.getAlignment()
        if alignment > 0:
            offset += (alignment - (offset % alignment)) % alignment

        for fieldName, fieldTypeOrClass in structureFields:
            try:
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

        return offset - offset0

    def getAlignment(self):
          
          
          
          
          
          

          

          
          
          
          
          
          
          
          
          

          
          
          

        align = 0
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
            if isinstance(self.fields[fieldName], NDR):
                tmpAlign = self.fields[fieldName].getAlignment()
            else:
                tmpAlign = self.calcPackSize(fieldTypeOrClass, b'')
            if tmpAlign > align:
                align = tmpAlign
        return align

  
class NDRUNION(NDRCONSTRUCTEDTYPE):
    commonHdr = (
        ('tag', NDRUSHORT),
    )
    commonHdr64 = (
        ('tag', NDRULONG),
    )
   
    union = {
          
          
          
    }
    def __init__(self, data = None, isNDR64=False, topLevel = False):
          
        self.topLevel = topLevel
        self._isNDR64 = isNDR64
        self.fields = {}

        if isNDR64 is True:
            if self.commonHdr64 != ():
                self.commonHdr = self.commonHdr64
            if self.structure64 != ():
                self.structure = self.structure64
            if hasattr(self, 'align64'):
                self.align = self.align64

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
            if self.isNDR(fieldTypeOrClass):
               if self.isPointer(fieldTypeOrClass):
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64, topLevel = topLevel)
               elif self.isUnion(fieldTypeOrClass):
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64, topLevel = topLevel)
               else:
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64)
            elif fieldTypeOrClass == ':':
               self.fields[fieldName] = None
            elif len(fieldTypeOrClass.split('=')) == 2: 
               try:
                   self.fields[fieldName] = eval(fieldTypeOrClass.split('=')[1])
               except:
                   self.fields[fieldName] = None
            else:
               self.fields[fieldName] = 0

        if data is not None:
            self.fromString(data)

    def __setitem__(self, key, value):
        if key == 'tag':
              
            self.structure = ()
            if value in self.union:
                self.structure = (self.union[value]),
                  
                self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
                self.fields['tag']['Data'] = value
            else:
                  
                if 'default' in self.union:
                    if self.union['default'] is None:
                        self.structure = ()
                    else:
                        self.structure = (self.union['default']),
                          
                        self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
                    self.fields['tag']['Data'] = 0xffff
                else:
                    raise Exception("Unknown tag %d for union!" % value)
        else:
            return NDRCONSTRUCTEDTYPE.__setitem__(self,key,value)

    def getData(self, soFar = 0):
        data = b''
        soFar0 = soFar

          
        alignment = self.getAlignment()
        if alignment > 0:
            pad = (alignment - (soFar % alignment)) % alignment
        else:
            pad = 0
        if pad > 0:
            soFar += pad
            data += b'\xbc'*pad

        for fieldName, fieldTypeOrClass in self.commonHdr:
            try:
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xbb'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

          
          
          
          
          
        if self._isNDR64:
            align = 8
        else:
            if hasattr(self, 'notAlign'):
                align = 1
            else:
                align = 4

        pad = (align - (soFar % align)) % align
        if pad > 0:
            data += b'\xbd'*pad
            soFar += pad

        if self.structure == ():
            return data

        for fieldName, fieldTypeOrClass in self.structure:
            try:
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xbe'*pad

                res = self.pack(fieldName, fieldTypeOrClass, soFar)
                data += res
                soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def fromString(self, data, offset=0):
        offset0 = offset
          
        alignment = self.getAlignment()
        if alignment > 0:
            pad = (alignment - (offset % alignment)) % alignment
        else:
            pad = 0
        if pad > 0:
            offset += pad

        if len(data)-offset > 4:
              
              
            tagtype = self.commonHdr[0][1].structure[0][1].split('=')[0]
            tag = unpack_from(tagtype, data, offset)[0]
            if tag in self.union:
                self.structure = (self.union[tag]),
                self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
            else:
                  
                if 'default' in self.union:
                    if self.union['default'] is None:
                        self.structure = ()
                    else:
                        self.structure = (self.union['default']),
                          
                        self.__init__(None, isNDR64=self._isNDR64, topLevel = self.topLevel)
                    self.fields['tag']['Data'] = 0xffff
                else:
                    raise Exception("Unknown tag %d for union!" % tag)

        for fieldName, fieldTypeOrClass in self.commonHdr:
            try:
                offset += self.calculatePad(fieldTypeOrClass, offset)
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

          
          
          
          
          
        if self._isNDR64:
            align = 8
        else:
            if hasattr(self, 'notAlign'):
                align = 1
            else:
                align = 4

        offset += (align - (offset % align)) % align

        if self.structure == ():
            return offset-offset0

        for fieldName, fieldTypeOrClass in self.structure:
            try:
                offset += self.calculatePad(fieldTypeOrClass, offset)
                offset += self.unpack(fieldName, fieldTypeOrClass, data, offset)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

        return offset - offset0

    def getAlignment(self):
          
          
          
          
          
        align = 0
        if self._isNDR64:
            fields =  self.commonHdr+self.structure
        else: 
            fields =  self.commonHdr
        for fieldName, fieldTypeOrClass in fields:
            if isinstance(self.fields[fieldName], NDR):
                tmpAlign = self.fields[fieldName].getAlignment()
            else:
                tmpAlign = self.calcPackSize(fieldTypeOrClass, b'')
            if tmpAlign > align:
                align = tmpAlign

        if self._isNDR64:
            for fieldName, fieldTypeOrClass in self.union.values():
                tmpAlign = fieldTypeOrClass(isNDR64 = self._isNDR64).getAlignment()
                if tmpAlign > align:
                    align = tmpAlign
        return align
   
  

  
class NDRPOINTERNULL(NDR):
    align = 4
    align64 = 8
    structure = (
        ('Data', '<L=0'),
    )
    structure64 = (
        ('Data', '<Q=0'),
    )

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print("%s" % msg, end=' ')
          
        print(" NULL", end=' ')

NULL = NDRPOINTERNULL()

class NDRPOINTER(NDRSTRUCT):
    align = 4
    align64 = 8
    commonHdr = (
        ('ReferentID','<L=0xff'),
    )
    commonHdr64 = (
        ('ReferentID','<Q=0xff'),
    )

    referent = (
          
        ('Data',':'),
    )
    def __init__(self, data = None, isNDR64=False, topLevel = False):
        NDRSTRUCT.__init__(self,None, isNDR64=isNDR64)
          
          
          
          
          
        if topLevel is True:
            self.structure = self.referent
            self.referent = ()
       
        if data is None:
            self.fields['ReferentID'] = random.randint(1,65535)
        else:
           self.fromString(data)

    def __setitem__(self, key, value):
        if (key in self.fields) is False:
              
            return self.fields['Data'].__setitem__(key,value)
        else:
            return NDRSTRUCT.__setitem__(self,key,value)

    def __getitem__(self, key):
        if key in self.fields:
            if isinstance(self.fields[key], NDR):
                if 'Data' in self.fields[key].fields:
                    return self.fields[key]['Data']
            return self.fields[key]
        else:
              
            return self.fields['Data'].__getitem__(key)

    def getData(self, soFar = 0):
          
        data = b''
        pad = self.calculatePad(self.commonHdr[0][1], soFar)
        if pad > 0:
            soFar += pad
            data = b'\xaa'*pad
          
        if self.fields['ReferentID'] == 0:
            if len(self.referent) > 0:
                self['Data'] = b''
            else:
                if self._isNDR64 is True:
                    return data+b'\x00'*8
                else:
                    return data+b'\x00'*4

        return data + NDRSTRUCT.getData(self, soFar)

    def fromString(self, data, offset=0):
          
        pad = self.calculatePad(self.commonHdr[0][1], offset)
        offset += pad

          
        if self._isNDR64 is True:
            unpackStr = '<Q'
        else:
            unpackStr = '<L'

        if unpack_from(unpackStr, data, offset)[0] == 0:
              
            self['ReferentID'] = 0
            self.fields['Data'] = b''
            if self._isNDR64 is True:
                return pad + 8
            else:
                return pad + 4
        else:
            retVal = NDRSTRUCT.fromString(self, data, offset)
            return retVal + pad

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print("%s" % msg, end=' ')
          
        if isinstance(self.fields['Data'], NDR):
            self.fields['Data'].dump('', indent = indent)
        else:
            if self['ReferentID'] == 0:
                print(" NULL", end=' ')
            else:
                print(" %r" % (self['Data']), end=' ')

    def getAlignment(self):
        if self._isNDR64 is True:
            return 8
        else:
            return 4


  

  
  

class PNDRUniConformantVaryingArray(NDRPOINTER):
    referent = (
        ('Data', NDRUniConformantVaryingArray),
    )

class PNDRUniConformantArray(NDRPOINTER):
    referent = (
        ('Data', NDRUniConformantArray),
    )
    def __init__(self, data = None, isNDR64 = False, topLevel = False):
        NDRPOINTER.__init__(self,data,isNDR64,topLevel)

class NDRCALL(NDRCONSTRUCTEDTYPE):
      
      
      
    referent       = ()
    commonHdr      = ()
    commonHdr64    = ()
    structure      = ()
    structure64    = ()
    align          = 4
    def __init__(self, data = None, isNDR64 = False):
        self._isNDR64 = isNDR64
        self.fields = {}

        if isNDR64 is True:
            if self.commonHdr64 != ():
                self.commonHdr = self.commonHdr64
            if self.structure64 != ():
                self.structure = self.structure64
            if hasattr(self, 'align64'):
                self.align = self.align64

        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure+self.referent:
            if self.isNDR(fieldTypeOrClass):
               if self.isPointer(fieldTypeOrClass):
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64, topLevel = True)
               elif self.isUnion(fieldTypeOrClass):
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64, topLevel = True)
               else:
                   self.fields[fieldName] = fieldTypeOrClass(isNDR64 = self._isNDR64)
            elif fieldTypeOrClass == ':':
               self.fields[fieldName] = None
            elif len(fieldTypeOrClass.split('=')) == 2:
               try:
                   self.fields[fieldName] = eval(fieldTypeOrClass.split('=')[1])
               except:
                   self.fields[fieldName] = None
            else:
               self.fields[fieldName] = 0

        if data is not None:
            self.fromString(data)

    def dump(self, msg = None, indent = 0):
        NDRCONSTRUCTEDTYPE.dump(self, msg, indent)
        print('\n\n')

    def getData(self, soFar = 0):
        data = b''
        soFar0 = soFar
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                pad = self.calculatePad(fieldTypeOrClass, soFar)
                if pad > 0:
                    soFar += pad
                    data += b'\xab'*pad

                  
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName],
                              NDRUniConformantVaryingArray):
                      
                    if self._isNDR64:
                        pad = (8 - (soFar % 8)) % 8
                    else:
                        pad = (4 - (soFar % 4)) % 4
                      
                    res = self.pack(fieldName, fieldTypeOrClass, soFar+pad)
                      
                    arraySize = self.getArrayMaximumSize(fieldName)
                    if self._isNDR64:
                        pad = (8 - (soFar % 8)) % 8
                        data += b'\xce'*pad + pack('<Q', arraySize) + res
                    else:
                        pad = (4 - (soFar % 4)) % 4
                        data += b'\xce'*pad + pack('<L', arraySize) + res
                else:
                    data += self.pack(fieldName, fieldTypeOrClass, soFar)

                soFar = soFar0 + len(data)
                  
                  
                  
                  
                if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                    data += self.fields[fieldName].getDataReferents(soFar)
                    soFar = soFar0 + len(data)
                    data += self.fields[fieldName].getDataReferent(soFar)
                    soFar = soFar0 + len(data)
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error packing field '%s | %s' in %s" % (fieldName, fieldTypeOrClass, self.__class__))
                raise

        return data

    def fromString(self, data, offset=0):
        offset0 = offset
        for fieldName, fieldTypeOrClass in self.commonHdr+self.structure:
            try:
                  
                if isinstance(self.fields[fieldName], NDRUniConformantArray) or isinstance(self.fields[fieldName],
                              NDRUniConformantVaryingArray):
                      
                    arraySize, advanceStream = self.getArraySize(fieldName, data, offset)
                    self.fields[fieldName].setArraySize(arraySize)
                    offset += advanceStream

                size = self.unpack(fieldName, fieldTypeOrClass, data, offset)

                  
                if isinstance(self.fields[fieldName], NDRCONSTRUCTEDTYPE):
                    size += self.fields[fieldName].fromStringReferents(data, offset+size)
                    size += self.fields[fieldName].fromStringReferent(data, offset+size)
                offset += size
            except Exception as e:
                LOG.error(str(e))
                LOG.error("Error unpacking field '%s | %s | %r'" % (fieldName, fieldTypeOrClass, data[offset:offset+256]))
                raise

        return offset - offset0

  
NDRTLSTRUCT = NDRCALL

class UNKNOWNDATA(NDR):
    align = 1
    structure = (
        ('Data', ':'),
    )
