from __future__ import division
from __future__ import print_function
from struct import unpack, calcsize, pack
from functools import partial
import collections
import logging
import six

from libs.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER, NDRUniConformantVaryingArray, NDRUNION, \
    NDRENUM
from libs.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, IRemUnknown, PMInterfacePointer, INTERFACE, \
    PMInterfacePointer_ARRAY, BYTE_ARRAY, PPMInterfacePointer, OBJREF_CUSTOM
from libs.dcerpc.v5.dcom.oaut import BSTR
from libs.dcerpc.v5.dtypes import ULONG, DWORD, NULL, LPWSTR, LONG, HRESULT, PGUID, LPCSTR, GUID
from libs.dcerpc.v5.enum import Enum
from libs.dcerpc.v5.rpcrt import DCERPCException
from libs import hresult_errors, LOG
from libs.uuid import string_to_bin, uuidtup_to_bin
from libs.structure import Structure, hexdump


def format_structure(d, level=0):
    x = ""
    if isinstance(d, collections.Mapping):
        lenk = max([len(str(x)) for x in list(d.keys())])
        for k, v in list(d.items()):
            key_text = "\n" + " "*level + " "*(lenk - len(str(k))) + str(k)
            x += key_text + ": " + format_structure(v, level=level+lenk)
    elif isinstance(d, collections.Iterable) and not isinstance(d, str):
        for e in d:
            x += "\n" + " "*level + "- " + format_structure(e, level=level+4)
    else:
        x = str(d)
    return x
try:
    from collections import OrderedDict
except:
    try:
        from ordereddict.ordereddict import OrderedDict
    except:
        from ordereddict import OrderedDict

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        if self.error_code in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1] 
            return 'WMI SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
              
            try:
                return 'WMI Session Error: code: 0x%x - %s' % (self.error_code, WBEMSTATUS.enumItems(self.error_code).name)
            except:
                return 'WMI SessionError: unknown error code: 0x%x' % self.error_code

  
  
  
WBEM_FLAVOR_FLAG_PROPAGATE_O_INSTANCE      = 0x01
WBEM_FLAVOR_FLAG_PROPAGATE_O_DERIVED_CLASS = 0x02
WBEM_FLAVOR_NOT_OVERRIDABLE                = 0x10
WBEM_FLAVOR_ORIGIN_PROPAGATED              = 0x20
WBEM_FLAVOR_ORIGIN_SYSTEM                  = 0x40
WBEM_FLAVOR_AMENDED                        = 0x80

  
OBJECT_FLAGS = 'B=0'

  
SIGNATURE = '<L=0x12345678'

  
OBJECT_ENCODING_LENGTH = '<L=0'

  
ENCODING_LENGTH = '<L=0'

  
ENCODED_STRING_FLAG = 'B=0'

  
RESERVED_OCTET = 'B=0'

  
NDTABLE_VALUE_TABLE_LENGTH = '<L=0'

  
DICTIONARY_REFERENCE = {
    0 : '"',
    1 : 'key',
    2 : 'NADA',
    3 : 'read',
    4 : 'write',
    5 : 'volatile',
    6 : 'provider',
    7 : 'dynamic',
    8 : 'cimwin32',
    9 : 'DWORD',
   10 : 'CIMTYPE',
}

class ENCODED_STRING(Structure):
    commonHdr = (
        ('Encoded_String_Flag', ENCODED_STRING_FLAG),
    )

    tascii = (
        ('Character', 'z'),
    )

    tunicode = (
        ('Character', 'u'),
    )

    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is not None:
              
            self.fromString(data)
            self.structure = ()
            self.isUnicode = False
            if len(data) > 1:
                if self['Encoded_String_Flag'] == 0:
                    self.structure += self.tascii
                      
                    index = data[1:].find(b'\x00')
                    data  = data[:index+1+1]
                else:
                    self.structure = self.tunicode
                    self.isUnicode = True

                self.fromString(data)
        else:
            self.structure = self.tascii
            self.data = None

    def __getitem__(self, key):
        if key == 'Character' and self.isUnicode:
            return self.fields['Character'].decode('utf-16le')
        return Structure.__getitem__(self, key)


  
DEC_SERVER_NAME = ENCODED_STRING

  
DEC_NAMESPACE_NAME = ENCODED_STRING

  
class DECORATION(Structure):
    structure = (
        ('DecServerName', ':', DEC_SERVER_NAME),
        ('DecNamespaceName', ':', DEC_NAMESPACE_NAME),
    )

  
HEAPREF = '<L=0'

  
HEAP_STRING_REF = HEAPREF

  
CLASS_NAME_REF = HEAP_STRING_REF

  
class CLASS_HEADER(Structure):
    structure = (
        ('EncodingLength', ENCODING_LENGTH),
        ('ReservedOctet', RESERVED_OCTET),
        ('ClassNameRef', CLASS_NAME_REF),
        ('NdTableValueTableLength', NDTABLE_VALUE_TABLE_LENGTH),
    )

  
class DERIVATION_LIST(Structure):
    structure = (
        ('EncodingLength', ENCODING_LENGTH),
        ('_ClassNameEncoding','_-ClassNameEncoding', 'self["EncodingLength"]-4'),
        ('ClassNameEncoding', ':'),
    )

  
CIM_TYPE = '<L=0'
CIM_ARRAY_FLAG = 0x2000

class EnumType(type):
    def __getattr__(self, attr):
        return self.enumItems[attr].value

class CIM_TYPE_ENUM(Enum):
  
    CIM_TYPE_SINT8      = 16
    CIM_TYPE_UINT8      = 17
    CIM_TYPE_SINT16     = 2
    CIM_TYPE_UINT16     = 18
    CIM_TYPE_SINT32     = 3
    CIM_TYPE_UINT32     = 19
    CIM_TYPE_SINT64     = 20
    CIM_TYPE_UINT64     = 21
    CIM_TYPE_REAL32     = 4
    CIM_TYPE_REAL64     = 5
    CIM_TYPE_BOOLEAN    = 11
    CIM_TYPE_STRING     = 8
    CIM_TYPE_DATETIME   = 101
    CIM_TYPE_REFERENCE  = 102
    CIM_TYPE_CHAR16     = 103
    CIM_TYPE_OBJECT     = 13
    CIM_ARRAY_SINT8     = 8208
    CIM_ARRAY_UINT8     = 8209
    CIM_ARRAY_SINT16    = 8194
    CIM_ARRAY_UINT16    = 8210
    CIM_ARRAY_SINT32    = 8195
    CIM_ARRAY_UINT32    = 8201
    CIM_ARRAY_SINT64    = 8202
    CIM_ARRAY_UINT64    = 8203
    CIM_ARRAY_REAL32    = 8196
    CIM_ARRAY_REAL64    = 8197
    CIM_ARRAY_BOOLEAN   = 8203
    CIM_ARRAY_STRING    = 8200
    CIM_ARRAY_DATETIME  = 8293
    CIM_ARRAY_REFERENCE = 8294
    CIM_ARRAY_CHAR16    = 8295
    CIM_ARRAY_OBJECT    = 8205

CIM_TYPES_REF = {
    CIM_TYPE_ENUM.CIM_TYPE_SINT8.value    : 'b=0',
    CIM_TYPE_ENUM.CIM_TYPE_UINT8.value    : 'B=0',
    CIM_TYPE_ENUM.CIM_TYPE_SINT16.value   : '<h=0',
    CIM_TYPE_ENUM.CIM_TYPE_UINT16.value   : '<H=0',
    CIM_TYPE_ENUM.CIM_TYPE_SINT32.value   : '<l=0',
    CIM_TYPE_ENUM.CIM_TYPE_UINT32.value   : '<L=0',
    CIM_TYPE_ENUM.CIM_TYPE_SINT64.value   : '<q=0',
    CIM_TYPE_ENUM.CIM_TYPE_UINT64.value   : '<Q=0',
    CIM_TYPE_ENUM.CIM_TYPE_REAL32.value   : '<f=0',
    CIM_TYPE_ENUM.CIM_TYPE_REAL64.value   : '<d=0',
    CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value  : '<H=0',
    CIM_TYPE_ENUM.CIM_TYPE_STRING.value   : HEAPREF,
    CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value : HEAPREF,
    CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value: HEAPREF,
    CIM_TYPE_ENUM.CIM_TYPE_CHAR16.value   : '<H=0',
    CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value   : HEAPREF,
}

CIM_TYPE_TO_NAME = {
    CIM_TYPE_ENUM.CIM_TYPE_SINT8.value    : 'sint8',
    CIM_TYPE_ENUM.CIM_TYPE_UINT8.value    : 'uint8',
    CIM_TYPE_ENUM.CIM_TYPE_SINT16.value   : 'sint16',
    CIM_TYPE_ENUM.CIM_TYPE_UINT16.value   : 'uint16',
    CIM_TYPE_ENUM.CIM_TYPE_SINT32.value   : 'sint32',
    CIM_TYPE_ENUM.CIM_TYPE_UINT32.value   : 'uint32',
    CIM_TYPE_ENUM.CIM_TYPE_SINT64.value   : 'sint64',
    CIM_TYPE_ENUM.CIM_TYPE_UINT64.value   : 'uint64',
    CIM_TYPE_ENUM.CIM_TYPE_REAL32.value   : 'real32',
    CIM_TYPE_ENUM.CIM_TYPE_REAL64.value   : 'real64',
    CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value  : 'bool',
    CIM_TYPE_ENUM.CIM_TYPE_STRING.value   : 'string',
    CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value : 'datetime',
    CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value: 'reference',
    CIM_TYPE_ENUM.CIM_TYPE_CHAR16.value   : 'char16',
    CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value   : 'object',
}

CIM_NUMBER_TYPES = (
    CIM_TYPE_ENUM.CIM_TYPE_CHAR16.value, CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value,
    CIM_TYPE_ENUM.CIM_TYPE_SINT8.value, CIM_TYPE_ENUM.CIM_TYPE_UINT8.value,
    CIM_TYPE_ENUM.CIM_TYPE_SINT16.value, CIM_TYPE_ENUM.CIM_TYPE_UINT16.value,
    CIM_TYPE_ENUM.CIM_TYPE_SINT32.value, CIM_TYPE_ENUM.CIM_TYPE_UINT32.value,
    CIM_TYPE_ENUM.CIM_TYPE_SINT64.value, CIM_TYPE_ENUM.CIM_TYPE_UINT64.value,
    CIM_TYPE_ENUM.CIM_TYPE_REAL32.value, CIM_TYPE_ENUM.CIM_TYPE_REAL64.value,
)

  
QUALIFIER_NAME = HEAP_STRING_REF

  
QUALIFIER_FLAVOR = 'B=0'

  
QUALIFIER_TYPE = CIM_TYPE

  
class ENCODED_VALUE(Structure):
    structure = (
        ('QualifierName', QUALIFIER_NAME),
    )

    @classmethod
    def getValue(cls, cimType, entry, heap):
          
        pType = cimType & (~(CIM_ARRAY_FLAG|Inherited))

        if entry != 0xffffffff:
            heapData = heap[entry:]
            if cimType & CIM_ARRAY_FLAG:
                  
                dataSize = calcsize(HEAPREF[:-2])
                numItems = unpack(HEAPREF[:-2], heapData[:dataSize])[0]
                heapData = heapData[dataSize:]
                array = list()
                unpackStrArray =  CIM_TYPES_REF[pType][:-2]
                dataSizeArray = calcsize(unpackStrArray)
                if cimType == CIM_TYPE_ENUM.CIM_ARRAY_STRING.value:
                      
                      
                      
                    heapData = heapData[4*numItems:]
                      
                    for _ in range(numItems):
                        item = ENCODED_STRING(heapData)
                        array.append(item['Character'])
                        heapData = heapData[len(item.getData()):]
                elif cimType == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT.value:
                      
                    heapData = heapData[dataSize*numItems:]
                    for item in range(numItems):
                        msb = METHOD_SIGNATURE_BLOCK(heapData)
                        unit = ENCODING_UNIT()
                        unit['ObjectEncodingLength'] = msb['EncodingLength']
                        unit['ObjectBlock'] = msb['ObjectBlock']
                        array.append(unit)
                        heapData = heapData[msb['EncodingLength']+4:]
                else:
                    for item in range(numItems):
                          
                        array.append(unpack(unpackStrArray, heapData[:dataSizeArray])[0])
                        heapData = heapData[dataSizeArray:]
                value = array
            elif pType == CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value:
                if entry == 0xffff:
                    value = 'True'
                else:
                    value = 'False'
            elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                  
                  

                  
                  
                msb = METHOD_SIGNATURE_BLOCK(heapData)
                unit = ENCODING_UNIT()
                unit['ObjectEncodingLength'] = msb['EncodingLength']
                unit['ObjectBlock'] = msb['ObjectBlock']
                value = unit
            elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING.value, CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                               CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value):
                value = entry
            else:
                try:
                    value = ENCODED_STRING(heapData)['Character']
                except UnicodeDecodeError:
                    if logging.getLogger().level == logging.DEBUG:
                        LOG.debug('Unicode Error: dumping heapData')
                        hexdump(heapData)
                    raise

            return value

  
QUALIFIER_VALUE = ENCODED_VALUE

  
class QUALIFIER(Structure):
    commonHdr = (
        ('QualifierName', QUALIFIER_NAME),
        ('QualifierFlavor', QUALIFIER_FLAVOR),
        ('QualifierType', QUALIFIER_TYPE),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is not None:
              
            self.fromString(data)
            self.structure = (('QualifierValue', CIM_TYPES_REF[self["QualifierType"] & (~CIM_ARRAY_FLAG)]),)
            self.fromString(data)
        else:
            self.data = None

  
class QUALIFIER_SET(Structure):
    structure = (
        ('EncodingLength', ENCODING_LENGTH),
        ('_Qualifier','_-Qualifier', 'self["EncodingLength"]-4'),
        ('Qualifier', ':'),
    )

    def getQualifiers(self, heap):
        data = self['Qualifier']
        qualifiers = dict()
        while len(data) > 0:
            itemn = QUALIFIER(data)
            if itemn['QualifierName'] == 0xffffffff:
                qName = b''
            elif itemn['QualifierName'] & 0x80000000:
                qName = DICTIONARY_REFERENCE[itemn['QualifierName'] & 0x7fffffff]
            else:
                qName = ENCODED_STRING(heap[itemn['QualifierName']:])['Character']

            value = ENCODED_VALUE.getValue(itemn['QualifierType'], itemn['QualifierValue'], heap)
            qualifiers[qName] = value
            data = data[len(itemn):]

        return qualifiers
 
  
CLASS_QUALIFIER_SET = QUALIFIER_SET

  
PROPERTY_COUNT = '<L=0'

  
PROPERTY_NAME_REF = HEAP_STRING_REF

  
PROPERTY_INFO_REF = HEAPREF

  
class PropertyLookup(Structure):
    structure = (
        ('PropertyNameRef', PROPERTY_NAME_REF),
        ('PropertyInfoRef', PROPERTY_INFO_REF),
    )

  
PROPERTY_TYPE = '<L=0'

  
DECLARATION_ORDER = '<H=0'

  
VALUE_TABLE_OFFSET = '<L=0'

  
CLASS_OF_ORIGIN = '<L=0'

  
PROPERTY_QUALIFIER_SET = QUALIFIER_SET

  
class PROPERTY_INFO(Structure):
    structure = (
        ('PropertyType', PROPERTY_TYPE),
        ('DeclarationOrder', DECLARATION_ORDER),
        ('ValueTableOffset', VALUE_TABLE_OFFSET),
        ('ClassOfOrigin', CLASS_OF_ORIGIN),
        ('PropertyQualifierSet', ':', PROPERTY_QUALIFIER_SET),
    )

  
Inherited = 0x4000

  
class PROPERTY_LOOKUP_TABLE(Structure):
    PropertyLookupSize = len(PropertyLookup())
    structure = (
        ('PropertyCount', PROPERTY_COUNT),
        ('_PropertyLookup','_-PropertyLookup', 'self["PropertyCount"]*self.PropertyLookupSize'),
        ('PropertyLookup', ':'),
    )

    def getProperties(self, heap):
        propTable = self['PropertyLookup']
        properties = dict()
        for property in range(self['PropertyCount']):
            propItemDict = dict()
            propItem = PropertyLookup(propTable)
            if propItem['PropertyNameRef'] & 0x80000000:
                propName = DICTIONARY_REFERENCE[propItem['PropertyNameRef'] & 0x7fffffff]
            else:
                propName = ENCODED_STRING(heap[propItem['PropertyNameRef']:])['Character']
            propInfo = PROPERTY_INFO(heap[propItem['PropertyInfoRef']:])
            pType = propInfo['PropertyType']
            pType &= (~CIM_ARRAY_FLAG)
            pType &= (~Inherited)
            sType = CIM_TYPE_TO_NAME[pType]
 
            propItemDict['stype'] = sType
            propItemDict['name'] = propName
            propItemDict['type'] = propInfo['PropertyType']
            propItemDict['order'] = propInfo['DeclarationOrder']
            propItemDict['inherited'] = propInfo['PropertyType'] & Inherited
            propItemDict['value'] = None

            qualifiers = dict() 
            qualifiersBuf = propInfo['PropertyQualifierSet']['Qualifier']
            while len(qualifiersBuf) > 0:
                record = QUALIFIER(qualifiersBuf)
                if record['QualifierName'] & 0x80000000:
                    qualifierName = DICTIONARY_REFERENCE[record['QualifierName'] & 0x7fffffff]
                else:
                    qualifierName = ENCODED_STRING(heap[record['QualifierName']:])['Character']
                qualifierValue = ENCODED_VALUE.getValue(record['QualifierType'], record['QualifierValue'], heap)
                qualifiersBuf = qualifiersBuf[len(record):]
                qualifiers[qualifierName] = qualifierValue

            propItemDict['qualifiers'] = qualifiers
            properties[propName] = propItemDict

            propTable = propTable[self.PropertyLookupSize:]

        return OrderedDict(sorted(list(properties.items()), key=lambda x:x[1]['order']))
          

  
HEAP_LENGTH = '<L=0'

class HEAP(Structure):
    structure = (
        ('HeapLength', HEAP_LENGTH),
          
          
          
        ('_HeapItem','_-HeapItem', 'self["HeapLength"]&0x7fffffff'),
        ('HeapItem', ':'),
    )

  
CLASS_HEAP = HEAP

  
class CLASS_PART(Structure):
    commonHdr = (
        ('ClassHeader', ':', CLASS_HEADER),
        ('DerivationList', ':', DERIVATION_LIST),
        ('ClassQualifierSet', ':', CLASS_QUALIFIER_SET),
        ('PropertyLookupTable', ':', PROPERTY_LOOKUP_TABLE),
        ('_NdTable_ValueTable','_-NdTable_ValueTable', 'self["ClassHeader"]["NdTableValueTableLength"]'),
        ('NdTable_ValueTable',':'),
        ('ClassHeap', ':', CLASS_HEAP),
        ('_Garbage', '_-Garbage', 'self["ClassHeader"]["EncodingLength"]-len(self)'),
        ('Garbage', ':=b""'),
    )
    def getQualifiers(self):
        return self["ClassQualifierSet"].getQualifiers(self["ClassHeap"]["HeapItem"])

    def getProperties(self):
        heap = self["ClassHeap"]["HeapItem"]
        properties =  self["PropertyLookupTable"].getProperties(self["ClassHeap"]["HeapItem"])
        sorted_props = sorted(list(properties.keys()), key=lambda k: properties[k]['order'])
        valueTableOff = (len(properties) - 1) // 4 + 1
        valueTable = self['NdTable_ValueTable'][valueTableOff:]
        for key in sorted_props:
              
            pType = properties[key]['type'] & (~(CIM_ARRAY_FLAG|Inherited))
            if properties[key]['type'] & CIM_ARRAY_FLAG:
                unpackStr = HEAPREF[:-2]
            else:
                unpackStr = CIM_TYPES_REF[pType][:-2]
            dataSize = calcsize(unpackStr)
            try:
                itemValue = unpack(unpackStr, valueTable[:dataSize])[0]
            except: 
                LOG.error("getProperties: Error unpacking!!")
                itemValue = 0xffffffff

            if itemValue != 0xffffffff and itemValue > 0:
                value = ENCODED_VALUE.getValue(properties[key]['type'], itemValue, heap)
                properties[key]['value'] = "%s" % value
            valueTable = valueTable[dataSize:]
        return properties
             
  
METHOD_COUNT = '<H=0'

  
METHOD_COUNT_PADDING = '<H=0'

  
METHOD_NAME = HEAP_STRING_REF

  
METHOD_FLAGS = 'B=0'

  
METHOD_PADDING = "3s=b''"

  
METHOD_ORIGIN = '<L=0'

  
HEAP_QUALIFIER_SET_REF = HEAPREF

  
METHOD_QUALIFIERS = HEAP_QUALIFIER_SET_REF

  
HEAP_METHOD_SIGNATURE_BLOCK_REF = HEAPREF

  
METHOD_SIGNATURE = HEAP_METHOD_SIGNATURE_BLOCK_REF

  
INPUT_SIGNATURE = METHOD_SIGNATURE

  
OUTPUT_SIGNATURE = METHOD_SIGNATURE

  
METHOD_HEAP = HEAP

  
class METHOD_DESCRIPTION(Structure):
    structure = (
        ('MethodName',METHOD_NAME),
        ('MethodFlags', METHOD_FLAGS),
        ('MethodPadding', METHOD_PADDING),
        ('MethodOrigin', METHOD_ORIGIN),
        ('MethodQualifiers', METHOD_QUALIFIERS),
        ('InputSignature', INPUT_SIGNATURE),
        ('OutputSignature', OUTPUT_SIGNATURE),
    )

  
class METHODS_PART(Structure):
    MethodDescriptionSize = len(METHOD_DESCRIPTION())
    structure = (
        ('EncodingLength',ENCODING_LENGTH),
        ('MethodCount', METHOD_COUNT),
        ('MethodCountPadding', METHOD_COUNT_PADDING),
        ('_MethodDescription', '_-MethodDescription', 'self["MethodCount"]*self.MethodDescriptionSize'),
        ('MethodDescription', ':'),
        ('MethodHeap', ':', METHOD_HEAP),
    )

    def getMethods(self):
        methods = OrderedDict()
        data = self['MethodDescription']
        heap = self['MethodHeap']['HeapItem']

        for method in range(self['MethodCount']):
            methodDict = OrderedDict()
            itemn = METHOD_DESCRIPTION(data)
            if itemn['MethodFlags'] & WBEM_FLAVOR_ORIGIN_PROPAGATED:
                 
                 
                 
               pass
            methodDict['name'] = ENCODED_STRING(heap[itemn['MethodName']:])['Character']
            methodDict['origin'] = itemn['MethodOrigin']
            if itemn['MethodQualifiers'] != 0xffffffff:
                  
                qualifiersSet = QUALIFIER_SET(heap[itemn['MethodQualifiers']:])
                qualifiers = qualifiersSet.getQualifiers(heap)
                methodDict['qualifiers'] = qualifiers
            if itemn['InputSignature'] != 0xffffffff:
                inputSignature = METHOD_SIGNATURE_BLOCK(heap[itemn['InputSignature']:])
                if inputSignature['EncodingLength'] > 0:
                    methodDict['InParams'] = inputSignature['ObjectBlock']['ClassType']['CurrentClass'].getProperties()
                    methodDict['InParamsRaw'] = inputSignature['ObjectBlock']
                      
                else:
                    methodDict['InParams'] = None
            if itemn['OutputSignature'] != 0xffffffff:
                outputSignature = METHOD_SIGNATURE_BLOCK(heap[itemn['OutputSignature']:])
                if outputSignature['EncodingLength'] > 0:
                    methodDict['OutParams'] = outputSignature['ObjectBlock']['ClassType']['CurrentClass'].getProperties()
                    methodDict['OutParamsRaw'] = outputSignature['ObjectBlock']
                else:
                    methodDict['OutParams'] = None
            data = data[len(itemn):]
            methods[methodDict['name']] = methodDict

        return methods

  
class CLASS_AND_METHODS_PART(Structure):
    structure = (
        ('ClassPart', ':', CLASS_PART),
        ('MethodsPart', ':', METHODS_PART),
    )

    def getClassName(self):
        pClassName = self['ClassPart']['ClassHeader']['ClassNameRef']
        cHeap = self['ClassPart']['ClassHeap']['HeapItem']
        if pClassName == 0xffffffff:
            return 'None'
        else:
            className = ENCODED_STRING(cHeap[pClassName:])['Character']
            derivationList = self['ClassPart']['DerivationList']['ClassNameEncoding']
            while len(derivationList) > 0:
                superClass = ENCODED_STRING(derivationList)['Character']
                className += ' : %s ' % superClass
                derivationList = derivationList[len(ENCODED_STRING(derivationList))+4:]
            return className

    def getQualifiers(self):
        return self["ClassPart"].getQualifiers()

    def getProperties(self):
          
        return self["ClassPart"].getProperties()

    def getMethods(self):
        return self["MethodsPart"].getMethods()

  
CURRENT_CLASS = CLASS_AND_METHODS_PART

  
INSTANCE_FLAGS = 'B=0'

  
INSTANCE_CLASS_NAME = HEAP_STRING_REF

  
NULL_AND_DEFAULT_FLAG = 'B=0'

  
NDTABLE = NULL_AND_DEFAULT_FLAG

  
  

class CURRENT_CLASS_NO_METHODS(CLASS_AND_METHODS_PART):
    structure = (
        ('ClassPart', ':', CLASS_PART),
    )
    def getMethods(self):
        return ()

  
INST_PROP_QUAL_SET_FLAG = 'B=0'
class INSTANCE_PROP_QUALIFIER_SET(Structure):
    commonHdr = (
        ('InstPropQualSetFlag', INST_PROP_QUAL_SET_FLAG),
    )
    tail = (
          
          
        ('QualifierSet', ':', QUALIFIER_SET),
    )

    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        self.structure = ()
        if data is not None:
              
            self.fromString(data)
            if self['InstPropQualSetFlag'] == 2:
                  
                raise Exception("self['InstPropQualSetFlag'] == 2")
            self.fromString(data)
        else:
            self.data = None

  
class INSTANCE_QUALIFIER_SET(Structure):
    structure = (
        ('QualifierSet', ':', QUALIFIER_SET),
        ('InstancePropQualifierSet', ':', INSTANCE_PROP_QUALIFIER_SET),
    )

  
INSTANCE_HEAP = HEAP

  
class INSTANCE_TYPE(Structure):
    commonHdr = (
        ('CurrentClass', ':', CURRENT_CLASS_NO_METHODS),
        ('EncodingLength', ENCODING_LENGTH),
        ('InstanceFlags', INSTANCE_FLAGS),
        ('InstanceClassName', INSTANCE_CLASS_NAME),
        ('_NdTable_ValueTable', '_-NdTable_ValueTable',
         'self["CurrentClass"]["ClassPart"]["ClassHeader"]["NdTableValueTableLength"]'),
        ('NdTable_ValueTable',':'),
        ('InstanceQualifierSet', ':', INSTANCE_QUALIFIER_SET),
        ('InstanceHeap', ':', INSTANCE_HEAP),
    )

    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        self.structure = ()
        if data is not None:
              
            self.fromString(data)
              
            self.NdTableSize = (self['CurrentClass']['ClassPart']['PropertyLookupTable']['PropertyCount'] - 1) //4 + 1
              
            self.fromString(data)
        else:
            self.data = None

    def __processNdTable(self, properties):
        octetCount = (len(properties) - 1) // 4 + 1    
        packedNdTable = self['NdTable_ValueTable'][:octetCount]
        unpackedNdTable = [(byte >> shift) & 0b11 for byte in six.iterbytes(packedNdTable) for shift in (0, 2, 4, 6)]
        for key in properties:
            ndEntry = unpackedNdTable[properties[key]['order']]
            properties[key]['null_default'] = bool(ndEntry & 0b01)
            properties[key]['inherited_default'] = bool(ndEntry & 0b10)

        return octetCount

    @staticmethod
    def __isNonNullNumber(prop):
        return prop['type'] & ~Inherited in CIM_NUMBER_TYPES and not prop['null_default']

    def getValues(self, properties):
        heap = self["InstanceHeap"]["HeapItem"]
        valueTableOff = self.__processNdTable(properties)
        valueTable = self['NdTable_ValueTable'][valueTableOff:]
        sorted_props = sorted(list(properties.keys()), key=lambda k: properties[k]['order'])
        for key in sorted_props:
            pType = properties[key]['type'] & (~(CIM_ARRAY_FLAG|Inherited))
            if properties[key]['type'] & CIM_ARRAY_FLAG:
                unpackStr = HEAPREF[:-2]
            else:
                unpackStr = CIM_TYPES_REF[pType][:-2]
            dataSize = calcsize(unpackStr)
            try:
                itemValue = unpack(unpackStr, valueTable[:dataSize])[0]
            except:
                LOG.error("getValues: Error Unpacking!")
                itemValue = 0xffffffff

              
            if itemValue != 0 or self.__isNonNullNumber(properties[key]):
                value = ENCODED_VALUE.getValue( properties[key]['type'], itemValue, heap)
                properties[key]['value'] = value
              
            elif properties[key]['inherited'] == 0:
                properties[key]['value'] = None
            valueTable = valueTable[dataSize:]
        return properties

  
PARENT_CLASS = CLASS_AND_METHODS_PART

  
CURRENT_CLASS = CLASS_AND_METHODS_PART

class CLASS_TYPE(Structure):
    structure = (
        ('ParentClass', ':', PARENT_CLASS),
        ('CurrentClass', ':', CURRENT_CLASS),
    )

  
class OBJECT_BLOCK(Structure):
    commonHdr = (
        ('ObjectFlags', OBJECT_FLAGS),
    )

    decoration = (
        ('Decoration', ':', DECORATION),
    )

    instanceType = (
        ('InstanceType', ':', INSTANCE_TYPE),
    )

    classType = (
        ('ClassType', ':', CLASS_TYPE),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        self.ctParent  = None
        self.ctCurrent = None

        if data is not None:
            self.structure = ()
            if ord(data[0:1]) & 0x4:
                  
                self.structure += self.decoration
            if ord(data[0:1]) & 0x01:
                  
                self.structure += self.classType
            else:
                self.structure += self.instanceType

            self.fromString(data)
        else:
            self.data = None

    def isInstance(self):
        if self['ObjectFlags'] & 0x01:
            return False
        return True

    def printClass(self, pClass, cInstance = None):
        qualifiers = pClass.getQualifiers()

        for qualifier in qualifiers:
            print("[%s]" % qualifier)

        className = pClass.getClassName()

        print("class %s \n{" % className)

        properties = pClass.getProperties()
        if cInstance is not None:
            properties = cInstance.getValues(properties)

        for pName in properties:
              
                qualifiers = properties[pName]['qualifiers']
                for qName in qualifiers:
                    if qName != 'CIMTYPE':
                        print('\t[%s(%s)]' % (qName, qualifiers[qName]))
                print("\t%s %s" % (properties[pName]['stype'], properties[pName]['name']), end=' ')
                if properties[pName]['value'] is not None:
                    if properties[pName]['type'] == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                        print('= IWbemClassObject\n')
                    elif properties[pName]['type'] == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT.value:
                        if properties[pName]['value'] == 0:
                            print('= %s\n' % properties[pName]['value'])
                        else:
                            print('= %s\n' % list('IWbemClassObject' for _ in range(len(properties[pName]['value']))))
                    else:
                        print('= %s\n' % properties[pName]['value'])
                else:
                    print('\n')

        print() 
        methods = pClass.getMethods()
        for methodName in methods:
            for qualifier in methods[methodName]['qualifiers']:
                print('\t[%s]' % qualifier)

            if methods[methodName]['InParams'] is None and methods[methodName]['OutParams'] is None: 
                print('\t%s %s();\n' % ('void', methodName))
            if methods[methodName]['InParams'] is None and len(methods[methodName]['OutParams']) == 1:
                print('\t%s %s();\n' % (methods[methodName]['OutParams']['ReturnValue']['stype'], methodName))
            else:
                returnValue = b''
                if methods[methodName]['OutParams'] is not None:
                      
                      
                    if 'ReturnValue' in methods[methodName]['OutParams']:
                        returnValue = methods[methodName]['OutParams']['ReturnValue']['stype']
 
                print('\t%s %s(\n' % (returnValue, methodName), end=' ')
                if methods[methodName]['InParams'] is not None:
                    for pName  in methods[methodName]['InParams']:
                        print('\t\t[in]    %s %s,' % (methods[methodName]['InParams'][pName]['stype'], pName))

                if methods[methodName]['OutParams'] is not None:
                    for pName in methods[methodName]['OutParams']:
                        if pName != 'ReturnValue':
                            print('\t\t[out]    %s %s,' % (methods[methodName]['OutParams'][pName]['stype'], pName))

                print('\t);\n')

        print("}")

    def parseClass(self, pClass, cInstance = None):
        classDict = OrderedDict()
        classDict['name'] = pClass.getClassName()
        classDict['qualifiers'] = pClass.getQualifiers()
        classDict['properties'] = pClass.getProperties()
        classDict['methods'] = pClass.getMethods()
        if cInstance is not None:
            classDict['values'] = cInstance.getValues(classDict['properties'])
        else:
            classDict['values'] = None

        return classDict

    def parseObject(self):
        if (self['ObjectFlags'] & 0x01) == 0:
              
            ctCurrent = self['InstanceType']['CurrentClass']
            currentName = ctCurrent.getClassName()
            if currentName is not None:
                self.ctCurrent = self.parseClass(ctCurrent, self['InstanceType'])
            return
        else: 
            ctParent = self['ClassType']['ParentClass']
            ctCurrent = self['ClassType']['CurrentClass']

            parentName = ctParent.getClassName()
            if parentName is not None:
                self.ctParent = self.parseClass(ctParent)

            currentName = ctCurrent.getClassName()
            if currentName is not None:
                self.ctCurrent = self.parseClass(ctCurrent)

    def printInformation(self):
          
        if (self['ObjectFlags'] & 0x01) == 0:
              
            ctCurrent = self['InstanceType']['CurrentClass']
            currentName = ctCurrent.getClassName()
            if currentName is not None:
                self.printClass(ctCurrent, self['InstanceType'])
            return
        else: 
            ctParent = self['ClassType']['ParentClass']
            ctCurrent = self['ClassType']['CurrentClass']

            parentName = ctParent.getClassName()
            if parentName is not None:
                self.printClass(ctParent)

            currentName = ctCurrent.getClassName()
            if currentName is not None:
                self.printClass(ctCurrent)

  
class METHOD_SIGNATURE_BLOCK(Structure):
    commonHdr = (
        ('EncodingLength', ENCODING_LENGTH),
    )
    tail = (
        ('_ObjectBlock', '_-ObjectBlock', 'self["EncodingLength"]'),
        ('ObjectBlock', ':', OBJECT_BLOCK),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is not None:
            self.fromString(data)
            if self['EncodingLength'] > 0:
                self.structure = ()
                self.structure += self.tail
            self.fromString(data)
        else:
            self.data = None

  
class ENCODING_UNIT(Structure):
    structure = (
        ('Signature', SIGNATURE),
        ('ObjectEncodingLength', OBJECT_ENCODING_LENGTH),
        ('_ObjectBlock', '_-ObjectBlock', 'self["ObjectEncodingLength"]'),
        ('ObjectBlock', ':', OBJECT_BLOCK),
    )

  
  
  
  
CLSID_WbemLevel1Login     = string_to_bin('8BC3F05E-D86B-11D0-A075-00C04FB68820')
CLSID_WbemBackupRestore   = string_to_bin('C49E32C6-BC8B-11D2-85D4-00105A1F8304')
CLSID_WbemClassObject     = string_to_bin('4590F812-1D3A-11D0-891F-00AA004B2E24')

IID_IWbemLevel1Login      = uuidtup_to_bin(('F309AD18-D86A-11d0-A075-00C04FB68820', '0.0'))
IID_IWbemLoginClientID    = uuidtup_to_bin(('d4781cd6-e5d3-44df-ad94-930efe48a887', '0.0'))
IID_IWbemLoginHelper      = uuidtup_to_bin(('541679AB-2E5F-11d3-B34E-00104BCC4B4A', '0.0'))
IID_IWbemServices         = uuidtup_to_bin(('9556DC99-828C-11CF-A37E-00AA003240C7', '0.0'))
IID_IWbemBackupRestore    = uuidtup_to_bin(('C49E32C7-BC8B-11d2-85D4-00105A1F8304', '0.0'))
IID_IWbemBackupRestoreEx  = uuidtup_to_bin(('A359DEC5-E813-4834-8A2A-BA7F1D777D76', '0.0'))
IID_IWbemClassObject      = uuidtup_to_bin(('DC12A681-737F-11CF-884D-00AA004B2E24', '0.0'))
IID_IWbemContext          = uuidtup_to_bin(('44aca674-e8fc-11d0-a07c-00c04fb68820', '0.0'))
IID_IEnumWbemClassObject  = uuidtup_to_bin(('027947e1-d731-11ce-a357-000000000001', '0.0'))
IID_IWbemCallResult       = uuidtup_to_bin(('44aca675-e8fc-11d0-a07c-00c04fb68820', '0.0'))
IID_IWbemFetchSmartEnum   = uuidtup_to_bin(('1C1C45EE-4395-11d2-B60B-00104B703EFD', '0.0'))
IID_IWbemWCOSmartEnum     = uuidtup_to_bin(('423EC01E-2E35-11d2-B604-00104B703EFD', '0.0'))

error_status_t = ULONG

  
WBEM_FLAG_RETURN_WBEM_COMPLETE          = 0x00000000
WBEM_FLAG_UPDATE_ONLY                   = 0x00000001
WBEM_FLAG_CREATE_ONLY                   = 0x00000002
WBEM_FLAG_RETURN_IMMEDIATELY            = 0x00000010
WBEM_FLAG_UPDATE_SAFE_MODE              = 0x00000020
WBEM_FLAG_FORWARD_ONLY                  = 0x00000020
WBEM_FLAG_NO_ERROR_OBJECT               = 0x00000040
WBEM_FLAG_UPDATE_FORCE_MODE             = 0x00000040
WBEM_FLAG_SEND_STATUS                   = 0x00000080
WBEM_FLAG_ENSURE_LOCATABLE              = 0x00000100
WBEM_FLAG_DIRECT_READ                   = 0x00000200
WBEM_MASK_RESERVED_FLAGS                = 0x0001F000
WBEM_FLAG_USE_AMENDED_QUALIFIERS        = 0x00020000
WBEM_FLAG_STRONG_VALIDATION             = 0x00100000
WBEM_FLAG_BACKUP_RESTORE_FORCE_SHUTDOWN = 0x00000001

WBEM_INFINITE = 0xffffffff

  
  
  
class UCHAR_ARRAY_CV(NDRUniConformantVaryingArray):
    item = 'c'

class PUCHAR_ARRAY_CV(NDRPOINTER):
    referent = (
        ('Data', UCHAR_ARRAY_CV),
    )

class PMInterfacePointer_ARRAY_CV(NDRUniConformantVaryingArray):
    item = PMInterfacePointer

REFGUID = PGUID

class ULONG_ARRAY(NDRUniConformantArray):
    item = ULONG

class PULONG_ARRAY(NDRPOINTER):
    referent = (
        ('Data', ULONG_ARRAY),
    )

  
class WBEM_CHANGE_FLAG_TYPE(NDRENUM):
      
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_CREATE_OR_UPDATE  = 0x00
        WBEM_FLAG_UPDATE_ONLY       = 0x01
        WBEM_FLAG_CREATE_ONLY       = 0x02
        WBEM_FLAG_UPDATE_SAFE_MODE  = 0x20
        WBEM_FLAG_UPDATE_FORCE_MODE = 0x40

  
class WBEM_GENERIC_FLAG_TYPE(NDRENUM):
      
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_RETURN_WBEM_COMPLETE   = 0x00
        WBEM_FLAG_RETURN_IMMEDIATELY     = 0x10
        WBEM_FLAG_FORWARD_ONLY           = 0x20
        WBEM_FLAG_NO_ERROR_OBJECT        = 0x40
        WBEM_FLAG_SEND_STATUS            = 0x80
        WBEM_FLAG_ENSURE_LOCATABLE       = 0x100
        WBEM_FLAG_DIRECT_READ            = 0x200
        WBEM_MASK_RESERVED_FLAGS         = 0x1F000
        WBEM_FLAG_USE_AMENDED_QUALIFIERS = 0x20000
        WBEM_FLAG_STRONG_VALIDATION      = 0x100000

  
class WBEM_STATUS_TYPE(NDRENUM):
    class enumItems(Enum):
        WBEM_STATUS_COMPLETE     = 0x00
        WBEM_STATUS_REQUIREMENTS = 0x01
        WBEM_STATUS_PROGRESS     = 0x02

  
class WBEM_TIMEOUT_TYPE(NDRENUM):
      
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_NO_WAIT  = 0x00000000
        WBEM_INFINITE = 0xFFFFFFFF

  
class WBEM_QUERY_FLAG_TYPE(NDRENUM):
      
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_DEEP      = 0x00000000
        WBEM_FLAG_SHALLOW   = 0x00000001
        WBEM_FLAG_PROTOTYPE = 0x00000002

  
class WBEM_BACKUP_RESTORE_FLAGS(NDRENUM):
      
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_BACKUP_RESTORE_FORCE_SHUTDOWN = 0x00000001

  
class WBEMSTATUS(NDRENUM):
      
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_S_NO_ERROR                      = 0x00000000
        WBEM_S_FALSE                         = 0x00000001
        WBEM_S_TIMEDOUT                      = 0x00040004
        WBEM_S_NEW_STYLE                     = 0x000400FF
        WBEM_S_PARTIAL_RESULTS               = 0x00040010
        WBEM_E_FAILED                        = 0x80041001
        WBEM_E_NOT_FOUND                     = 0x80041002
        WBEM_E_ACCESS_DENIED                 = 0x80041003
        WBEM_E_PROVIDER_FAILURE              = 0x80041004
        WBEM_E_TYPE_MISMATCH                 = 0x80041005
        WBEM_E_OUT_OF_MEMORY                 = 0x80041006
        WBEM_E_INVALID_CONTEXT               = 0x80041007
        WBEM_E_INVALID_PARAMETER             = 0x80041008
        WBEM_E_NOT_AVAILABLE                 = 0x80041009
        WBEM_E_CRITICAL_ERROR                = 0x8004100a
        WBEM_E_NOT_SUPPORTED                 = 0x8004100c
        WBEM_E_PROVIDER_NOT_FOUND            = 0x80041011
        WBEM_E_INVALID_PROVIDER_REGISTRATION = 0x80041012
        WBEM_E_PROVIDER_LOAD_FAILURE         = 0x80041013
        WBEM_E_INITIALIZATION_FAILURE        = 0x80041014
        WBEM_E_TRANSPORT_FAILURE             = 0x80041015
        WBEM_E_INVALID_OPERATION             = 0x80041016
        WBEM_E_ALREADY_EXISTS                = 0x80041019
        WBEM_E_UNEXPECTED                    = 0x8004101d
        WBEM_E_INCOMPLETE_CLASS              = 0x80041020
        WBEM_E_SHUTTING_DOWN                 = 0x80041033
        E_NOTIMPL                            = 0x80004001
        WBEM_E_INVALID_SUPERCLASS            = 0x8004100D
        WBEM_E_INVALID_NAMESPACE             = 0x8004100E
        WBEM_E_INVALID_OBJECT                = 0x8004100F
        WBEM_E_INVALID_CLASS                 = 0x80041010
        WBEM_E_INVALID_QUERY                 = 0x80041017
        WBEM_E_INVALID_QUERY_TYPE            = 0x80041018
        WBEM_E_PROVIDER_NOT_CAPABLE          = 0x80041024
        WBEM_E_CLASS_HAS_CHILDREN            = 0x80041025
        WBEM_E_CLASS_HAS_INSTANCES           = 0x80041026
        WBEM_E_ILLEGAL_NULL                  = 0x80041028
        WBEM_E_INVALID_CIM_TYPE              = 0x8004102D
        WBEM_E_INVALID_METHOD                = 0x8004102E
        WBEM_E_INVALID_METHOD_PARAMETERS     = 0x8004102F
        WBEM_E_INVALID_PROPERTY              = 0x80041031
        WBEM_E_CALL_CANCELLED                = 0x80041032
        WBEM_E_INVALID_OBJECT_PATH           = 0x8004103A
        WBEM_E_OUT_OF_DISK_SPACE             = 0x8004103B
        WBEM_E_UNSUPPORTED_PUT_EXTENSION     = 0x8004103D
        WBEM_E_QUOTA_VIOLATION               = 0x8004106c
        WBEM_E_SERVER_TOO_BUSY               = 0x80041045
        WBEM_E_METHOD_NOT_IMPLEMENTED        = 0x80041055
        WBEM_E_METHOD_DISABLED               = 0x80041056
        WBEM_E_UNPARSABLE_QUERY              = 0x80041058
        WBEM_E_NOT_EVENT_CLASS               = 0x80041059
        WBEM_E_MISSING_GROUP_WITHIN          = 0x8004105A
        WBEM_E_MISSING_AGGREGATION_LIST      = 0x8004105B
        WBEM_E_PROPERTY_NOT_AN_OBJECT        = 0x8004105c
        WBEM_E_AGGREGATING_BY_OBJECT         = 0x8004105d
        WBEM_E_BACKUP_RESTORE_WINMGMT_RUNNING= 0x80041060
        WBEM_E_QUEUE_OVERFLOW                = 0x80041061
        WBEM_E_PRIVILEGE_NOT_HELD            = 0x80041062
        WBEM_E_INVALID_OPERATOR              = 0x80041063
        WBEM_E_CANNOT_BE_ABSTRACT            = 0x80041065
        WBEM_E_AMENDED_OBJECT                = 0x80041066
        WBEM_E_VETO_PUT                      = 0x8004107A
        WBEM_E_PROVIDER_SUSPENDED            = 0x80041081
        WBEM_E_ENCRYPTED_CONNECTION_REQUIRED = 0x80041087
        WBEM_E_PROVIDER_TIMED_OUT            = 0x80041088
        WBEM_E_NO_KEY                        = 0x80041089
        WBEM_E_PROVIDER_DISABLED             = 0x8004108a
        WBEM_E_REGISTRATION_TOO_BROAD        = 0x80042001
        WBEM_E_REGISTRATION_TOO_PRECISE      = 0x80042002

  
class WBEM_CONNECT_OPTIONS(NDRENUM):
      
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_CONNECT_REPOSITORY_ONLY = 0x40
        WBEM_FLAG_CONNECT_PROVIDERS       = 0x100

  
class ObjectArray(Structure):
    structure = (
        ('dwByteOrdering', '<L=0'),
        ('abSignature', '8s="WBEMDATA"'),
        ('dwSizeOfHeader1', '<L=0x1a'),
        ('dwDataSize1', '<L=0'),
        ('dwFlags', '<L=0'),
        ('bVersion', 'B=1'),
        ('bPacketType', 'B=0'),
        ('dwSizeOfHeader2', '<L=8'),
        ('dwDataSize2', '<L', 'len(self["wbemObjects"])+12'),
        ('dwSizeOfHeader3', '<L=12'),
        ('dwDataSize3', '<L', 'len(self["dwDataSize2"])-12)'),
        ('dwNumObjects', '<L=0'),
        ('_wbemObjects', '_-wbemObjects', 'self["dwDataSize3"]'),
        ('wbemObjects', ':'),
    )

  
class WBEM_DATAPACKET_OBJECT(Structure):
    structure = (
        ('dwSizeOfHeader', '<L=9'),
        ('dwSizeOfData', '<L','len(self["Object"])'),
        ('bObjectType', 'B=0'),
        ('_Object', '_-Object', 'self["dwSizeOfData"]'),
        ('Object', ':'),
    )

  
class WBEMOBJECT_CLASS(Structure):
    structure = (
        ('dwSizeOfHeader', '<L=8'),
        ('dwSizeOfData', '<L','len(self["ObjectData"])'),
        ('_ObjectData', '_-ObjectData', 'self["dwSizeOfData"]'),
        ('ObjectData', ':'),
    )

  
class WBEMOBJECT_INSTANCE(Structure):
    structure = (
        ('dwSizeOfHeader', '<L=0x18'),
        ('dwSizeOfData', '<L','len(self["ObjectData"])'),
        ('classID', '16s=b"\x00"*16'),
        ('_ObjectData', '_-ObjectData', 'self["dwSizeOfData"]'),
        ('ObjectData', ':'),
    )

  
class WBEMOBJECT_INSTANCE_NOCLASS(Structure):
    structure = (
        ('dwSizeOfHeader', '<L=0x18'),
        ('dwSizeOfData', '<L','len(self["ObjectData"])'),
        ('classID', '16s=b"\x00"*16'),
        ('_ObjectData', '_-ObjectData', 'self["dwSizeOfData"]'),
        ('ObjectData', ':'),
    )

  
class WBEM_REFRESHED_OBJECT(NDRSTRUCT):
    structure = (
        ('m_lRequestId', LONG),
        ('m_lBlobType', LONG),
        ('m_lBlobLength', LONG),
        ('m_pBlob', BYTE_ARRAY),
    )

class WBEM_REFRESHED_OBJECT_ARRAY(NDRUniConformantArray):
    item = WBEM_REFRESHED_OBJECT

class PWBEM_REFRESHED_OBJECT_ARRAY(NDRPOINTER):
    referent = (
        ('Data', WBEM_REFRESHED_OBJECT_ARRAY),
    )

  
class WBEM_INSTANCE_BLOB(Structure):
    structure = (
        ('Version', '<L=0x1'),
        ('numObjects', '<L=0'),
        ('Objects', ':'),
    )

  
class WBEM_INSTANCE_BLOB_TYPE(NDRENUM):
      
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WBEM_FLAG_CONNECT_REPOSITORY_ONLY = 0x40
        WBEM_FLAG_CONNECT_PROVIDERS       = 0x100

  
class _WBEM_REFRESH_INFO_NON_HIPERF(NDRSTRUCT):
    structure = (
        ('m_wszNamespace', LPWSTR),
        ('m_pTemplate', PMInterfacePointer),
    )

  
class _WBEM_REFRESH_INFO_REMOTE(NDRSTRUCT):
    structure = (
        ('m_pRefresher', PMInterfacePointer),
        ('m_pTemplate', PMInterfacePointer),
        ('m_Guid', GUID),
    )

  
class WBEM_REFRESH_TYPE(NDRENUM):
    class enumItems(Enum):
        WBEM_REFRESH_TYPE_INVALID       = 0
        WBEM_REFRESH_TYPE_REMOTE        = 3
        WBEM_REFRESH_TYPE_NON_HIPERF    = 6

  
class _WBEM_REFRESH_INFO_UNION(NDRUNION):
    commonHdr = (
        ('tag', LONG),
    )
    union = {
        WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_REMOTE    : ('m_Remote', _WBEM_REFRESH_INFO_REMOTE),
        WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_NON_HIPERF: ('m_NonHiPerf', _WBEM_REFRESH_INFO_NON_HIPERF),
        WBEM_REFRESH_TYPE.WBEM_REFRESH_TYPE_INVALID   : ('m_hres', HRESULT),
    }

  
class _WBEM_REFRESH_INFO(NDRSTRUCT):
    structure = (
        ('m_lType', LONG),
        ('m_Info', _WBEM_REFRESH_INFO_UNION),
        ('m_lCancelId', LONG),
    )

  
class _WBEM_REFRESHER_ID(NDRSTRUCT):
    structure = (
        ('m_szMachineName', LPCSTR),
        ('m_dwProcessId', DWORD),
        ('m_guidRefresherId', GUID),
    )

  
class _WBEM_RECONNECT_INFO(NDRSTRUCT):
    structure = (
        ('m_lType', LPCSTR),
        ('m_pwcsPath', LPWSTR),
    )

class _WBEM_RECONNECT_INFO_ARRAY(NDRUniConformantArray):
    item = _WBEM_RECONNECT_INFO

  
class _WBEM_RECONNECT_RESULTS(NDRSTRUCT):
    structure = (
        ('m_lId', LONG),
        ('m_hr', HRESULT),
    )

class _WBEM_RECONNECT_RESULTS_ARRAY(NDRUniConformantArray):
    item = _WBEM_RECONNECT_INFO


  
  
  
  
  
class IWbemLevel1Login_EstablishPosition(DCOMCALL):
    opnum = 3
    structure = (
       ('reserved1', LPWSTR),
       ('reserved2', DWORD),
    )

class IWbemLevel1Login_EstablishPositionResponse(DCOMANSWER):
    structure = (
       ('LocaleVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

  
class IWbemLevel1Login_RequestChallenge(DCOMCALL):
    opnum = 4
    structure = (
       ('reserved1', LPWSTR),
       ('reserved2', LPWSTR),
    )

class IWbemLevel1Login_RequestChallengeResponse(DCOMANSWER):
    structure = (
       ('reserved3', UCHAR_ARRAY_CV),
       ('ErrorCode', error_status_t),
    )

  
class IWbemLevel1Login_WBEMLogin(DCOMCALL):
    opnum = 5
    structure = (
       ('reserved1', LPWSTR),
       ('reserved2', PUCHAR_ARRAY_CV),
       ('reserved3', LONG),
       ('reserved4', PMInterfacePointer),
    )

class IWbemLevel1Login_WBEMLoginResponse(DCOMANSWER):
    structure = (
       ('reserved5', UCHAR_ARRAY_CV),
       ('ErrorCode', error_status_t),
    )

  
class IWbemLevel1Login_NTLMLogin(DCOMCALL):
    opnum = 6
    structure = (
       ('wszNetworkResource', LPWSTR),
       ('wszPreferredLocale', LPWSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemLevel1Login_NTLMLoginResponse(DCOMANSWER):
    structure = (
       ('ppNamespace', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemObjectSink_Indicate(DCOMCALL):
    opnum = 3
    structure = (
       ('lObjectCount', LONG),
       ('apObjArray', PMInterfacePointer_ARRAY),
    )

class IWbemObjectSink_IndicateResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemObjectSink_SetStatus(DCOMCALL):
    opnum = 4
    structure = (
       ('lFlags', LONG),
       ('hResult', HRESULT),
       ('strParam', BSTR),
       ('pObjParam', PMInterfacePointer),
    )

class IWbemObjectSink_SetStatusResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemServices_OpenNamespace(DCOMCALL):
    opnum = 3
    structure = (
       ('strNamespace', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppWorkingNamespace', PMInterfacePointer),
       ('ppResult', PMInterfacePointer),
    )

class IWbemServices_OpenNamespaceResponse(DCOMANSWER):
    structure = (
       ('ppWorkingNamespace', PPMInterfacePointer),
       ('ppResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_CancelAsyncCall(DCOMCALL):
    opnum = 4
    structure = (
       ('IWbemObjectSink', PMInterfacePointer),
    )

class IWbemServices_CancelAsyncCallResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_QueryObjectSink(DCOMCALL):
    opnum = 5
    structure = (
       ('lFlags', LONG),
    )

class IWbemServices_QueryObjectSinkResponse(DCOMANSWER):
    structure = (
       ('ppResponseHandler', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_GetObject(DCOMCALL):
    opnum = 6
    structure = (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppObject', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_GetObjectResponse(DCOMANSWER):
    structure = (
       ('ppObject', PPMInterfacePointer),
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_GetObjectAsync(DCOMCALL):
    opnum = 7
    structure = (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_GetObjectAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_PutClass(DCOMCALL):
    opnum = 8
    structure = (
       ('pObject', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_PutClassResponse(DCOMANSWER):
    structure = (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_PutClassAsync(DCOMCALL):
    opnum = 9
    structure = (
       ('pObject', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_PutClassAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_DeleteClass(DCOMCALL):
    opnum = 10
    structure = (
       ('strClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_DeleteClassResponse(DCOMANSWER):
    structure = (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_DeleteClassAsync(DCOMCALL):
    opnum = 11
    structure = (
       ('strClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_DeleteClassAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_CreateClassEnum(DCOMCALL):
    opnum = 12
    structure = (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemServices_CreateClassEnumResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_CreateClassEnumAsync(DCOMCALL):
    opnum = 13
    structure = (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_CreateClassEnumAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_PutInstance(DCOMCALL):
    opnum = 14
    structure = (
       ('pInst', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_PutInstanceResponse(DCOMANSWER):
    structure = (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_PutInstanceAsync(DCOMCALL):
    opnum = 15
    structure = (
       ('pInst', PMInterfacePointer),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_PutInstanceAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_DeleteInstance(DCOMCALL):
    opnum = 16
    structure = (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('ppCallResult', PMInterfacePointer),
    )

class IWbemServices_DeleteInstanceResponse(DCOMANSWER):
    structure = (
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_DeleteInstanceAsync(DCOMCALL):
    opnum = 17
    structure = (
       ('strObjectPath', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_DeleteInstanceAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_CreateInstanceEnum(DCOMCALL):
    opnum = 18
    structure = (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemServices_CreateInstanceEnumResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_CreateInstanceEnumAsync(DCOMCALL):
    opnum = 19
    structure = (
       ('strSuperClass', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_CreateInstanceEnumAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_ExecQuery(DCOMCALL):
    opnum = 20
    structure = (
       ('strQueryLanguage', BSTR),
       ('strQuery', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemServices_ExecQueryResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_ExecQueryAsync(DCOMCALL):
    opnum = 21
    structure = (
       ('strQueryLanguage', BSTR),
       ('strQuery', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_ExecQueryAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_ExecNotificationQuery(DCOMCALL):
    opnum = 22
    structure = (
       ('strQueryLanguage', BSTR),
       ('strQuery', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
    )

class IWbemServices_ExecNotificationQueryResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_ExecNotificationQueryAsync(DCOMCALL):
    opnum = 23
    structure = (
       ('strQueryLanguage', BSTR),
       ('strQuery', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_ExecNotificationQueryAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_ExecMethod(DCOMCALL):
    opnum = 24
    structure = (
       ('strObjectPath', BSTR),
       ('strMethodName', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pInParams', PMInterfacePointer),
       ('ppOutParams', PPMInterfacePointer),
       ('ppCallResult', PPMInterfacePointer),
    )

class IWbemServices_ExecMethodResponse(DCOMANSWER):
    structure = (
       ('ppOutParams', PPMInterfacePointer),
       ('ppCallResult', PPMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemServices_ExecMethodAsync(DCOMCALL):
    opnum = 25
    structure = (
       ('strObjectPath', BSTR),
       ('strMethodName', BSTR),
       ('lFlags', LONG),
       ('pCtx', PMInterfacePointer),
       ('pInParams', PMInterfacePointer),
       ('pResponseHandler', PMInterfacePointer),
    )

class IWbemServices_ExecMethodAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
  
class IEnumWbemClassObject_Reset(DCOMCALL):
    opnum = 3
    structure = (
    )

class IEnumWbemClassObject_ResetResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IEnumWbemClassObject_Next(DCOMCALL):
    opnum = 4
    structure = (
       ('lTimeout', ULONG),
       ('uCount', ULONG),
    )

class IEnumWbemClassObject_NextResponse(DCOMANSWER):
    structure = (
       ('apObjects', PMInterfacePointer_ARRAY_CV),
       ('puReturned', ULONG),
       ('ErrorCode', error_status_t),
    )

  
class IEnumWbemClassObject_NextAsync(DCOMCALL):
    opnum = 5
    structure = (
       ('lTimeout', LONG),
       ('pSink', PMInterfacePointer),
    )

class IEnumWbemClassObject_NextAsyncResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IEnumWbemClassObject_Clone(DCOMCALL):
    opnum = 6
    structure = (
    )

class IEnumWbemClassObject_CloneResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IEnumWbemClassObject_Skip(DCOMCALL):
    opnum = 7
    structure = (
       ('lTimeout', LONG),
       ('uCount', ULONG),
    )

class IEnumWbemClassObject_SkipResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemCallResult_GetResultObject(DCOMCALL):
    opnum = 3
    structure = (
       ('lTimeout', LONG),
    )

class IWbemCallResult_GetResultObjectResponse(DCOMANSWER):
    structure = (
       ('ppResultObject', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemCallResult_GetResultString(DCOMCALL):
    opnum = 4
    structure = (
       ('lTimeout', LONG),
    )

class IWbemCallResult_GetResultStringResponse(DCOMANSWER):
    structure = (
       ('pstrResultString', BSTR),
       ('ErrorCode', error_status_t),
    )

  
class IWbemCallResult_GetResultServices(DCOMCALL):
    opnum = 5
    structure = (
       ('lTimeout', LONG),
    )

class IWbemCallResult_GetResultServicesResponse(DCOMANSWER):
    structure = (
       ('ppServices', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
class IWbemCallResult_GetCallStatus(DCOMCALL):
    opnum = 6
    structure = (
       ('lTimeout', LONG),
    )

class IWbemCallResult_GetCallStatusResponse(DCOMANSWER):
    structure = (
       ('plStatus', LONG),
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemFetchSmartEnum_GetSmartEnum(DCOMCALL):
    opnum = 3
    structure = (
    )

class IWbemFetchSmartEnum_GetSmartEnumResponse(DCOMANSWER):
    structure = (
       ('ppSmartEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemWCOSmartEnum_Next(DCOMCALL):
    opnum = 3
    structure = (
       ('proxyGUID', REFGUID),
       ('lTimeout', LONG),
       ('uCount', ULONG),
    )

class IWbemWCOSmartEnum_NextResponse(DCOMANSWER):
    structure = (
       ('puReturned', ULONG),
       ('pdwBuffSize', ULONG),
       ('pBuffer', BYTE_ARRAY),
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemLoginClientID_SetClientInfo(DCOMCALL):
    opnum = 3
    structure = (
       ('wszClientMachine', LPWSTR),
       ('lClientProcId', LONG),
       ('lReserved', LONG),
    )

class IWbemLoginClientID_SetClientInfoResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemLoginHelper_SetEvent(DCOMCALL):
    opnum = 3
    structure = (
       ('sEventToSet', LPCSTR),
    )

class IWbemLoginHelper_SetEventResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
  
  
class IWbemBackupRestore_Backup(DCOMCALL):
    opnum = 3
    structure = (
       ('strBackupToFile', LPWSTR),
       ('lFlags', LONG),
    )

class IWbemBackupRestore_BackupResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemBackupRestore_Restore(DCOMCALL):
    opnum = 4
    structure = (
       ('strRestoreFromFile', LPWSTR),
       ('lFlags', LONG),
    )

class IWbemBackupRestore_RestoreResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemBackupRestoreEx_Pause(DCOMCALL):
    opnum = 5
    structure = (
    )

class IWbemBackupRestoreEx_PauseResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IWbemBackupRestoreEx_Resume(DCOMCALL):
    opnum = 6
    structure = (
    )

class IWbemBackupRestoreEx_ResumeResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemRefreshingServices_AddObjectToRefresher(DCOMCALL):
    opnum = 3
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('wszPath', LPWSTR),
       ('lFlags', LONG),
       ('pContext', PMInterfacePointer),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_AddObjectToRefresherResponse(DCOMANSWER):
    structure = (
       ('pInfo', _WBEM_REFRESH_INFO),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

  
class IWbemRefreshingServices_AddObjectToRefresherByTemplate(DCOMCALL):
    opnum = 4
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('pTemplate', PMInterfacePointer),
       ('lFlags', LONG),
       ('pContext', PMInterfacePointer),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_AddObjectToRefresherByTemplateResponse(DCOMANSWER):
    structure = (
       ('pInfo', _WBEM_REFRESH_INFO),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

  
class IWbemRefreshingServices_AddEnumToRefresher(DCOMCALL):
    opnum = 5
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('wszClass', LPWSTR),
       ('lFlags', LONG),
       ('pContext', PMInterfacePointer),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_AddEnumToRefresherResponse(DCOMANSWER):
    structure = (
       ('pInfo', _WBEM_REFRESH_INFO),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

  
class IWbemRefreshingServices_RemoveObjectFromRefresher(DCOMCALL):
    opnum = 6
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('lId', LONG),
       ('lFlags', LONG),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_RemoveObjectFromRefresherResponse(DCOMANSWER):
    structure = (
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

  
class IWbemRefreshingServices_GetRemoteRefresher(DCOMCALL):
    opnum = 7
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('lFlags', LONG),
       ('dwClientRefrVersion', DWORD),
    )

class IWbemRefreshingServices_GetRemoteRefresherResponse(DCOMANSWER):
    structure = (
       ('ppRemRefresher', PMInterfacePointer),
       ('pGuid', GUID),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

  
class IWbemRefreshingServices_ReconnectRemoteRefresher(DCOMCALL):
    opnum = 8
    structure = (
       ('pRefresherId', _WBEM_REFRESHER_ID),
       ('lFlags', LONG),
       ('lNumObjects', LONG),
       ('dwClientRefrVersion', DWORD),
       ('apReconnectInfo', _WBEM_RECONNECT_INFO_ARRAY),
    )

class IWbemRefreshingServices_ReconnectRemoteRefresherResponse(DCOMANSWER):
    structure = (
       ('apReconnectResults', _WBEM_RECONNECT_RESULTS_ARRAY),
       ('pdwSvrRefrVersion', DWORD),
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemRemoteRefresher_RemoteRefresh(DCOMCALL):
    opnum = 3
    structure = (
       ('lFlags', LONG),
    )

class IWbemRemoteRefresher_RemoteRefreshResponse(DCOMANSWER):
    structure = (
       ('plNumObjects', _WBEM_RECONNECT_RESULTS_ARRAY),
       ('paObjects', PWBEM_REFRESHED_OBJECT_ARRAY),
       ('ErrorCode', error_status_t),
    )

  
class IWbemRemoteRefresher_StopRefreshing(DCOMCALL):
    opnum = 4
    structure = (
       ('lNumIds', LONG),
       ('aplIds', PULONG_ARRAY),
       ('lFlags', LONG),
    )

class IWbemRemoteRefresher_StopRefreshingResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemShutdown_Shutdown(DCOMCALL):
    opnum = 3
    structure = (
       ('reserved1', LONG),
       ('reserved2', ULONG),
       ('reserved3', PMInterfacePointer),
    )

class IWbemShutdown_ShutdownResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
  
class IUnsecuredApartment_CreateObjectStub(DCOMCALL):
    opnum = 3
    structure = (
       ('reserved1', PMInterfacePointer),
    )

class IUnsecuredApartment_CreateObjectStubResponse(DCOMANSWER):
    structure = (
       ('reserved2', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
  
class IWbemUnsecuredApartment_CreateSinkStub(DCOMCALL):
    opnum = 3
    structure = (
       ('reserved1', PMInterfacePointer),
       ('reserved2', DWORD),
       ('reserved3', LPWSTR),
    )

class IWbemUnsecuredApartment_CreateSinkStubResponse(DCOMANSWER):
    structure = (
       ('reserved4', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
  
  
OPNUMS = {
}

  
  
  
def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

class IWbemClassObject(IRemUnknown):
    def __init__(self, interface, iWbemServices = None):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemClassObject
        self.__iWbemServices = iWbemServices
        self.__methods = None

        objRef = self.get_objRef()
        objRef = OBJREF_CUSTOM(objRef)
        self.encodingUnit = ENCODING_UNIT(objRef['pObjectData'])
        self.parseObject()
        if self.encodingUnit['ObjectBlock'].isInstance() is False:
            self.createMethods(self.getClassName(), self.getMethods())
        else:
            self.createProperties(self.getProperties())

    def __getattr__(self, attr):
        if attr.startswith('__') is not True:
            properties = self.getProperties()
              
            keyProperty = None
            for pName in properties:
                if 'key' in properties[pName]['qualifiers']:
                    keyProperty = pName

            if keyProperty is None:
                LOG.error("I don't have a key property in this set!")
            else:
                if self.__methods is None:
                    classObject,_ = self.__iWbemServices.GetObject(self.getClassName())
                    self.__methods = classObject.getMethods()

                if attr in self.__methods:
                      
                    if self.getProperties()[keyProperty]['stype'] != 'string':
                        instanceName = '%s.%s=%s' % (
                        self.getClassName(), keyProperty, self.getProperties()[keyProperty]['value'])
                    else:
                        instanceName = '%s.%s="%s"' % (
                        self.getClassName(), keyProperty, self.getProperties()[keyProperty]['value'])

                    self.createMethods(instanceName , self.__methods)
                      
                    return getattr(self, attr)

        raise AttributeError("%r object has no attribute %r" %
                             (self.__class__, attr))

    def parseObject(self):
        self.encodingUnit['ObjectBlock'].parseObject()

    def getObject(self):
        return self.encodingUnit['ObjectBlock']

    def getClassName(self):
        if self.encodingUnit['ObjectBlock'].isInstance() is False:
            return self.encodingUnit['ObjectBlock']['ClassType']['CurrentClass'].getClassName().split(' ')[0]
        else:
            return self.encodingUnit['ObjectBlock']['InstanceType']['CurrentClass'].getClassName().split(' ')[0]

    def printInformation(self):
        return self.encodingUnit['ObjectBlock'].printInformation()

    def getProperties(self):
        if self.encodingUnit['ObjectBlock'].ctCurrent is None:
            return ()
        return self.encodingUnit['ObjectBlock'].ctCurrent['properties']
    
    def getMethods(self):
        if self.encodingUnit['ObjectBlock'].ctCurrent is None:
            return ()
        return self.encodingUnit['ObjectBlock'].ctCurrent['methods']

    @staticmethod
    def __ndEntry(index, null_default, inherited_default):
          
        return (bool(null_default) << 1 | bool(inherited_default)) << (2 * index)

    def marshalMe(self):
          
          
          

        instanceHeap = b''
        valueTable = b''
        ndTable = 0
        parametersClass = ENCODED_STRING()
        parametersClass['Character'] = self.getClassName()
        instanceHeap += parametersClass.getData()
        curHeapPtr = len(instanceHeap)
        properties = self.getProperties()
        for i, propName in enumerate(properties):
            propRecord = properties[propName]
            itemValue = getattr(self, propName)
            propIsInherited = propRecord['inherited']
            print("PropName %r, Value: %r" % (propName,itemValue))

            pType = propRecord['type'] & (~(CIM_ARRAY_FLAG|Inherited)) 
            if propRecord['type'] & CIM_ARRAY_FLAG:
                  
                packStr = HEAPREF[:-2]
            else:
                packStr = CIM_TYPES_REF[pType][:-2]

            if propRecord['type'] & CIM_ARRAY_FLAG:
                if itemValue is None:
                    ndTable |= self.__ndEntry(i, True, propIsInherited)
                    valueTable += pack(packStr, 0)
                else:
                    valueTable += pack('<L', curHeapPtr)
                    arraySize = pack(HEAPREF[:-2], len(itemValue))
                    packStrArray =  CIM_TYPES_REF[pType][:-2]
                    arrayItems = b''
                    for j in range(len(itemValue)):
                        arrayItems += pack(packStrArray, itemValue[j])
                    instanceHeap += arraySize + arrayItems
                    curHeapPtr = len(instanceHeap)
            elif pType in (CIM_TYPE_ENUM.CIM_TYPE_UINT8.value, CIM_TYPE_ENUM.CIM_TYPE_UINT16.value,
                           CIM_TYPE_ENUM.CIM_TYPE_UINT32.value, CIM_TYPE_ENUM.CIM_TYPE_UINT64.value):
                if itemValue is None:
                    ndTable |= self.__ndEntry(i, True, propIsInherited)
                    valueTable += pack(packStr, 0)
                else:
                    valueTable += pack(packStr, int(itemValue))
            elif pType in (CIM_TYPE_ENUM.CIM_TYPE_BOOLEAN.value,):
                if itemValue is None:
                    ndTable |= self.__ndEntry(i, True, propIsInherited)
                    valueTable += pack(packStr, False)
                else:
                    valueTable += pack(packStr, bool(itemValue))
            elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING.value, CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                               CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value, CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value):
                if itemValue is None:
                    ndTable |= self.__ndEntry(i, True, propIsInherited)
                    valueTable += pack(packStr, -1)
                else:
                    valueTable += pack(packStr, itemValue)
            elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                  
                  
                valueTable += b'\x00'*4
                if itemValue is None:
                    ndTable |= self.__ndEntry(i, True, True)
            else:
                if itemValue == '':
                      
                      
                    ndTable |= self.__ndEntry(i, True, True)
                    valueTable += pack('<L', 0)
                else:
                    strIn = ENCODED_STRING()
                    strIn['Character'] = itemValue
                    valueTable += pack('<L', curHeapPtr)
                    instanceHeap += strIn.getData()
                    curHeapPtr = len(instanceHeap)

        ndTableLen = (len(properties) - 1) // 4 + 1
        packedNdTable = b''
        for i in range(ndTableLen):
            packedNdTable += pack('B', ndTable & 0xff)
            ndTable >>=  8

          
        objRef = self.get_objRef()
        objRef = OBJREF_CUSTOM(objRef)
        encodingUnit = ENCODING_UNIT(objRef['pObjectData'])

        currentClass = encodingUnit['ObjectBlock']['InstanceType']['CurrentClass']
        encodingUnit['ObjectBlock']['InstanceType']['CurrentClass'] = b''

        encodingUnit['ObjectBlock']['InstanceType']['NdTable_ValueTable'] = packedNdTable + valueTable
        encodingUnit['ObjectBlock']['InstanceType']['InstanceHeap']['HeapLength'] = len(instanceHeap) | 0x80000000
        encodingUnit['ObjectBlock']['InstanceType']['InstanceHeap']['HeapItem'] = instanceHeap

        encodingUnit['ObjectBlock']['InstanceType']['EncodingLength'] = len(encodingUnit['ObjectBlock']['InstanceType'])
        encodingUnit['ObjectBlock']['InstanceType']['CurrentClass'] = currentClass

        encodingUnit['ObjectEncodingLength'] = len(encodingUnit['ObjectBlock'])

          
          

        objRef['pObjectData'] = encodingUnit

        return objRef

    def SpawnInstance(self):
          
          
          
        if self.encodingUnit['ObjectBlock'].isInstance() is False:
              
            encodingUnit = ENCODING_UNIT()

            instanceData = OBJECT_BLOCK()
            instanceData.structure += OBJECT_BLOCK.decoration
            instanceData.structure += OBJECT_BLOCK.instanceType
            instanceData['ObjectFlags'] = 6
            instanceData['Decoration'] = self.encodingUnit['ObjectBlock']['Decoration'].getData()

            instanceType = INSTANCE_TYPE()
            instanceType['CurrentClass'] = b''

              
            instanceHeap = b''
            valueTable = b''
            parametersClass = ENCODED_STRING()
            parametersClass['Character'] = self.getClassName()
            instanceHeap += parametersClass.getData()
            curHeapPtr = len(instanceHeap)

            ndTable = 0
            properties = self.getProperties()

              
            for i, propName in enumerate(properties):
                propRecord = properties[propName]

                pType = propRecord['type'] & (~(CIM_ARRAY_FLAG|Inherited)) 
                if propRecord['type'] & CIM_ARRAY_FLAG:
                      
                      
                      
                    packStr = HEAPREF[:-2]
                else:
                    packStr = CIM_TYPES_REF[pType][:-2]

                if propRecord['type'] & CIM_ARRAY_FLAG:
                    valueTable += pack(packStr, 0)
                elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING.value, CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                                   CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value, CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value):
                    valueTable += pack(packStr, 0)
                elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                      
                      
                    valueTable += b'\x00'*4
                    ndTable |= self.__ndEntry(i, True, True)
                else:
                    strIn = ENCODED_STRING()
                    strIn['Character'] = ''
                    valueTable += pack('<L', curHeapPtr)
                    instanceHeap += strIn.getData()
                    curHeapPtr = len(instanceHeap)

            ndTableLen = (len(properties) - 1) // 4 + 1
            packedNdTable = b''
            for i in range(ndTableLen):
                packedNdTable += pack('B', ndTable & 0xff)
                ndTable >>=  8

            instanceType['NdTable_ValueTable'] = packedNdTable + valueTable

            instanceType['InstanceQualifierSet'] = b'\x04\x00\x00\x00\x01'

            instanceType['InstanceHeap'] = HEAP()
            instanceType['InstanceHeap']['HeapItem'] = instanceHeap
            instanceType['InstanceHeap']['HeapLength'] = len(instanceHeap) | 0x80000000
            instanceType['EncodingLength'] = len(instanceType)

            instanceType['CurrentClass'] = self.encodingUnit['ObjectBlock']['ClassType']['CurrentClass']['ClassPart']
            instanceData['InstanceType'] = instanceType.getData()

            encodingUnit['ObjectBlock'] = instanceData
            encodingUnit['ObjectEncodingLength'] = len(instanceData)

              

            objRefCustomIn = OBJREF_CUSTOM()
            objRefCustomIn['iid'] = self._iid
            objRefCustomIn['clsid'] = CLSID_WbemClassObject
            objRefCustomIn['cbExtension'] = 0
            objRefCustomIn['ObjectReferenceSize'] = len(encodingUnit)
            objRefCustomIn['pObjectData'] = encodingUnit

              
              
            import copy
            newObj = copy.deepcopy(self)
            newObj.set_objRef(objRefCustomIn.getData())
            newObj.process_interface(objRefCustomIn.getData())
            newObj.encodingUnit = ENCODING_UNIT(encodingUnit.getData())
            newObj.parseObject()
            if newObj.encodingUnit['ObjectBlock'].isInstance() is False:
                newObj.createMethods(newObj.getClassName(), newObj.getMethods())
            else:
                newObj.createProperties(newObj.getProperties())

            return newObj
        else:
            return self

    def createProperties(self, properties):
        for property in properties:
              
            if properties[property]['type'] == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                  
                objRef = OBJREF_CUSTOM()
                objRef['iid'] = self._iid
                objRef['clsid'] = CLSID_WbemClassObject
                objRef['cbExtension'] = 0
                objRef['ObjectReferenceSize'] = len(properties[property]['value'].getData())
                objRef['pObjectData'] = properties[property]['value']
                value = IWbemClassObject( INTERFACE(self.get_cinstance(), objRef.getData(), self.get_ipidRemUnknown(),
                      oxid=self.get_oxid(), target=self.get_target()))
            elif properties[property]['type'] == CIM_TYPE_ENUM.CIM_ARRAY_OBJECT.value:
                if isinstance(properties[property]['value'], list):
                    value = list()
                    for item in properties[property]['value']:
                          
                        objRef = OBJREF_CUSTOM()
                        objRef['iid'] = self._iid
                        objRef['clsid'] = CLSID_WbemClassObject
                        objRef['cbExtension'] = 0
                        objRef['ObjectReferenceSize'] = len(item.getData())
                        objRef['pObjectData'] = item
                        wbemClass = IWbemClassObject(
                            INTERFACE(self.get_cinstance(), objRef.getData(), self.get_ipidRemUnknown(),
                                      oxid=self.get_oxid(), target=self.get_target()))
                        value.append(wbemClass)
                else:
                    value = properties[property]['value']
            else:
                value = properties[property]['value']
            setattr(self, property, value)

    def createMethods(self, classOrInstance, methods):
        class FunctionPool:
            def __init__(self,function):
                self.function = function
            def __getitem__(self,item):
                return partial(self.function,item)

        @FunctionPool
        def innerMethod(staticArgs, *args):
            classOrInstance = staticArgs[0] 
            methodDefinition = staticArgs[1] 
            if methodDefinition['InParams'] is not None:
                if len(args) != len(methodDefinition['InParams']):
                    LOG.error("Function called with %d parameters instead of %d!" % (len(args), len(methodDefinition['InParams'])))
                    return None
                  
                encodingUnit = ENCODING_UNIT()

                inParams = OBJECT_BLOCK()
                inParams.structure += OBJECT_BLOCK.instanceType
                inParams['ObjectFlags'] = 2
                inParams['Decoration'] = b''

                instanceType = INSTANCE_TYPE()
                instanceType['CurrentClass'] = b''
                instanceType['InstanceQualifierSet'] = b'\x04\x00\x00\x00\x01'

                  
                instanceHeap = b''
                valueTable = b''
                parametersClass = ENCODED_STRING()
                parametersClass['Character'] = '__PARAMETERS'
                instanceHeap += parametersClass.getData()
                curHeapPtr = len(instanceHeap)

                ndTable = 0
                for i in range(len(args)):
                    paramDefinition = list(methodDefinition['InParams'].values())[i]
                    inArg = args[i]

                    pType = paramDefinition['type'] & (~(CIM_ARRAY_FLAG|Inherited)) 
                    if paramDefinition['type'] & CIM_ARRAY_FLAG:
                          
                          
                          
                        packStr = HEAPREF[:-2]
                    else:
                        packStr = CIM_TYPES_REF[pType][:-2]

                    if paramDefinition['type'] & CIM_ARRAY_FLAG:
                        if inArg is None:
                            valueTable += pack(packStr, 0)
                        elif pType in (CIM_TYPE_ENUM.CIM_TYPE_STRING.value, CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                                       CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value, CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value):
                            arraySize = pack(HEAPREF[:-2], len(inArg))
                            arrayItems = []
                            for j in range(len(inArg)):
                                curVal = inArg[j]
                                if pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                                    curObject = b''
                                    marshaledObject = curVal.marshalMe()
                                    curObject += pack('<L', marshaledObject['pObjectData']['ObjectEncodingLength'])
                                    curObject += marshaledObject['pObjectData']['ObjectBlock'].getData()
                                    arrayItems.append(curObject)
                                    continue
                                strIn = ENCODED_STRING()
                                if type(curVal) is str:
                                      
                                      
                                      
                                    strIn['Encoded_String_Flag'] = 0x1
                                    strIn.structure = strIn.tunicode
                                    strIn['Character'] = curVal.encode('utf-16le')
                                else:
                                    strIn['Character'] = curVal
                                arrayItems.append(strIn.getData())


                            curStrHeapPtr = curHeapPtr + 4
                            arrayHeapPtrValues = b''
                            arrayValueTable = b''
                            for j in range(len(arrayItems)):
                                arrayHeapPtrValues += pack('<L', curStrHeapPtr + 4 * (len(arrayItems) - j) + len(arrayValueTable))
                                arrayValueTable += arrayItems[j]
                                curStrHeapPtr += 4

                            valueTable += pack('<L', curHeapPtr)
                            instanceHeap += arraySize + arrayHeapPtrValues + arrayValueTable
                            curHeapPtr = len(instanceHeap)
                        else:
                            arraySize = pack(HEAPREF[:-2], len(inArg))
                            valueTable += pack('<L', curHeapPtr)
                            instanceHeap += arraySize
                            for curVal in inArg:
                                instanceHeap += pack(packStr, curVal)
                            curHeapPtr = len(instanceHeap)
                    elif pType not in (CIM_TYPE_ENUM.CIM_TYPE_STRING.value, CIM_TYPE_ENUM.CIM_TYPE_DATETIME.value,
                                       CIM_TYPE_ENUM.CIM_TYPE_REFERENCE.value, CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value):
                        valueTable += pack(packStr, inArg)
                    elif pType == CIM_TYPE_ENUM.CIM_TYPE_OBJECT.value:
                        if inArg is None:
                              
                              
                            valueTable += b'\x00' * 4
                            ndTable |= self.__ndEntry(i, True, True)
                        else:
                            valueTable += pack('<L', curHeapPtr)
                            marshaledObject = inArg.marshalMe()
                            instanceHeap += pack('<L', marshaledObject['pObjectData']['ObjectEncodingLength'])
                            instanceHeap += marshaledObject['pObjectData']['ObjectBlock'].getData()
                            curHeapPtr = len(instanceHeap)
                    else:
                        strIn = ENCODED_STRING()
                        if type(inArg) is str:
                              
                              
                              
                            strIn['Encoded_String_Flag'] = 0x1
                            strIn.structure = strIn.tunicode
                            strIn['Character'] = inArg.encode('utf-16le')
                        else:
                            strIn['Character'] = inArg
                        valueTable += pack('<L', curHeapPtr)
                        instanceHeap += strIn.getData()
                        curHeapPtr = len(instanceHeap)

                ndTableLen = (len(args) - 1) // 4 + 1

                packedNdTable = b''
                for i in range(ndTableLen):
                    packedNdTable += pack('B', ndTable & 0xff)
                    ndTable >>=  8

                instanceType['NdTable_ValueTable'] = packedNdTable + valueTable
                heapRecord = HEAP()
                heapRecord['HeapLength'] = len(instanceHeap) | 0x80000000
                heapRecord['HeapItem'] = instanceHeap
                
                instanceType['InstanceHeap'] = heapRecord

                instanceType['EncodingLength'] = len(instanceType)
                inMethods = methodDefinition['InParamsRaw']['ClassType']['CurrentClass']['ClassPart']
                inMethods['ClassHeader']['EncodingLength'] = len(
                    methodDefinition['InParamsRaw']['ClassType']['CurrentClass']['ClassPart'].getData())
                instanceType['CurrentClass'] = inMethods

                inParams['InstanceType'] = instanceType.getData()

                encodingUnit['ObjectBlock'] = inParams
                encodingUnit['ObjectEncodingLength'] = len(inParams)

                objRefCustomIn = OBJREF_CUSTOM()
                objRefCustomIn['iid'] = self._iid
                objRefCustomIn['clsid'] = CLSID_WbemClassObject
                objRefCustomIn['cbExtension'] = 0
                objRefCustomIn['ObjectReferenceSize'] = len(encodingUnit)
                objRefCustomIn['pObjectData'] = encodingUnit
            else:
                objRefCustomIn = NULL

              
            encodingUnit = ENCODING_UNIT()

            outParams = OBJECT_BLOCK()
            outParams.structure += OBJECT_BLOCK.instanceType
            outParams['ObjectFlags'] = 2
            outParams['Decoration'] = b''

            instanceType = INSTANCE_TYPE()
            instanceType['CurrentClass'] = b''
            instanceType['NdTable_ValueTable'] = b''
            instanceType['InstanceQualifierSet'] = b''
            instanceType['InstanceHeap'] = b''
            instanceType['EncodingLength'] = len(instanceType)
            instanceType['CurrentClass'] = methodDefinition['OutParamsRaw']['ClassType']['CurrentClass']['ClassPart'].getData()
            outParams['InstanceType'] = instanceType.getData()


            encodingUnit['ObjectBlock'] = outParams
            encodingUnit['ObjectEncodingLength'] = len(outParams)

            objRefCustom = OBJREF_CUSTOM()
            objRefCustom['iid'] = self._iid
            objRefCustom['clsid'] = CLSID_WbemClassObject
            objRefCustom['cbExtension'] = 0
            objRefCustom['ObjectReferenceSize'] = len(encodingUnit)
            objRefCustom['pObjectData'] = encodingUnit
            try:
                return self.__iWbemServices.ExecMethod(classOrInstance, methodDefinition['name'], pInParams = objRefCustomIn )
                  
                  
            except Exception as e:
                if LOG.level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                LOG.error(str(e))

        for methodName in methods:
           innerMethod.__name__ = methodName
           setattr(self,innerMethod.__name__,innerMethod[classOrInstance,methods[methodName]])
          
 

class IWbemLoginClientID(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemLoginClientID

    def SetClientInfo(self, wszClientMachine, lClientProcId = 1234):
        request = IWbemLoginClientID_SetClientInfo()
        request['wszClientMachine'] = checkNullString(wszClientMachine)
        request['lClientProcId'] = lClientProcId
        request['lReserved'] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp

class IWbemLoginHelper(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemLoginHelper

    def SetEvent(self, sEventToSet):
        request = IWbemLoginHelper_SetEvent()
        request['sEventToSet'] = sEventToSet
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp


class IWbemWCOSmartEnum(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemWCOSmartEnum

    def Next(self, proxyGUID, lTimeout, uCount):
        request = IWbemWCOSmartEnum_Next()
        request['proxyGUID'] = proxyGUID
        request['lTimeout'] = lTimeout
        request['uCount'] = uCount
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IWbemFetchSmartEnum(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemFetchSmartEnum

    def GetSmartEnum(self, lTimeout):
        request = IWbemFetchSmartEnum_GetSmartEnum()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IWbemCallResult(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemCallResult

    def GetResultObject(self, lTimeout):
        request = IWbemCallResult_GetResultObject()
        request['lTimeout'] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetResultString(self, lTimeout):
        request = IWbemCallResult_GetResultString()
        request['lTimeout'] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetResultServices(self, lTimeout):
        request = IWbemCallResult_GetResultServices()
        request['lTimeout'] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def GetCallStatus(self, lTimeout):
        request = IWbemCallResult_GetCallStatus()
        request['lTimeout'] = lTimeout
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp['plStatus']

class IEnumWbemClassObject(IRemUnknown):
    def __init__(self, interface, iWbemServices = None):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IEnumWbemClassObject
        self.__iWbemServices = iWbemServices

    def Reset(self):
        request = IEnumWbemClassObject_Reset()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def Next(self, lTimeout, uCount):
        request = IEnumWbemClassObject_Next()
        request['lTimeout'] = lTimeout
        request['uCount'] = uCount
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        interfaces = list()
        for interface in resp['apObjects']:
            interfaces.append(IWbemClassObject(
                INTERFACE(self.get_cinstance(), b''.join(interface['abData']), self.get_ipidRemUnknown(),
                          oxid=self.get_oxid(), target=self.get_target()), self.__iWbemServices))

        return interfaces

    def NextAsync(self, lTimeout, pSink):
        request = IEnumWbemClassObject_NextAsync()
        request['lTimeout'] = lTimeout
        request['pSink'] = pSink
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def Clone(self):
        request = IEnumWbemClassObject_Clone()
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def Skip(self, lTimeout, uCount):
        request = IEnumWbemClassObject_Skip()
        request['lTimeout'] = lTimeout
        request['uCount'] = uCount
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IWbemServices(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemServices

    def OpenNamespace(self, strNamespace, lFlags=0, pCtx = NULL):
        request = IWbemServices_OpenNamespace()
        request['strNamespace']['asData'] = strNamespace
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def CancelAsyncCall(self,IWbemObjectSink ):
        request = IWbemServices_CancelAsyncCall()
        request['IWbemObjectSink'] = IWbemObjectSink
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp['ErrorCode']

    def QueryObjectSink(self):
        request = IWbemServices_QueryObjectSink()
        request['lFlags'] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return INTERFACE(self.get_cinstance(), b''.join(resp['ppResponseHandler']['abData']), self.get_ipidRemUnknown(),
                         target=self.get_target())

    def GetObject(self, strObjectPath, lFlags=0, pCtx=NULL):
        request = IWbemServices_GetObject()
        request['strObjectPath']['asData'] = strObjectPath
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        ppObject = IWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp['ppObject']['abData']), self.get_ipidRemUnknown(),
                      oxid=self.get_oxid(), target=self.get_target()), self)
        if resp['ppCallResult'] != NULL:
            ppcallResult = IWbemCallResult(
                INTERFACE(self.get_cinstance(), b''.join(resp['ppObject']['abData']), self.get_ipidRemUnknown(),
                          target=self.get_target()))
        else:
            ppcallResult = NULL
        return ppObject, ppcallResult

    def GetObjectAsync(self, strNamespace, lFlags=0, pCtx = NULL):
        request = IWbemServices_GetObjectAsync()
        request['strObjectPath']['asData'] = checkNullString(strNamespace)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def PutClass(self, pObject, lFlags=0, pCtx=NULL):
        request = IWbemServices_PutClass()
        request['pObject'] = pObject
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def PutClassAsync(self, pObject, lFlags=0, pCtx=NULL):
        request = IWbemServices_PutClassAsync()
        request['pObject'] = pObject
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def DeleteClass(self, strClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_DeleteClass()
        request['strClass']['asData'] = checkNullString(strClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def DeleteClassAsync(self, strClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_DeleteClassAsync()
        request['strClass']['asData'] = checkNullString(strClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def CreateClassEnum(self, strSuperClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_CreateClassEnum()
        request['strSuperClass']['asData'] = checkNullString(strSuperClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def CreateClassEnumAsync(self, strSuperClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_CreateClassEnumAsync()
        request['strSuperClass']['asData'] = checkNullString(strSuperClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def PutInstance(self, pInst, lFlags=0, pCtx=NULL):
        request = IWbemServices_PutInstance()

        if pInst is NULL:
            request['pInst'] = pInst
        else:
            request['pInst']['ulCntData'] = len(pInst)
            request['pInst']['abData'] = list(pInst.getData())
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IWbemCallResult(
            INTERFACE(self.get_cinstance(), b''.join(resp['ppCallResult']['abData']), self.get_ipidRemUnknown(),
                      target=self.get_target()))

    def PutInstanceAsync(self, pInst, lFlags=0, pCtx=NULL):
        request = IWbemServices_PutInstanceAsync()
        request['pInst'] = pInst
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def DeleteInstance(self, strObjectPath, lFlags=0, pCtx=NULL):
        request = IWbemServices_DeleteInstance()
        request['strObjectPath']['asData'] = checkNullString(strObjectPath)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IWbemCallResult(
            INTERFACE(self.get_cinstance(), b''.join(resp['ppCallResult']['abData']), self.get_ipidRemUnknown(),
                      target=self.get_target()))

    def DeleteInstanceAsync(self, strObjectPath, lFlags=0, pCtx=NULL):
        request = IWbemServices_DeleteInstanceAsync()
        request['strObjectPath']['asData'] = checkNullString(strObjectPath)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def CreateInstanceEnum(self, strSuperClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_CreateInstanceEnum()
        request['strSuperClass']['asData'] = strSuperClass
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return IEnumWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(),
                      target=self.get_target()))

    def CreateInstanceEnumAsync(self, strSuperClass, lFlags=0, pCtx=NULL):
        request = IWbemServices_CreateInstanceEnumAsync()
        request['strSuperClass']['asData'] = checkNullString(strSuperClass)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

      
    def ExecQuery(self, strQuery, lFlags=0, pCtx=NULL):
        request = IWbemServices_ExecQuery()
        request['strQueryLanguage']['asData'] = checkNullString('WQL')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IEnumWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(),
                      target=self.get_target()), self)

    def ExecQueryAsync(self, strQuery, lFlags=0, pCtx=NULL):
        request = IWbemServices_ExecQueryAsync()
        request['strQueryLanguage']['asData'] = checkNullString('WQL')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def ExecNotificationQuery(self, strQuery, lFlags=0, pCtx=NULL):
        request = IWbemServices_ExecNotificationQuery()
        request['strQueryLanguage']['asData'] = checkNullString('WQL')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IEnumWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(),
                      target=self.get_target()), self)

    def ExecNotificationQueryAsync(self, strQuery, lFlags=0, pCtx=NULL):
        request = IWbemServices_ExecNotificationQueryAsync()
        request['strQueryLanguage']['asData'] = checkNullString('WQL')
        request['strQuery']['asData'] = checkNullString(strQuery)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

    def ExecMethod(self, strObjectPath, strMethodName, lFlags=0, pCtx=NULL, pInParams=NULL, ppOutParams = NULL):
        request = IWbemServices_ExecMethod()
        request['strObjectPath']['asData'] = checkNullString(strObjectPath)
        request['strMethodName']['asData'] = checkNullString(strMethodName)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        if pInParams is NULL:
            request['pInParams'] = pInParams
        else:
            request['pInParams']['ulCntData'] = len(pInParams)
            request['pInParams']['abData'] = list(pInParams.getData())

        request.fields['ppCallResult'] = NULL
        if ppOutParams is NULL:
            request.fields['ppOutParams'].fields['Data'] = NULL
        else:
            request['ppOutParams']['ulCntData'] = len(ppOutParams.getData())
            request['ppOutParams']['abData'] = list(ppOutParams.getData())
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IWbemClassObject(
            INTERFACE(self.get_cinstance(), b''.join(resp['ppOutParams']['abData']), self.get_ipidRemUnknown(),
                      oxid=self.get_oxid(), target=self.get_target()))

    def ExecMethodAsync(self, strObjectPath, strMethodName, lFlags=0, pCtx=NULL, pInParams=NULL):
        request = IWbemServices_ExecMethodAsync()
        request['strObjectPath']['asData'] = checkNullString(strObjectPath)
        request['strMethodName']['asData'] = checkNullString(strMethodName)
        request['lFlags'] = lFlags
        request['pCtx'] = pCtx
        request['pInParams'] = pInParams
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        resp.dump()
        return resp

class IWbemLevel1Login(IRemUnknown):
    def __init__(self, interface):
        IRemUnknown.__init__(self,interface)
        self._iid = IID_IWbemLevel1Login

    def EstablishPosition(self):
        request = IWbemLevel1Login_EstablishPosition()
        request['reserved1'] = NULL
        request['reserved2'] = 0
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp['LocaleVersion']

    def RequestChallenge(self):
        request = IWbemLevel1Login_RequestChallenge()
        request['reserved1'] = NULL
        request['reserved2'] = NULL
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp['reserved3']

    def WBEMLogin(self):
        request = IWbemLevel1Login_WBEMLogin()
        request['reserved1'] = NULL
        request['reserved2'] = NULL
        request['reserved3'] = 0
        request['reserved4'] = NULL
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return resp['reserved5']

    def NTLMLogin(self, wszNetworkResource, wszPreferredLocale, pCtx):
        request = IWbemLevel1Login_NTLMLogin()
        request['wszNetworkResource'] = checkNullString(wszNetworkResource)
        request['wszPreferredLocale'] = checkNullString(wszPreferredLocale)
        request['lFlags'] = 0
        request['pCtx'] = pCtx
        resp = self.request(request, iid = self._iid, uuid = self.get_iPid())
        return IWbemServices(
            INTERFACE(self.get_cinstance(), b''.join(resp['ppNamespace']['abData']), self.get_ipidRemUnknown(),
                      target=self.get_target()))


if __name__ == '__main__':
      
    baseClass = b'xV4\x12\xd0\x00\x00\x00\x05\x00DPRAVAT-DEV\x00\x00ROOT\x00\x1d\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80f\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x04\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x06\x00\x00\x00\n\x00\x00\x00\x05\xff\xff\xff\xff<\x00\x00\x80\x00Base\x00\x00Id\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\n\x00\x00\x80\x03\x08\x00\x00\x004\x00\x00\x00\x01\x00\x00\x80\x13\x0b\x00\x00\x00\xff\xff\x00sint32\x00\x0c\x00\x00\x00\x00\x004\x00\x00\x00\x00\x80\x00\x80\x13\x0b\x00\x00\x00\xff\xff\x00sint32\x00'

      
      
      
      

      
      
      
      
      
      

      
      
      
      
