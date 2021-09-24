from __future__ import division
from __future__ import print_function
from struct import unpack
from datetime import datetime
from six import PY2
import binascii

from libs import hresult_errors, mapi_constants, uuid
from libs.uuid import EMPTY_UUID
from libs.structure import Structure
from libs.dcerpc.v5.dtypes import NULL, STR, DWORD, LPDWORD, UUID, PUUID, LONG, ULONG, \
    FILETIME, PFILETIME, BYTE, SHORT, LPSTR, LPWSTR, USHORT, LPLONG, DWORD_ARRAY
from libs.ldap.ldaptypes import LDAP_SID
from libs.dcerpc.v5.ndr import NDR, NDRCALL, NDRPOINTER, NDRSTRUCT, NDRUNION, \
    NDRUniConformantVaryingArray, NDRUniConformantArray, NDRUniVaryingArray
from libs.dcerpc.v5.rpcrt import DCERPCException
from libs.uuid import string_to_bin, uuidtup_to_bin, EMPTY_UUID

MSRPC_UUID_NSPI = uuidtup_to_bin(('F5CC5A18-4264-101A-8C59-08002B2F8426', '56.0'))

class DCERPCSessionError(DCERPCException):
    def __str__( self ):
        key = self.error_code
        if key in mapi_constants.ERROR_MESSAGES:
            error_msg_short = mapi_constants.ERROR_MESSAGES[key]
            return 'NSPI SessionError: code: 0x%x - %s' % (self.error_code, error_msg_short)
        elif key in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'NSPI SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'NSPI SessionError: unknown error code: 0x%x' % self.error_code

  
  
  
class handle_t(NDRSTRUCT):
    structure = (
         ('context_handle_attributes',ULONG),
         ('context_handle_uuid',UUID),
    )

    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        self['context_handle_uuid'] = b'\x00'*16

    def isNull(self):
        return self['context_handle_uuid'] == b'\x00'*16

  
PtypEmbeddedTable = 0x0000000D
PtypNull          = 0x00000001
PtypUnspecified   = 0x00000000

  
DT_MAILUSER         = 0x00000000
DT_DISTLIST         = 0x00000001
DT_FORUM            = 0x00000002
DT_AGENT            = 0x00000003
DT_ORGANIZATION     = 0x00000004
DT_PRIVATE_DISTLIST = 0x00000005
DT_REMOTE_MAILUSER  = 0x00000006
DT_CONTAINER        = 0x00000100
DT_TEMPLATE         = 0x00000101
DT_ADDRESS_TEMPLATE = 0x00000102
DT_SEARCH           = 0x00000200

  
NSPI_DEFAULT_LOCALE = 0x00000409

  
CP_TELETEX    = 0x00004F25
CP_WINUNICODE = 0x000004B0

  
NORM_IGNORECASE     = 1 << 0
NORM_IGNORENONSPACE = 1 << 1
NORM_IGNORESYMBOLS  = 1 << 2
SORT_STRINGSORT     = 1 << 12
NORM_IGNOREKANATYPE = 1 << 16
NORM_IGNOREWIDTH    = 1 << 17

  
GUID_NSPI = string_to_bin("C840A7DC-42C0-1A10-B4B9-08002B2FE182")

  
MID_BEGINNING_OF_TABLE = 0x00000000
MID_END_OF_TABLE       = 0x00000002
MID_CURRENT            = 0x00000001

  
MID_UNRESOLVED = 0x00000000
MID_AMBIGUOUS  = 0x00000001
MID_RESOLVED   = 0x00000002

  
SortTypeDisplayName         = 0
SortTypePhoneticDisplayName = 0x00000003
SortTypeDisplayName_RO      = 0x000003E8
SortTypeDisplayName_W       = 0x000003E9

  
fAnonymousLogin = 0x00000020

  
fSkipObjects = 0x00000001
fEphID       = 0x00000002

  
NspiAddressCreationTemplates = 0x00000002
NspiUnicodeStrings           = 0x00000004

  
NspiUnicodeProptypes = 0x80000000

  
NspiVerifyNames = 0x00000002

  
TI_TEMPLATE          = 0x00000001
TI_SCRIPT            = 0x00000004
TI_EMT               = 0x00000010
TI_HELPFILE_NAME     = 0x00000020
TI_HELPFILE_CONTENTS = 0x00000040

  
fDelete = 0x00000001

  
FlatUID_r = UUID
PFlatUID_r = PUUID

  
class PropertyTagArray(NDRUniConformantVaryingArray):
    item = DWORD

class PropertyTagArray_r(NDRSTRUCT):
    structure = (
         ('cValues', ULONG),
         ('aulPropTag', PropertyTagArray)
    )

class PPropertyTagArray_r(NDRPOINTER):
    referent = (
         ('Data', PropertyTagArray_r),
    )

  
class Binary(NDRUniConformantArray):
    item = 'c'

class PBinary(NDRPOINTER):
    referent = (
         ('Data', Binary),
    )

class Binary_r(NDRSTRUCT):
    structure = (
         ('cValues', DWORD),
         ('lpb', PBinary),
    )

  
class ShortArray(NDRUniConformantArray):
    item = SHORT

class PShortArray(NDRPOINTER):
    referent = (
         ('Data', ShortArray),
    )

class ShortArray_r(NDRSTRUCT):
    structure = (
         ('cValues', DWORD),
         ('lpi', PShortArray),
    )

  
class LongArray(NDRUniConformantArray):
    item = LONG

class PLongArray(NDRPOINTER):
    referent = (
         ('Data', LongArray),
    )

class LongArray_r(NDRSTRUCT):
    structure = (
         ('cValues', DWORD),
         ('lpl', PLongArray)
    )

  
class StringArray(NDRUniConformantArray):
    item = LPSTR

class PStringArray(NDRPOINTER):
    referent = (
         ('Data', StringArray),
    )

class StringArray_r(NDRSTRUCT):
    structure = (
         ('cValues', DWORD),
         ('lppszA', PStringArray)
    )

  
class BinaryArray(NDRUniConformantArray):
    item = Binary_r

class PBinaryArray(NDRPOINTER):
    referent = (
         ('Data', BinaryArray),
    )

class BinaryArray_r(NDRSTRUCT):
    structure = (
         ('cValues', DWORD),
         ('lpbin', PBinaryArray)
    )

  
class FlatUIDArray(NDRUniConformantArray):
    item = PFlatUID_r

class PFlatUIDArray(NDRPOINTER):
    referent = (
         ('Data', FlatUIDArray),
    )

class FlatUIDArray_r(NDRSTRUCT):
    structure = (
         ('cValues', DWORD),
         ('lpguid', PFlatUIDArray)
    )

  
class WStringArray(NDRUniConformantArray):
    item = LPWSTR

class PWStringArray(NDRPOINTER):
    referent = (
         ('Data', WStringArray),
    )

class WStringArray_r(NDRSTRUCT):
    structure = (
         ('cValues', DWORD),
         ('lppszW', PWStringArray)
    )

  
class DateTimeArray(NDRUniConformantArray):
    item = PFILETIME

class PDateTimeArray(NDRPOINTER):
    referent = (
         ('Data', DateTimeArray),
    )

class DateTimeArray_r(NDRSTRUCT):
    structure = (
         ('cValues', DWORD),
         ('lpft', PDateTimeArray)
    )

  
class PROP_VAL_UNION(NDRUNION):
    commonHdr = (
         ('tag', DWORD),
    )

    union = {
        0x0002: ('i', SHORT),                 
        0x0003: ('l', LONG),                  
        0x000B: ('b', USHORT),                
        0x001E: ('lpszA', LPSTR),             
        0x0102: ('bin', Binary_r),            
        0x001F: ('lpszW', LPWSTR),            
        0x0048: ('lpguid', PFlatUID_r),       
        0x0040: ('ft', FILETIME),             
        0x000A: ('err', ULONG),               
        0x1002: ('MVi', ShortArray_r),        
        0x1003: ('MVl', LongArray_r),         
        0x101E: ('MVszA', StringArray_r),     
        0x1102: ('MVbin', BinaryArray_r),     
        0x1048: ('MVguid', FlatUIDArray_r),   
        0x101F: ('MVszW', WStringArray_r),    
        0x1040: ('MVft', DateTimeArray_r),    
        0x0001: ('lReserved', LONG),          
        0x000D: ('lReserved', LONG),          
        0x0000: ('lReserved', LONG),          
    }

  
class PropertyValue_r(NDRSTRUCT):
    structure = (
         ('ulPropTag', DWORD),
         ('ulReserved', DWORD),   
         ('Value', PROP_VAL_UNION),
    )

class PPropertyValue_r(NDRPOINTER):
    referent = (
         ('Data', PropertyValue_r),
    )

  
class PropertyValue(NDRUniConformantArray):
    item = PropertyValue_r

class PPropertyValue(NDRPOINTER):
    referent = (
         ('Data', PropertyValue),
    )

class PropertyRow_r(NDRSTRUCT):
    structure = (
         ('Reserved', DWORD),   
         ('cValues', DWORD),
         ('lpProps', PPropertyValue)
    )

class PPropertyRow_r(NDRPOINTER):
    referent = (
         ('Data', PropertyRow_r),
    )

  
class PropertyRowSet(NDRUniConformantArray): 
    item = PropertyRow_r

class PropertyRowSet_r(NDRSTRUCT):
    structure = (
         ('cRows', DWORD),
         ('aRow', PropertyRowSet),
    )

class PPropertyRowSet_r(NDRPOINTER):
    referent = (
         ('Data', PropertyRowSet_r),
    )

  
class Restriction_r(NDRSTRUCT):
    pass

class PRestriction_r(NDRPOINTER):
    referent = (
         ('Data', Restriction_r),
    )

  
class AndRestriction(NDRUniConformantArray): 
    item = Restriction_r

class PAndRestriction(NDRPOINTER):
    referent = (
         ('Data', AndRestriction),
    )

class AndRestriction_r(NDRSTRUCT):
    structure = (
         ('cRes', DWORD),
         ('lpRes', PAndRestriction),
    )

OrRestriction_r = AndRestriction_r

  
class NotRestriction_r(NDRSTRUCT):
    structure = (
         ('lpRes', PRestriction_r),
    )

  
class ContentRestriction_r(NDRSTRUCT):
    structure = (
         ('ulFuzzyLevel', DWORD),
         ('ulPropTag', DWORD),
         ('lpProp', PPropertyValue_r),
    )

  
class BitMaskRestriction_r(NDRSTRUCT):
    structure = (
         ('relBMR', DWORD),
         ('ulPropTag', DWORD),
         ('ulMask', DWORD),
    )

  
class PropertyRestriction_r(NDRSTRUCT):
    structure = (
         ('relop', DWORD),
         ('ulPropTag', DWORD),
         ('lpProp', PPropertyValue_r),
    )

  
class ComparePropsRestriction_r(NDRSTRUCT):
    structure = (
         ('relop', DWORD),
         ('ulPropTag1', DWORD),
         ('ulPropTag2', DWORD),
    )

  
class SubRestriction_r(NDRSTRUCT):
    structure = (
         ('ulSubObject', DWORD),
         ('lpRes', PRestriction_r),
    )

  
class SizeRestriction_r(NDRSTRUCT):
    structure = (
         ('relop', DWORD),
         ('ulPropTag', DWORD),
         ('cb', DWORD),
    )

  
class ExistRestriction_r(NDRSTRUCT):
    structure = (
         ('ulReserved1', DWORD),
         ('ulPropTag', DWORD),
         ('ulReserved2', DWORD),
    )

  
class RestrictionUnion_r(NDRUNION):
    commonHdr = (
         ('tag', DWORD),
    )

    union = {
        0x00000000: ('resAnd', AndRestriction_r),
        0x00000001: ('resOr', OrRestriction_r),
        0x00000002: ('resNot', NotRestriction_r),
        0x00000003: ('resContent', ContentRestriction_r),
        0x00000004: ('resProperty', PropertyRestriction_r),
        0x00000005: ('resCompareProps', ComparePropsRestriction_r),
        0x00000006: ('resBitMask', BitMaskRestriction_r),
        0x00000007: ('resSize', SizeRestriction_r),
        0x00000008: ('resExist', ExistRestriction_r),
        0x00000009: ('resSubRestriction', SubRestriction_r),
    }

  
Restriction_r.structure = (
    ('rt', DWORD),
    ('res', RestrictionUnion_r),
)

  
class PropertyName_r(NDRSTRUCT):
    structure = (
         ('lpguid', PFlatUID_r),
         ('ulReserved', DWORD),
         ('lID', LONG),
    )

class PPropertyName_r(NDRPOINTER):
    referent = (
         ('Data', PropertyName_r),
    )

  
class PropertyNameSet(NDRUniConformantArray):
    item = PropertyName_r

class PropertyNameSet_r(NDRSTRUCT):
    structure = (
         ('cNames', DWORD),
         ('aulPropTag', PropertyNameSet)
    )

class PPropertyNameSet_r(NDRPOINTER):
    referent = (
         ('Data', PropertyNameSet_r),
    )

  
class StringsArray(NDRUniConformantArray):
    item = LPSTR

class StringsArray_r(NDRSTRUCT):
    structure = (
         ('Count', DWORD),
         ('Strings', StringsArray)
    )

  
class WStringsArray(NDRUniConformantArray):
    item = LPWSTR

class WStringsArray_r(NDRSTRUCT):
    structure = (
         ('Count', DWORD),
         ('Strings', WStringsArray)
    )

  
class STAT(NDRSTRUCT):
    structure = (
         ('SortType', DWORD),
         ('ContainerID', DWORD),
         ('CurrentRec', DWORD),
         ('Delta', LONG),
         ('NumPos', DWORD),
         ('TotalRecs', DWORD),
         ('CodePage', DWORD),
         ('TemplateLocale', DWORD),
         ('SortLocale', DWORD),
    )

class PSTAT(NDRPOINTER):
    referent = (
         ('Data', STAT),
    )

  
MinEntryID = '<L=0'

  
class EphemeralEntryID(Structure):
    structure = (
         ('IDType','<B=0x87'),
         ('R1','<B=0'),
         ('R2','<B=0'),
         ('R3','<B=0'),
         ('ProviderUID','16s=b"\\x00"*16'),
         ('R4','<L=0x0000001'),
         ('DisplayType','<L'),
         ('MId',MinEntryID),
    )

  
class PermanentEntryID(Structure):
    default_guid = GUID_NSPI
    structure = (
         ('IDType','<B=0'),
         ('R1','<B=0'),
         ('R2','<B=0'),
         ('R3','<B=0'),
         ('ProviderUID','16s=self["default_guid"]'),
         ('R4','<L=0x0000001'),
         ('DisplayType','<L'),
         ('DistinguishedName','z'),
    )

    def __str__(self):
        return self["DistinguishedName"]

  
  
  

  
class NspiBind(NDRCALL):
    opnum = 0
    structure = (
        ('dwFlags', DWORD),
        ('pStat', STAT),
        ('pServerGuid', PFlatUID_r),
    )

class NspiBindResponse(NDRCALL):
    structure = (
        ('pServerGuid', PFlatUID_r),
        ('contextHandle', handle_t),
        ('ErrorCode', ULONG),
    )

  
class NspiUnbind(NDRCALL):
    opnum = 1
    structure = (
        ('contextHandle', handle_t),
        ('Reserved', DWORD),   
    )

class NspiUnbindResponse(NDRCALL):
    structure = (
        ('contextHandle', handle_t),
        ('ErrorCode', ULONG),
    )

  
class NspiUpdateStat(NDRCALL):
    opnum = 2
    structure = (
        ('hRpc', handle_t),
        ('Reserved', DWORD),   
        ('pStat', STAT),
        ('plDelta', LPLONG),
    )

class NspiUpdateStatResponse(NDRCALL):
    structure = (
        ('pStat', STAT),
        ('plDelta', LPLONG),
        ('ErrorCode', ULONG),
    )

  
class DWORD_ARRAY(NDRUniConformantArray):
    item = DWORD

class PDWORD_ARRAY(NDRPOINTER):
    referent = (
         ('Data', DWORD_ARRAY),
    )

class NspiQueryRows(NDRCALL):
    opnum = 3
    structure = (
        ('hRpc', handle_t),
        ('dwFlags', DWORD),
        ('pStat', STAT),
        ('dwETableCount', DWORD),
        ('lpETable', PDWORD_ARRAY),
        ('Count', DWORD),
        ('pPropTags', PPropertyTagArray_r),
    )

class NspiQueryRowsResponse(NDRCALL):
    structure = (
        ('pStat', STAT),
        ('ppRows', PPropertyRowSet_r),
        ('ErrorCode', ULONG),
    )

  
class NspiSeekEntries(NDRCALL):
    opnum = 4
    structure = (
        ('hRpc', handle_t),
        ('Reserved', DWORD),   
        ('pStat', STAT),
        ('pTarget', PropertyValue_r),
        ('lpETable', PropertyTagArray_r),
        ('pPropTags', PropertyTagArray_r),
    )

class NspiSeekEntriesResponse(NDRCALL):
    structure = (
        ('pStat', STAT),
        ('ppRows', PPropertyRowSet_r),
        ('ErrorCode', ULONG),
    )

  
  
  
  
  
  
  
  
  
  
  
  
  
  

  
  
  
  
  
  
  

  
  
  
  
  
  
  
  
  
  

  
  
  
  
  
  

  
class NspiDNToMId(NDRCALL):
    opnum = 7
    structure = (
        ('hRpc', handle_t),
        ('Reserved', DWORD),   
        ('pNames', StringsArray_r),
    )

class NspiDNToMIdResponse(NDRCALL):
    structure = (
        ('ppOutMIds', PPropertyTagArray_r),
        ('ErrorCode', ULONG),
    )

  
class NspiGetPropList(NDRCALL):
    opnum = 8
    structure = (
        ('hRpc', handle_t),
        ('dwFlags', DWORD),
        ('dwMId', DWORD),
        ('CodePage', DWORD),
    )

class NspiGetPropListResponse(NDRCALL):
    structure = (
        ('ppOutMIds', PPropertyTagArray_r),
        ('ErrorCode', ULONG),
    )

  
class NspiGetProps(NDRCALL):
    opnum = 9
    structure = (
        ('hRpc', handle_t),
        ('dwFlags', DWORD),
        ('pStat', PSTAT),
        ('pPropTags', PPropertyTagArray_r),
    )

class NspiGetPropsResponse(NDRCALL):
    structure = (
        ('ppRows', PPropertyRow_r),
        ('ErrorCode', ULONG),
    )

  
class NspiCompareMIds(NDRCALL):
    opnum = 10
    structure = (
        ('hRpc', handle_t),
        ('Reserved', DWORD),   
        ('pStat', STAT),
        ('MId1', DWORD),
        ('MId2', DWORD),
    )

class NspiCompareMIdsResponse(NDRCALL):
    structure = (
        ('plResult', LONG),
        ('ErrorCode', ULONG),
    )

  
  
  
  
  
  
  
  
  
  

  
  
  
  
  

  
class NspiGetSpecialTable(NDRCALL):
    opnum = 12
    structure = (
        ('hRpc', handle_t),
        ('dwFlags', DWORD),
        ('pStat', PSTAT),
        ('lpVersion', LPDWORD),
    )

class NspiGetSpecialTableResponse(NDRCALL):
    structure = (
          
          
          
        ('lpVersion', DWORD), 
        ('ppRows', PPropertyRowSet_r),
        ('ErrorCode', DWORD),
    )

  
class NspiGetTemplateInfo(NDRCALL):
    opnum = 13
    structure = (
        ('hRpc', handle_t),
        ('dwFlags', DWORD),
        ('ulType', DWORD),
        ('pDN', LPSTR),
        ('dwCodePage', DWORD),
        ('dwLocaleID', DWORD),
    )

class NspiGetTemplateInfoResponse(NDRCALL):
    structure = (
        ('ppData', PPropertyRow_r),
        ('ErrorCode', ULONG),
    )

  
class NspiModLinkAtt(NDRCALL):
    opnum = 14
    structure = (
        ('hRpc', handle_t),
        ('dwFlags', DWORD),
        ('ulPropTag', DWORD),
        ('dwMId', DWORD),
        ('lpEntryIds', BinaryArray_r),
    )

class NspiModLinkAttResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

  
  
  
  
  
  
  
  
  

  
  
  
  

  
class NspiQueryColumns(NDRCALL):
    opnum = 16
    structure = (
        ('hRpc', handle_t),
        ('Reserved', DWORD),   
        ('dwFlags', DWORD),    
    )

class NspiQueryColumnsResponse(NDRCALL):
    structure = (
        ('ppColumns', PPropertyTagArray_r),
        ('ErrorCode', ULONG),
    )

  
class NspiGetNamesFromIDs(NDRCALL):
    opnum = 17
    structure = (
        ('hRpc', handle_t),
        ('Reserved', DWORD),   
        ('lpguid', PFlatUID_r),
        ('pPropTags', PPropertyTagArray_r),
    )

class NspiGetNamesFromIDsResponse(NDRCALL):
    structure = (
        ('ppReturnedPropTags', PPropertyTagArray_r),
        ('ppNames', PPropertyNameSet_r),
        ('ErrorCode', ULONG),
    )

  
class PropertyName_r_ARRAY(NDRUniConformantVaryingArray):
    item = PropertyName_r

class NspiGetIDsFromNames(NDRCALL):
    opnum = 18
    structure = (
        ('hRpc', handle_t),
        ('Reserved', DWORD),   
        ('dwFlags', DWORD),    
        ('cPropNames', DWORD),
        ('pNames', PropertyName_r_ARRAY),
    )

class NspiGetIDsFromNamesResponse(NDRCALL):
    structure = (
        ('ppPropTags', PPropertyTagArray_r),
        ('ErrorCode', ULONG),
    )

  
class NspiResolveNames(NDRCALL):
    opnum = 19
    structure = (
        ('hRpc', handle_t),
        ('Reserved', DWORD),   
        ('pStat', STAT),
        ('pPropTags', PPropertyTagArray_r),
        ('paStr', StringsArray_r),
    )

class NspiResolveNamesResponse(NDRCALL):
    structure = (
        ('ppMIds', PPropertyTagArray_r),
        ('ppRows', PPropertyRowSet_r),
        ('ErrorCode', ULONG),
    )

  
class NspiResolveNamesW(NDRCALL):
    opnum = 20
    structure = (
        ('hRpc', handle_t),
        ('Reserved', DWORD),   
        ('pStat', STAT),
        ('pPropTags', PPropertyTagArray_r),
        ('paStr', WStringsArray_r),
    )

class NspiResolveNamesWResponse(NDRCALL):
    structure = (
        ('ppMIds', PPropertyTagArray_r),
        ('ppRows', PPropertyRowSet_r),
        ('ErrorCode', ULONG),
    )

  
  
  
OPNUMS = {
    0  : (NspiBind, NspiBindResponse),
    1  : (NspiUnbind, NspiUnbindResponse),
    2  : (NspiUpdateStat, NspiUpdateStatResponse),
    3  : (NspiQueryRows, NspiQueryRowsResponse),
    4  : (NspiSeekEntries, NspiSeekEntriesResponse),
  
  
    7  : (NspiDNToMId, NspiDNToMIdResponse),
    8  : (NspiGetPropList, NspiGetPropListResponse),
    9  : (NspiGetProps, NspiGetPropsResponse),
    10 : (NspiCompareMIds, NspiCompareMIdsResponse),
  
    12 : (NspiGetSpecialTable, NspiGetSpecialTableResponse),
    13 : (NspiGetTemplateInfo, NspiGetTemplateInfoResponse),
    14 : (NspiModLinkAtt, NspiModLinkAttResponse),
  
    16 : (NspiQueryColumns, NspiQueryColumnsResponse),
    17 : (NspiGetNamesFromIDs, NspiGetNamesFromIDsResponse),
    18 : (NspiGetIDsFromNames, NspiGetIDsFromNamesResponse),
    19 : (NspiResolveNames, NspiResolveNamesResponse),
    20 : (NspiResolveNamesW, NspiResolveNamesWResponse),
}

  
  
  
def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

def get_guid_from_dn(legacyDN):
    legacyDN = str(legacyDN)
    guid = legacyDN[legacyDN.rfind("=")+1:]

    return uuid.string_to_bin(guid)

def get_dn_from_guid(guid, minimize=False):
    if minimize:
          
        dn_template = "/guid="
    else:
          
        dn_template = "/o=NT5/ou=00000000000000000000000000000000/cn="

    guid_bin = string_to_bin(guid)

    if PY2:
        return "%s%s" % (dn_template, binascii.hexlify(guid_bin))
    else:
        return "%s%s" % (dn_template, str(binascii.hexlify(guid_bin), 'ascii'))

class EXCH_SID(LDAP_SID):
    def __str__(self):
        return self.formatCanonical()

class ExchBinaryObject(bytes):
    pass

def getUnixTime(t):
    t -= 116444736000000000
    t //= 10000000
    return t

def simplifyPropertyRow(rowSetElem):
    row = {}

    for prop in rowSetElem['lpProps']:
        prop_name_in_union = prop['Value'].structure[0][0]
        prop_value = prop['Value'].fields[prop_name_in_union]

        PropTag = prop['ulPropTag']

        if isinstance(prop_value, SHORT) or \
           isinstance(prop_value, USHORT) or \
           isinstance(prop_value, LONG) or \
           isinstance(prop_value, ULONG):
            row[PropTag] = int(prop_value['Data'])
        elif isinstance(prop_value, LPWSTR):
            if PropTag in [0x8c38001f]:
                  
                row[PropTag] = ExchBinaryObject(prop_value['Data'].encode("utf-16le")[:-2])
            else:
                row[PropTag] = prop_value['Data'][:-1]
        elif isinstance(prop_value, LPSTR):
            row[PropTag] = prop_value['Data'][:-1]
        elif isinstance(prop_value, Binary_r):
            value = b''.join(prop_value['lpb'])

            if PropTag in [0x80270102, 0x8c750102]:
                value = EXCH_SID(value)
            elif PropTag == 0x300b0102:
                value = value[:-1].decode("utf-8")
            elif value[4:20] == GUID_NSPI and value[20:24] == b'\x01\x00\x00\x00' and value[:4] == b'\x00\x00\x00\x00':
                value = PermanentEntryID(value)
            elif value[:4] == b'\x87\x00\x00\x00' and value[20:24] == b'\x01\x00\x00\x00' and len(value) == 32:
                value = EphemeralEntryID(value)
            elif PropTag in [0x8c6d0102, 0x68c40102, 0x8c730102, 0x0ff80102]:
                value = uuid.bin_to_string(value).lower()
            elif PropTag == 0x0ff60102:
                value = unpack('<l', value)[0]
            else:
                value = ExchBinaryObject(value)

            row[PropTag] = value
        elif isinstance(prop_value, BinaryArray_r):
            array = []
            for value in prop_value['lpbin']:
                array.append(b''.join(value['lpb']))
            row[PropTag] = array
        elif isinstance(prop_value, StringArray_r):
            array = []
            for value in prop_value['lppszA']:
                array.append(value['Data'][:-1])
            row[PropTag] = array
        elif isinstance(prop_value, WStringArray_r):
            array = []
            for value in prop_value['lppszW']:
                array.append(value['Data'][:-1])
            row[PropTag] = array
        elif isinstance(prop_value, FILETIME):
            row[PropTag] = datetime.fromtimestamp( \
                getUnixTime(unpack('<Q', prop_value.getData())[0]))
        else:
            row[PropTag] = prop_value

    return row

def simplifyPropertyRowSet(propertyRowSet):
    ret = []

    for rowSet in propertyRowSet['aRow']:
        ret.append(simplifyPropertyRow(rowSet))

    return ret

def hNspiBind(dce, pStat=None):
    request = NspiBind()

    if pStat == None:
        request['pStat']['CodePage'] = CP_TELETEX
    else:
        request['pStat'] = pStat

    resp = dce.request(request)
    return resp

def hNspiUnbind(dce, handler):
    request = NspiUnbind()
    request['contextHandle'] = handler

    resp = dce.request(request, checkError=False)
    return resp

def hNspiUpdateStat(dce, handler, pStat, plDelta=NULL):
    request = NspiUpdateStat()
    request['hRpc'] = handler
    request['pStat'] = pStat
    request['plDelta'] = plDelta

    resp = dce.request(request, checkError=False)
    return resp

def hNspiQueryRows(dce, handler, dwFlags=fSkipObjects, pStat=None, ContainerID=0,
        Count=50, pPropTags=[], pPropTagsRaw=NULL, lpETable=[]):
    request = NspiQueryRows()
    request['hRpc'] = handler
    request['dwFlags'] = dwFlags
    request['Count'] = Count

    if pStat == None:
        request['pStat']['ContainerID'] = ContainerID
    else:
        request['pStat'] = pStat

    if len(pPropTags) > 0:
        for aulPropTag in pPropTags:
            prop = DWORD()
            prop['Data'] = aulPropTag
            request['pPropTags']['aulPropTag'].append(prop)
        request['pPropTags']['cValues'] = len(pPropTags)
        request.fields['pPropTags'].fields['Data'].fields['aulPropTag'].fields['MaximumCount'] = len(pPropTags) + 1
    else:
        request['pPropTags'] = pPropTagsRaw

    if len(lpETable) > 0:
        for mID in lpETable:
            elem = DWORD()
            elem['Data'] = mID
            request['lpETable'].append(elem)
        request['dwETableCount'] = len(lpETable)
    else:
        request['lpETable'] = NULL
        request['dwETableCount'] = 0

    resp = dce.request(request)
    return resp

def hNspiSeekEntries(dce, handler, displayName, ContainerID=0, SortType=0, \
        lpETable=[], lpETableRaw=NULL, pPropTags=[], pPropTagsRaw=NULL):
    request = NspiSeekEntries()
    request['hRpc'] = handler
    request['pStat']['ContainerID'] = ContainerID

      
      
      
    request['pStat']['SortType'] = SortTypeDisplayName

      
      
      
      
      
    request['pTarget']['ulPropTag'] = 0x3001001F
    request['pTarget']['Value']['tag'] = 0x0000001F
    request['pTarget']['Value']['lpszW'] = checkNullString(displayName)

    if len(lpETable) > 0:
        for mID in lpETable:
            elem = DWORD()
            elem['Data'] = mID
            request['lpETable'].append(elem)
    else:
        request['lpETable'] = lpETableRaw

    if len(pPropTags) > 0:
        for aulPropTag in pPropTags:
            prop = DWORD()
            prop['Data'] = aulPropTag
            request['pPropTags']['aulPropTag'].append(prop)
        request.fields['pPropTags'].fields['aulPropTag'].fields['MaximumCount'] = len(pPropTags) + 1
    else:
        request['pPropTags'] = pPropTagsRaw

    resp = dce.request(request)
    return resp

def hNspiDNToMId(dce, handler, pNames=[]):
    request = NspiDNToMId()
    request['hRpc'] = handler
    request['pNames']['Count'] = len(pNames)

    for name in pNames:
        lpstr = LPSTR()
        lpstr['Data'] = checkNullString(name)
        request['pNames']['Strings'].append(lpstr)

    resp = dce.request(request)
    return resp

def hNspiGetPropList(dce, handler, dwMId=0, dwFlags=fSkipObjects, CodePage=CP_TELETEX):
    request = NspiGetPropList()
    request['hRpc'] = handler
    request['dwMId'] = dwMId
    request['dwFlags'] = dwFlags
    request['CodePage'] = CodePage
    resp = dce.request(request)

    return resp

def hNspiGetProps(dce, handler, ContainerID=0, CurrentRec=0, dwFlags=fSkipObjects, CodePage=CP_TELETEX, pPropTags=[]):
    request = NspiGetProps()
    request['hRpc'] = handler
    request['dwFlags'] = dwFlags

    request['pStat']['CurrentRec'] = CurrentRec
    request['pStat']['ContainerID'] = ContainerID
    request['pStat']['CodePage'] = CodePage

    for aulPropTag in pPropTags:
        prop = DWORD()
        prop['Data'] = aulPropTag
        request['pPropTags']['aulPropTag'].append(prop)
    request['pPropTags']['cValues'] = len(pPropTags) + 1
    request.fields['pPropTags'].fields['Data'].fields['aulPropTag'].fields['MaximumCount'] = len(pPropTags) + 1

    resp = dce.request(request)
    return resp

def hNspiGetSpecialTable(dce, handler, dwFlags=NspiUnicodeStrings, pStat=STAT(), lpVersion=NULL):
    request = NspiGetSpecialTable()
    request['hRpc'] = handler
    request['dwFlags'] = dwFlags
    request['pStat'] = pStat
    request['lpVersion'] = lpVersion

    resp = dce.request(request)
    return resp

  
def hNspiGetTemplateInfo(dce, handler, pDN=NULL, dwLocaleID=0, ulType=0, dwCodePage=0, dwFlags=0xFFFFFFFF):
    request = NspiGetTemplateInfo()
    request['hRpc'] = handler
    request['dwFlags'] = dwFlags
    request['ulType'] = ulType
    request['pDN'] = checkNullString(pDN)
    request['dwCodePage'] = dwCodePage
    request['dwLocaleID'] = dwLocaleID

    resp = dce.request(request)
    return resp

def hNspiModLinkAtt(dce, handler, dwFlags, ulPropTag, dwMId, lpEntryIds):
    request = NspiModLinkAtt()
    request['hRpc'] = handler
    request['dwFlags'] = dwFlags
    request['ulPropTag'] = ulPropTag
    request['dwMId'] = dwMId

    for lpEntryId in lpEntryIds:
        prop = Binary_r()
        prop['lpb'] = lpEntryId.getData()
        prop['cValues'] = len(prop['lpb'])
        request['lpEntryIds']['lpbin'].append(prop)
    request['lpEntryIds']['cValues'] = len(lpEntryIds)

    resp = dce.request(request)
    return resp

def hNspiQueryColumns(dce, handler, dwFlags=NspiUnicodeProptypes):
    request = NspiQueryColumns()
    request['hRpc'] = handler
    request['dwFlags'] = dwFlags

    resp = dce.request(request)
    return resp

def hNspiGetNamesFromIDs(dce, handler, lpguid=EMPTY_UUID, pPropTags=[], pPropTagsRaw=NULL):
    request = NspiGetNamesFromIDs()
    request['hRpc'] = handler
    request['lpguid'] = lpguid

    if len(pPropTags) > 0:
        for aulPropTag in pPropTags:
            prop = DWORD()
            prop['Data'] = aulPropTag
            request['pPropTags']['aulPropTag'].append(prop)
        request['pPropTags']['cValues'] = len(pPropTags)
        request.fields['pPropTags'].fields['Data'].fields['aulPropTag'].fields['MaximumCount'] = len(pPropTags) + 1
    elif pPropTagsRaw == NULL:
        request.fields['pPropTags'] = NULL
    else:
        request['pPropTags'] = pPropTagsRaw

    resp = dce.request(request)
    return resp

def hNspiResolveNames(dce, handler, ContainerID=0, pPropTags=[], pPropTagsRaw=NULL, paStr=[]):
    request = NspiResolveNames()
    request['hRpc'] = handler
    request['pStat']['ContainerID'] = ContainerID

    if len(pPropTags) > 0:
        for aulPropTag in pPropTags:
            prop = DWORD()
            prop['Data'] = aulPropTag
            request['pPropTags']['aulPropTag'].append(prop)
        request['pPropTags']['cValues'] = len(pPropTags)
        request.fields['pPropTags'].fields['Data'].fields['aulPropTag'].fields['MaximumCount'] = len(pPropTags) + 1
    elif pPropTagsRaw == NULL:
        request.fields['pPropTags'] = NULL
    else:
        request['pPropTags'] = pPropTagsRaw

    if len(paStr) > 0:
        for paStrElem in paStr:
            value = LPSTR()
            value['Data'] = checkNullString(paStrElem)
            request['paStr']['Strings'].append(value)
        request['paStr']['Count'] = len(paStr)

    resp = dce.request(request)
    return resp

def hNspiResolveNamesW(dce, handler, ContainerID=0, pPropTags=[], pPropTagsRaw=NULL, paStr=[]):
    request = NspiResolveNamesW()
    request['hRpc'] = handler
    request['pStat']['ContainerID'] = ContainerID

    if len(pPropTags) > 0:
        for aulPropTag in pPropTags:
            prop = DWORD()
            prop['Data'] = aulPropTag
            request['pPropTags']['aulPropTag'].append(prop)
        request['pPropTags']['cValues'] = len(pPropTags)
        request.fields['pPropTags'].fields['Data'].fields['aulPropTag'].fields['MaximumCount'] = len(pPropTags) + 1
    elif pPropTagsRaw == NULL:
        request.fields['pPropTags'] = NULL
    else:
        request['pPropTags'] = pPropTagsRaw

    if len(paStr) > 0:
        for paStrElem in paStr:
            value = LPWSTR()
            value['Data'] = checkNullString(paStrElem)
            request['paStr']['Strings'].append(value)
        request['paStr']['Count'] = len(paStr)

    resp = dce.request(request)
    return resp
