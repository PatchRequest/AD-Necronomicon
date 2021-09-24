from __future__ import division
from __future__ import print_function
from struct import pack
from six import binary_type

from libs.dcerpc.v5.ndr import NDRULONG, NDRUHYPER, NDRSHORT, NDRLONG, NDRPOINTER, NDRUniConformantArray, \
    NDRUniFixedArray, NDR, NDRHYPER, NDRSMALL, NDRPOINTERNULL, NDRSTRUCT, \
    NDRUSMALL, NDRBOOLEAN, NDRUSHORT, NDRFLOAT, NDRDOUBLEFLOAT, NULL

DWORD = NDRULONG
BOOL = NDRULONG
UCHAR = NDRUSMALL
SHORT = NDRSHORT
NULL = NULL

class LPDWORD(NDRPOINTER):
    referent = (
        ('Data', DWORD),
    )

class PSHORT(NDRPOINTER):
    referent = (
        ('Data', SHORT),
    )

class PBOOL(NDRPOINTER):
    referent = (
        ('Data', BOOL),
    )

class LPBYTE(NDRPOINTER):
    referent = (
        ('Data', NDRUniConformantArray),
    )
PBYTE = LPBYTE

  
BOOLEAN = NDRBOOLEAN

  
BYTE = NDRUSMALL

  
CHAR = NDRSMALL
class PCHAR(NDRPOINTER):
    referent = (
        ('Data', CHAR),
    )

class WIDESTR(NDRUniFixedArray):
    def getDataLen(self, data, offset=0):
        return data.find(b'\x00\x00\x00', offset)+3-offset

    def __setitem__(self, key, value):
        if key == 'Data':
            try:
                self.fields[key] = value.encode('utf-16le')
            except UnicodeDecodeError:
                import sys
                self.fields[key] = value.decode(sys.getfilesystemencoding()).encode('utf-16le')

            self.data = None          
        else:
            return NDR.__setitem__(self, key, value)

    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le')
        else:
            return NDR.__getitem__(self,key)

class STR(NDRSTRUCT):
    commonHdr = (
        ('MaximumCount', '<L=len(Data)'),
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)'),
    )
    commonHdr64 = (
        ('MaximumCount', '<Q=len(Data)'),
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)'),
    )
    structure = (
        ('Data',':'),
    )

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print("%s" % msg, end=' ')
          
        print(" %r" % (self['Data']), end=' ')

    def __setitem__(self, key, value):
        if key == 'Data':
            try:
                if not isinstance(value, binary_type):
                    self.fields[key] = value.encode('utf-8')
                else:
                      
                    self.fields[key] = value
            except UnicodeDecodeError:
                import sys
                self.fields[key] = value.decode(sys.getfilesystemencoding()).encode('utf-8')
            self.fields['MaximumCount'] = None
            self.fields['ActualCount'] = None
            self.data = None          
        else:
            return NDR.__setitem__(self, key, value)

    def __getitem__(self, key):
        if key == 'Data':
            try:
                return self.fields[key].decode('utf-8')
            except UnicodeDecodeError:
                  
                return self.fields[key]
        else:
            return NDR.__getitem__(self,key)

    def getDataLen(self, data, offset=0):
        return self["ActualCount"]

class LPSTR(NDRPOINTER):
    referent = (
        ('Data', STR),
    )

class WSTR(NDRSTRUCT):
    commonHdr = (
        ('MaximumCount', '<L=len(Data)//2'),
        ('Offset','<L=0'),
        ('ActualCount','<L=len(Data)//2'),
    )
    commonHdr64 = (
        ('MaximumCount', '<Q=len(Data)//2'),
        ('Offset','<Q=0'),
        ('ActualCount','<Q=len(Data)//2'),
    )
    structure = (
        ('Data',':'),
    )

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print("%s" % msg, end=' ')
          
        print(" %r" % (self['Data']), end=' ')

    def getDataLen(self, data, offset=0):
        return self["ActualCount"]*2 

    def __setitem__(self, key, value):
        if key == 'Data':
            try:
                self.fields[key] = value.encode('utf-16le')
            except UnicodeDecodeError:
                import sys
                self.fields[key] = value.decode(sys.getfilesystemencoding()).encode('utf-16le')
            self.fields['MaximumCount'] = None
            self.fields['ActualCount'] = None
            self.data = None          
        else:
            return NDR.__setitem__(self, key, value)

    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le')
        else:
            return NDR.__getitem__(self,key)

class LPWSTR(NDRPOINTER):
    referent = (
        ('Data', WSTR),
    )

  
BSTR = LPWSTR

  
DOUBLE = NDRDOUBLEFLOAT
class PDOUBLE(NDRPOINTER):
    referent = (
        ('Data', DOUBLE),
    )

  
FLOAT = NDRFLOAT
class PFLOAT(NDRPOINTER):
    referent = (
        ('Data', FLOAT),
    )

  
HRESULT = NDRLONG
class PHRESULT(NDRPOINTER):
    referent = (
        ('Data', HRESULT),
    )

  
INT = NDRLONG
class PINT(NDRPOINTER):
    referent = (
        ('Data', INT),
    )

  
LMSTR = LPWSTR

  
LONG = NDRLONG
class LPLONG(NDRPOINTER):
    referent = (
        ('Data', LONG),
    )

PLONG = LPLONG

  
LONGLONG = NDRHYPER

class PLONGLONG(NDRPOINTER):
    referent = (
        ('Data', LONGLONG),
    )

  
LONG64 = NDRUHYPER
class PLONG64(NDRPOINTER):
    referent = (
        ('Data', LONG64),
    )

  
LPCSTR = LPSTR

  
NET_API_STATUS = DWORD

  
ULONG_PTR = NDRULONG
  
DWORD_PTR = ULONG_PTR

  
class GUID(NDRSTRUCT):
    structure = (
        ('Data','16s=b""'),
    )

    def getAlignment(self):
        return 4

class PGUID(NDRPOINTER):
    referent = (
        ('Data', GUID),
    )

UUID = GUID
PUUID = PGUID

  
NTSTATUS = DWORD

  
UINT = NDRULONG
class PUINT(NDRPOINTER):
    referent = (
        ('Data', UINT),
    )

  
ULONG = NDRULONG
class PULONG(NDRPOINTER):
    referent = (
        ('Data', ULONG),
    )

LPULONG = PULONG

  
ULONGLONG = NDRUHYPER
class PULONGLONG(NDRPOINTER):
    referent = (
        ('Data', ULONGLONG),
    )

  
USHORT = NDRUSHORT
class PUSHORT(NDRPOINTER):
    referent = (
        ('Data', USHORT),
    )

  
WCHAR = WSTR
PWCHAR = LPWSTR

  
WORD = NDRUSHORT
class PWORD(NDRPOINTER):
    referent = (
        ('Data', WORD),
    )
LPWORD = PWORD

  
class FILETIME(NDRSTRUCT):
    structure = (
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', LONG),
    )

class PFILETIME(NDRPOINTER):
    referent = (
        ('Data', FILETIME),
    )

  
LARGE_INTEGER = NDRHYPER
class PLARGE_INTEGER(NDRPOINTER):
    referent = (
        ('Data', LARGE_INTEGER),
    )

  
class LUID(NDRSTRUCT):
    structure = (
        ('LowPart', DWORD),
        ('HighPart', LONG),
    )

  
class RPC_UNICODE_STRING(NDRSTRUCT):
      
      
      
      
      
      
      
      
      
      
      
      
      
      
    structure = (
        ('Length','<H=0'),
        ('MaximumLength','<H=0'),
        ('Data',LPWSTR),
    )

    def __setitem__(self, key, value):
        if key == 'Data' and isinstance(value, NDR) is False:
            try:
                value.encode('utf-16le')
            except UnicodeDecodeError:
                import sys
                value = value.decode(sys.getfilesystemencoding())
            self['Length'] = len(value)*2
            self['MaximumLength'] = len(value)*2
        return NDRSTRUCT.__setitem__(self, key, value)

    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print("%s" % msg, end=' ')

        if isinstance(self.fields['Data'] , NDRPOINTERNULL):
            print(" NULL", end=' ')
        elif self.fields['Data']['ReferentID'] == 0:
            print(" NULL", end=' ')
        else:
            return self.fields['Data'].dump('',indent)

class PRPC_UNICODE_STRING(NDRPOINTER):
    referent = (
       ('Data', RPC_UNICODE_STRING ),
    )

  
ACCESS_MASK = DWORD
class OBJECT_TYPE_LIST(NDRSTRUCT):
    structure = (
        ('Level', WORD),
        ('Remaining',ACCESS_MASK),
        ('ObjectType',PGUID),
    )

class POBJECT_TYPE_LIST(NDRPOINTER):
    referent = (
       ('Data', OBJECT_TYPE_LIST ),
    )

  
class SYSTEMTIME(NDRSTRUCT):
    structure = (
        ('wYear', WORD),
        ('wMonth', WORD),
        ('wDayOfWeek', WORD),
        ('wDay', WORD),
        ('wHour', WORD),
        ('wMinute', WORD),
        ('wSecond', WORD),
        ('wMilliseconds', WORD),
    )

class PSYSTEMTIME(NDRPOINTER):
    referent = (
       ('Data', SYSTEMTIME ),
    )

  
class ULARGE_INTEGER(NDRSTRUCT):
    structure = (
        ('QuadPart', LONG64),
    )

class PULARGE_INTEGER(NDRPOINTER):
    referent = (
        ('Data', ULARGE_INTEGER),
    )

  
class DWORD_ARRAY(NDRUniConformantArray):
    item = '<L'

class RPC_SID_IDENTIFIER_AUTHORITY(NDRUniFixedArray):
    align = 1
    align64 = 1
    def getDataLen(self, data, offset=0):
        return 6

class RPC_SID(NDRSTRUCT):
    structure = (
        ('Revision',NDRSMALL),
        ('SubAuthorityCount',NDRSMALL),
        ('IdentifierAuthority',RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubAuthority',DWORD_ARRAY),
    )
    def getData(self, soFar = 0):
        self['SubAuthorityCount'] = len(self['SubAuthority'])
        return NDRSTRUCT.getData(self, soFar)

    def fromCanonical(self, canonical):
        items = canonical.split('-')
        self['Revision'] = int(items[1])
        self['IdentifierAuthority'] = b'\x00\x00\x00\x00\x00' + pack('B',int(items[2]))
        self['SubAuthorityCount'] = len(items) - 3
        for i in range(self['SubAuthorityCount']):
            self['SubAuthority'].append(int(items[i+3]))

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority'][5:6]))
        for i in range(self['SubAuthorityCount']):
            ans += '-%d' % self['SubAuthority'][i]
        return ans

class PRPC_SID(NDRPOINTER):
    referent = (
        ('Data', RPC_SID),
    )

PSID = PRPC_SID

  
GENERIC_READ            = 0x80000000
GENERIC_WRITE           = 0x40000000
GENERIC_EXECUTE         = 0x20000000
GENERIC_ALL             = 0x10000000
MAXIMUM_ALLOWED         = 0x02000000
ACCESS_SYSTEM_SECURITY  = 0x01000000
SYNCHRONIZE             = 0x00100000
WRITE_OWNER             = 0x00080000
WRITE_DACL              = 0x00040000
READ_CONTROL            = 0x00020000
DELETE                  = 0x00010000

  
class ACL(NDRSTRUCT):
    structure = (
        ('AclRevision',NDRSMALL),
        ('Sbz1',NDRSMALL),
        ('AclSize',NDRSHORT),
        ('AceCount',NDRSHORT),
        ('Sbz2',NDRSHORT),
    )

class PACL(NDRPOINTER):
    referent = (
        ('Data', ACL),
    )

  
class SECURITY_DESCRIPTOR(NDRSTRUCT):
    structure = (
        ('Revision',UCHAR),
        ('Sbz1',UCHAR),
        ('Control',USHORT),
        ('Owner',PSID),
        ('Group',PSID),
        ('Sacl',PACL),
        ('Dacl',PACL),
    )

  
OWNER_SECURITY_INFORMATION            = 0x00000001
GROUP_SECURITY_INFORMATION            = 0x00000002
DACL_SECURITY_INFORMATION             = 0x00000004
SACL_SECURITY_INFORMATION             = 0x00000008
LABEL_SECURITY_INFORMATION            = 0x00000010
UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
ATTRIBUTE_SECURITY_INFORMATION        = 0x00000020
SCOPE_SECURITY_INFORMATION            = 0x00000040
BACKUP_SECURITY_INFORMATION           = 0x00010000

SECURITY_INFORMATION = DWORD
class PSECURITY_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', SECURITY_INFORMATION),
    )
