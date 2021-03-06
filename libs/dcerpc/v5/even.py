from __future__ import division
from __future__ import print_function
from libs.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDR, NDRPOINTERNULL, NDRUniConformantArray
from libs.dcerpc.v5.dtypes import ULONG, LPWSTR, RPC_UNICODE_STRING, LPSTR, NTSTATUS, NULL, PRPC_UNICODE_STRING, PULONG, USHORT, PRPC_SID, LPBYTE
from libs.dcerpc.v5.lsad import PRPC_UNICODE_STRING_ARRAY
from libs.structure import Structure
from libs import nt_errors
from libs.uuid import uuidtup_to_bin
from libs.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_EVEN  = uuidtup_to_bin(('82273FDC-E32A-18C3-3F78-827929DC23EA','0.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in nt_errors.ERROR_MESSAGES:
            error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = nt_errors.ERROR_MESSAGES[key][1]
            return 'EVEN SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'EVEN SessionError: unknown error code: 0x%x' % self.error_code

  
  
  
  
EVENTLOG_SUCCESS           = 0x0000
EVENTLOG_ERROR_TYPE        = 0x0001
EVENTLOG_WARNING_TYPE      = 0x0002
EVENTLOG_INFORMATION_TYPE  = 0x0004
EVENTLOG_AUDIT_SUCCESS     = 0x0008
EVENTLOG_AUDIT_FAILURE     = 0x0010

  
  
EVENTLOG_HANDLE_W = LPWSTR

  
MAX_STRINGS      = 0x00000100
MAX_SINGLE_EVENT = 0x0003FFFF
MAX_BATCH_BUFF   = 0x0007FFFF

  
EVENTLOG_SEQUENTIAL_READ = 0x00000001
EVENTLOG_SEEK_READ       = 0x00000002

EVENTLOG_FORWARDS_READ   = 0x00000004
EVENTLOG_BACKWARDS_READ  = 0x00000008

  
  
  

class IELF_HANDLE(NDRSTRUCT):
    structure =  (
        ('Data','20s=""'),
    )
    def getAlignment(self):
        return 1

  
class EVENTLOGRECORD(Structure):
    structure = (
        ('Length','<L=0'),
        ('Reserved','<L=0'),
        ('RecordNumber','<L=0'),
        ('TimeGenerated','<L=0'),
        ('TimeWritten','<L=0'),
        ('EventID','<L=0'),
        ('EventType','<H=0'),
        ('NumStrings','<H=0'),
        ('EventCategory','<H=0'),
        ('ReservedFlags','<H=0'),
        ('ClosingRecordNumber','<L=0'),
        ('StringOffset','<L=0'),
        ('UserSidLength','<L=0'),
        ('UserSidOffset','<L=0'),
        ('DataLength','<L=0'),
        ('DataOffset','<L=0'),
        ('SourceName','z'),
        ('Computername','z'),
        ('UserSidPadding',':'),
        ('_UserSid','_-UserSid', 'self["UserSidLength"]'),
        ('UserSid',':'),
        ('Strings',':'),
        ('_Data','_-Data', 'self["DataLength"]'),
        ('Data',':'),
        ('Padding',':'),
        ('Length2','<L=0'),
    )

  
class EVENTLOG_FULL_INFORMATION(NDRSTRUCT):
    structure = (
        ('dwFull', ULONG),
    )

  
class RPC_CLIENT_ID(NDRSTRUCT):
    structure = (
        ('UniqueProcess', ULONG),
        ('UniqueThread', ULONG),
    )

  
class RPC_STRING(NDRSTRUCT):
    structure = (
        ('Length','<H=0'),
        ('MaximumLength','<H=0'),
        ('Data',LPSTR),
    )

    def __setitem__(self, key, value):
        if key == 'Data' and isinstance(value, NDR) is False:
            self['Length'] = len(value)
            self['MaximumLength'] = len(value)
        return NDRSTRUCT.__setitem__(self, key, value)

    def dump(self, msg = None, indent = 0):
        if msg is None: msg = self.__class__.__name__
        if msg != '':
            print("%s" % msg, end=' ')

        if isinstance(self.fields['Data'] , NDRPOINTERNULL):
            print(" NULL", end=' ')
        elif self.fields['Data']['ReferentID'] == 0:
            print(" NULL", end=' ')
        else:
            return self.fields['Data'].dump('',indent)

  
  
  
  
class ElfrClearELFW(NDRCALL):
    opnum = 0
    structure = (
       ('LogHandle', IELF_HANDLE),
       ('BackupFileName', PRPC_UNICODE_STRING),
    )

class ElfrClearELFWResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

  
class ElfrBackupELFW(NDRCALL):
    opnum = 1
    structure = (
       ('LogHandle', IELF_HANDLE),
       ('BackupFileName', RPC_UNICODE_STRING),
    )

class ElfrBackupELFWResponse(NDRCALL):
    structure = (
       ('ErrorCode', NTSTATUS),
    )

  
class ElfrCloseEL(NDRCALL):
    opnum = 2
    structure = (
        ('LogHandle', IELF_HANDLE),
    )

class ElfrCloseELResponse(NDRCALL):
    structure = (
        ('LogHandle', IELF_HANDLE),
        ('ErrorCode', NTSTATUS),
    )

  
class ElfrNumberOfRecords(NDRCALL):
    opnum = 4
    structure = (
        ('LogHandle', IELF_HANDLE),
    )

class ElfrNumberOfRecordsResponse(NDRCALL):
    structure = (
        ('NumberOfRecords', ULONG),
        ('ErrorCode', NTSTATUS),
    )

  
class ElfrOldestRecord(NDRCALL):
    opnum = 5
    structure = (
        ('LogHandle', IELF_HANDLE),
    )

class ElfrOldestRecordResponse(NDRCALL):
    structure = (
        ('OldestRecordNumber', ULONG),
        ('ErrorCode', NTSTATUS),
    )

  
class ElfrOpenELW(NDRCALL):
    opnum = 7
    structure = (
       ('UNCServerName', EVENTLOG_HANDLE_W),
       ('ModuleName', RPC_UNICODE_STRING),
       ('RegModuleName', RPC_UNICODE_STRING),
       ('MajorVersion', ULONG),
       ('MinorVersion', ULONG),
    )

class ElfrOpenELWResponse(NDRCALL):
    structure = (
       ('LogHandle', IELF_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

  
class ElfrRegisterEventSourceW(NDRCALL):
    opnum = 8
    structure = (
       ('UNCServerName', EVENTLOG_HANDLE_W),
       ('ModuleName', RPC_UNICODE_STRING),
       ('RegModuleName', RPC_UNICODE_STRING),
       ('MajorVersion', ULONG),
       ('MinorVersion', ULONG),
    )

class ElfrRegisterEventSourceWResponse(NDRCALL):
    structure = (
       ('LogHandle', IELF_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

  
class ElfrOpenBELW(NDRCALL):
    opnum = 9
    structure = (
       ('UNCServerName', EVENTLOG_HANDLE_W),
       ('BackupFileName', RPC_UNICODE_STRING),
       ('MajorVersion', ULONG),
       ('MinorVersion', ULONG),
    )

class ElfrOpenBELWResponse(NDRCALL):
    structure = (
       ('LogHandle', IELF_HANDLE),
       ('ErrorCode', NTSTATUS),
    )

  
class ElfrReadELW(NDRCALL):
    opnum = 10
    structure = (
       ('LogHandle', IELF_HANDLE),
       ('ReadFlags', ULONG),
       ('RecordOffset', ULONG),
       ('NumberOfBytesToRead', ULONG),
    )

class ElfrReadELWResponse(NDRCALL):
    structure = (
       ('Buffer', NDRUniConformantArray),
       ('NumberOfBytesRead', ULONG),
       ('MinNumberOfBytesNeeded', ULONG),
       ('ErrorCode', NTSTATUS),
    )

  
class ElfrReportEventW(NDRCALL):
    opnum = 11
    structure = (
       ('LogHandle', IELF_HANDLE),
       ('Time', ULONG),
       ('EventType', USHORT),
       ('EventCategory', USHORT),
       ('EventID', ULONG),
       ('NumStrings', USHORT),
       ('DataSize', ULONG),
       ('ComputerName', RPC_UNICODE_STRING),
       ('UserSID', PRPC_SID),
       ('Strings', PRPC_UNICODE_STRING_ARRAY),
       ('Data', LPBYTE),
       ('Flags', USHORT),
       ('RecordNumber', PULONG),
       ('TimeWritten', PULONG),
    )

class ElfrReportEventWResponse(NDRCALL):
    structure = (
       ('RecordNumber', PULONG),
       ('TimeWritten', PULONG),
       ('ErrorCode', NTSTATUS),
    )

  
  
  
OPNUMS = {
    0   : (ElfrClearELFW, ElfrClearELFWResponse),
    1   : (ElfrBackupELFW, ElfrBackupELFWResponse),
    2   : (ElfrCloseEL, ElfrCloseELResponse),
    4   : (ElfrNumberOfRecords, ElfrNumberOfRecordsResponse),
    5   : (ElfrOldestRecord, ElfrOldestRecordResponse),
    7   : (ElfrOpenELW, ElfrOpenELWResponse),
    8   : (ElfrRegisterEventSourceW, ElfrRegisterEventSourceWResponse),
    9   : (ElfrOpenBELW, ElfrOpenBELWResponse),
    10  : (ElfrReadELW, ElfrReadELWResponse),
    11  : (ElfrReportEventW, ElfrReportEventWResponse),
}

  
  
  
def hElfrOpenBELW(dce, backupFileName = NULL):
    request = ElfrOpenBELW()
    request['UNCServerName'] = NULL
    request['BackupFileName'] = backupFileName
    request['MajorVersion'] = 1
    request['MinorVersion'] = 1
    return dce.request(request)

def hElfrOpenELW(dce, moduleName = NULL, regModuleName = NULL):
    request = ElfrOpenELW()
    request['UNCServerName'] = NULL
    request['ModuleName'] = moduleName
    request['RegModuleName'] = regModuleName
    request['MajorVersion'] = 1
    request['MinorVersion'] = 1
    return dce.request(request)

def hElfrCloseEL(dce, logHandle):
    request = ElfrCloseEL()
    request['LogHandle'] = logHandle
    resp = dce.request(request)
    return resp

def hElfrRegisterEventSourceW(dce, moduleName = NULL, regModuleName = NULL):
    request = ElfrRegisterEventSourceW()
    request['UNCServerName'] = NULL
    request['ModuleName'] = moduleName
    request['RegModuleName'] = regModuleName
    request['MajorVersion'] = 1
    request['MinorVersion'] = 1
    return dce.request(request)

def hElfrReadELW(dce, logHandle = '', readFlags = EVENTLOG_SEEK_READ|EVENTLOG_FORWARDS_READ,
                 recordOffset = 0, numberOfBytesToRead = MAX_BATCH_BUFF):
    request = ElfrReadELW()
    request['LogHandle'] = logHandle
    request['ReadFlags'] = readFlags
    request['RecordOffset'] = recordOffset
    request['NumberOfBytesToRead'] = numberOfBytesToRead
    return dce.request(request)

def hElfrClearELFW(dce, logHandle = '', backupFileName = NULL):
    request = ElfrClearELFW()
    request['LogHandle'] = logHandle
    request['BackupFileName'] = backupFileName
    return dce.request(request)

def hElfrBackupELFW(dce, logHandle = '', backupFileName = NULL):
    request = ElfrBackupELFW()
    request['LogHandle'] = logHandle
    request['BackupFileName'] = backupFileName
    return dce.request(request)

def hElfrNumberOfRecords(dce, logHandle):
    request = ElfrNumberOfRecords()
    request['LogHandle'] = logHandle
    resp = dce.request(request)
    return resp

def hElfrOldestRecordNumber(dce, logHandle):
    request = ElfrOldestRecord()
    request['LogHandle'] = logHandle
    resp = dce.request(request)
    return resp
