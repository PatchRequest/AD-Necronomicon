from libs.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantArray
from libs.dcerpc.v5.dtypes import DWORD, LPWSTR, UCHAR, ULONG, LPDWORD, NULL
from libs import hresult_errors
from libs.uuid import uuidtup_to_bin
from libs.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_ATSVC  = uuidtup_to_bin(('1FF70682-0A51-30E8-076D-740BE8CEE98B','1.0'))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        key = self.error_code
        if key in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'TSCH SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'TSCH SessionError: unknown error code: 0x%x' % self.error_code

  
  
  
ATSVC_HANDLE = LPWSTR
  
CNLEN = 15
DNLEN = CNLEN
UNLEN = 256
MAX_BUFFER_SIZE = (DNLEN+UNLEN+1+1)

  
TASK_FLAG_INTERACTIVE                  = 0x1
TASK_FLAG_DELETE_WHEN_DONE             = 0x2
TASK_FLAG_DISABLED                     = 0x4
TASK_FLAG_START_ONLY_IF_IDLE           = 0x10
TASK_FLAG_KILL_ON_IDLE_END             = 0x20
TASK_FLAG_DONT_START_IF_ON_BATTERIES   = 0x40
TASK_FLAG_KILL_IF_GOING_ON_BATTERIES   = 0x80
TASK_FLAG_RUN_ONLY_IF_DOCKED           = 0x100
TASK_FLAG_HIDDEN                       = 0x200
TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET = 0x400
TASK_FLAG_RESTART_ON_IDLE_RESUME       = 0x800
TASK_FLAG_SYSTEM_REQUIRED              = 0x1000
TASK_FLAG_RUN_ONLY_IF_LOGGED_ON        = 0x2000

  
  
  
  
class AT_INFO(NDRSTRUCT):
    structure =  (
        ('JobTime',DWORD),
        ('DaysOfMonth',DWORD),
        ('DaysOfWeek',UCHAR),
        ('Flags',UCHAR),
        ('Command',LPWSTR),
    )

class LPAT_INFO(NDRPOINTER):
    referent = (
        ('Data',AT_INFO),
    )

  
class AT_ENUM(NDRSTRUCT):
    structure =  (
        ('JobId',DWORD),
        ('JobTime',DWORD),
        ('DaysOfMonth',DWORD),
        ('DaysOfWeek',UCHAR),
        ('Flags',UCHAR),
        ('Command',LPWSTR),
    )

class AT_ENUM_ARRAY(NDRUniConformantArray):
    item = AT_ENUM

class LPAT_ENUM_ARRAY(NDRPOINTER):
    referent = (
        ('Data',AT_ENUM_ARRAY),
    )

  
class AT_ENUM_CONTAINER(NDRSTRUCT):
    structure =  (
        ('EntriesRead',DWORD),
        ('Buffer',LPAT_ENUM_ARRAY),
    )

  
  
  
  
class NetrJobAdd(NDRCALL):
    opnum = 0
    structure = (
        ('ServerName',ATSVC_HANDLE),
        ('pAtInfo', AT_INFO),
    )

class NetrJobAddResponse(NDRCALL):
    structure = (
        ('pJobId',DWORD),
        ('ErrorCode',ULONG),
    )

  
class NetrJobDel(NDRCALL):
    opnum = 1
    structure = (
        ('ServerName',ATSVC_HANDLE),
        ('MinJobId', DWORD),
        ('MaxJobId', DWORD),
    )

class NetrJobDelResponse(NDRCALL):
    structure = (
        ('ErrorCode',ULONG),
    )

  
class NetrJobEnum(NDRCALL):
    opnum = 2
    structure = (
        ('ServerName',ATSVC_HANDLE),
        ('pEnumContainer', AT_ENUM_CONTAINER),
        ('PreferedMaximumLength', DWORD),
        ('pResumeHandle', DWORD),
    )

class NetrJobEnumResponse(NDRCALL):
    structure = (
        ('pEnumContainer', AT_ENUM_CONTAINER),
        ('pTotalEntries', DWORD),
        ('pResumeHandle',LPDWORD),
        ('ErrorCode',ULONG),
    )

  
class NetrJobGetInfo(NDRCALL):
    opnum = 3
    structure = (
        ('ServerName',ATSVC_HANDLE),
        ('JobId', DWORD),
    )

class NetrJobGetInfoResponse(NDRCALL):
    structure = (
        ('ppAtInfo', LPAT_INFO),
        ('ErrorCode',ULONG),
    )

  
  
  
OPNUMS = {
 0 : (NetrJobAdd,NetrJobAddResponse ),
 1 : (NetrJobDel,NetrJobDelResponse ),
 2 : (NetrJobEnum,NetrJobEnumResponse ),
 3 : (NetrJobGetInfo,NetrJobGetInfoResponse ),
}

  
  
  
def hNetrJobAdd(dce, serverName = NULL, atInfo = NULL):
    netrJobAdd = NetrJobAdd()
    netrJobAdd['ServerName'] = serverName
    netrJobAdd['pAtInfo'] = atInfo
    return dce.request(netrJobAdd)

def hNetrJobDel(dce, serverName = NULL, minJobId = 0, maxJobId = 0):
    netrJobDel = NetrJobDel()
    netrJobDel['ServerName'] = serverName
    netrJobDel['MinJobId'] = minJobId
    netrJobDel['MaxJobId'] = maxJobId
    return dce.request(netrJobDel)

def hNetrJobEnum(dce, serverName = NULL, pEnumContainer = NULL, preferedMaximumLength = 0xffffffff):
    netrJobEnum = NetrJobEnum()
    netrJobEnum['ServerName'] = serverName
    netrJobEnum['pEnumContainer']['Buffer'] = pEnumContainer
    netrJobEnum['PreferedMaximumLength'] = preferedMaximumLength
    return dce.request(netrJobEnum)

def hNetrJobGetInfo(dce, serverName = NULL, jobId = 0):
    netrJobGetInfo = NetrJobGetInfo()
    netrJobGetInfo['ServerName'] = serverName
    netrJobGetInfo['JobId'] = jobId
    return dce.request(netrJobGetInfo)
