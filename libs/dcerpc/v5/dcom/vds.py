from __future__ import division
from __future__ import print_function
from libs.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantVaryingArray, NDRENUM
from libs.dcerpc.v5.dcomrt import DCOMCALL, DCOMANSWER, IRemUnknown2, PMInterfacePointer, INTERFACE
from libs.dcerpc.v5.dtypes import LPWSTR, ULONG, DWORD, SHORT, GUID
from libs.dcerpc.v5.rpcrt import DCERPCException
from libs.dcerpc.v5.enum import Enum
from libs import hresult_errors
from libs.uuid import string_to_bin

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__( self ):
        if self.error_code in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[self.error_code][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[self.error_code][1] 
            return 'VDS SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'VDS SessionError: unknown error code: 0x%x' % (self.error_code)

  
  
  
  
CLSID_VirtualDiskService = string_to_bin('7D1933CB-86F6-4A98-8628-01BE94C9A575')
IID_IEnumVdsObject = string_to_bin('118610B7-8D94-4030-B5B8-500889788E4E')
IID_IVdsAdviseSink = string_to_bin('8326CD1D-CF59-4936-B786-5EFC08798E25')
IID_IVdsAsync = string_to_bin('D5D23B6D-5A55-4492-9889-397A3C2D2DBC')
IID_IVdsServiceInitialization = string_to_bin('4AFC3636-DB01-4052-80C3-03BBCB8D3C69')
IID_IVdsService = string_to_bin('0818A8EF-9BA9-40D8-A6F9-E22833CC771E')
IID_IVdsSwProvider = string_to_bin('9AA58360-CE33-4F92-B658-ED24B14425B8')
IID_IVdsProvider = string_to_bin('10C5E575-7984-4E81-A56B-431F5F92AE42')

error_status_t = ULONG

  
VDS_OBJECT_ID = GUID

  
  
  
  
class VDS_SERVICE_PROP(NDRSTRUCT):
    structure = (
        ('pwszVersion',LPWSTR),
        ('ulFlags',ULONG),
    )

class OBJECT_ARRAY(NDRUniConformantVaryingArray):
    item = PMInterfacePointer

  
class VDS_PROVIDER_TYPE(NDRENUM):
    class enumItems(Enum):
        VDS_PT_UNKNOWN     = 0
        VDS_PT_SOFTWARE    = 1
        VDS_PT_HARDWARE    = 2
        VDS_PT_VIRTUALDISK = 3
        VDS_PT_MAX         = 4

  
class VDS_PROVIDER_PROP(NDRSTRUCT):
    structure = (
        ('id',VDS_OBJECT_ID),
        ('pwszName',LPWSTR),
        ('guidVersionId',GUID),
        ('pwszVersion',LPWSTR),
        ('type',VDS_PROVIDER_TYPE),
        ('ulFlags',ULONG),
        ('ulStripeSizeFlags',ULONG),
        ('sRebuildPriority',SHORT),
    )

  
  
  

  
class IVdsServiceInitialization_Initialize(DCOMCALL):
    opnum = 3
    structure = (
       ('pwszMachineName', LPWSTR),
    )

class IVdsServiceInitialization_InitializeResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IVdsService_IsServiceReady(DCOMCALL):
    opnum = 3
    structure = (
    )

class IVdsService_IsServiceReadyResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IVdsService_WaitForServiceReady(DCOMCALL):
    opnum = 4
    structure = (
    )

class IVdsService_WaitForServiceReadyResponse(DCOMANSWER):
    structure = (
       ('ErrorCode', error_status_t),
    )

  
class IVdsService_GetProperties(DCOMCALL):
    opnum = 5
    structure = (
    )

class IVdsService_GetPropertiesResponse(DCOMANSWER):
    structure = (
       ('pServiceProp', VDS_SERVICE_PROP),
       ('ErrorCode', error_status_t),
    )

  
class IVdsService_QueryProviders(DCOMCALL):
    opnum = 6
    structure = (
        ('masks', DWORD),
    )

class IVdsService_QueryProvidersResponse(DCOMANSWER):
    structure = (
       ('ppEnum', PMInterfacePointer),
       ('ErrorCode', error_status_t),
    )

  
  
class IEnumVdsObject_Next(DCOMCALL):
    opnum = 3
    structure = (
       ('celt', ULONG),
    )

class IEnumVdsObject_NextResponse(DCOMANSWER):
    structure = (
       ('ppObjectArray', OBJECT_ARRAY),
       ('pcFetched', ULONG),
       ('ErrorCode', error_status_t),
    )
  
class IVdsProvider_GetProperties(DCOMCALL):
    opnum = 3
    structure = (
    )

class IVdsProvider_GetPropertiesResponse(DCOMANSWER):
    structure = (
       ('pProviderProp', VDS_PROVIDER_PROP),
       ('ErrorCode', error_status_t),
    )

  
  
  
OPNUMS = {
}

  
  
  
class IEnumVdsObject(IRemUnknown2):
    def Next(self, celt=0xffff):
        request = IEnumVdsObject_Next()
        request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
        request['ORPCthis']['flags'] = 0
        request['celt'] = celt
        try:
            resp = self.request(request, uuid = self.get_iPid())
        except Exception as e:
            resp = e.get_packet()
              
            if resp['ErrorCode'] != 1:
                raise
        interfaces = list()
        for interface in resp['ppObjectArray']:
            interfaces.append(IRemUnknown2(INTERFACE(self.get_cinstance(), ''.join(interface['abData']), self.get_ipidRemUnknown(), target = self.get_target())))
        return interfaces

class IVdsProvider(IRemUnknown2):
    def GetProperties(self):
        request = IVdsProvider_GetProperties()
        request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
        request['ORPCthis']['flags'] = 0
        resp = self.request(request, uuid = self.get_iPid())
        return resp 

class IVdsServiceInitialization(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)

    def Initialize(self):
        request = IVdsServiceInitialization_Initialize()
        request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
        request['ORPCthis']['flags'] = 0
        request['pwszMachineName'] = '\x00'
        resp = self.request(request, uuid = self.get_iPid())
        return resp 

class IVdsService(IRemUnknown2):
    def __init__(self, interface):
        IRemUnknown2.__init__(self, interface)

    def IsServiceReady(self):
        request = IVdsService_IsServiceReady()
        request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
        request['ORPCthis']['flags'] = 0
        try:
            resp = self.request(request, uuid = self.get_iPid())
        except Exception as e:
            resp = e.get_packet()
        return resp 

    def WaitForServiceReady(self):
        request = IVdsService_WaitForServiceReady()
        request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
        request['ORPCthis']['flags'] = 0
        resp = self.request(request, uuid = self.get_iPid())
        return resp 

    def GetProperties(self):
        request = IVdsService_GetProperties()
        request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
        request['ORPCthis']['flags'] = 0
        resp = self.request(request, uuid = self.get_iPid())
        return resp 

    def QueryProviders(self, masks):
        request = IVdsService_QueryProviders()
        request['ORPCthis'] = self.get_cinstance().get_ORPCthis()
        request['ORPCthis']['flags'] = 0
        request['masks'] = masks
        resp = self.request(request, uuid = self.get_iPid())
        return IEnumVdsObject(INTERFACE(self.get_cinstance(), ''.join(resp['ppEnum']['abData']), self.get_ipidRemUnknown(), target = self.get_target()))
