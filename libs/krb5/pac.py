from libs.dcerpc.v5.dtypes import ULONG, RPC_UNICODE_STRING, FILETIME, PRPC_SID, USHORT
from libs.dcerpc.v5.ndr import NDRSTRUCT, NDRUniConformantArray, NDRPOINTER
from libs.dcerpc.v5.nrpc import USER_SESSION_KEY, CHAR_FIXED_8_ARRAY, PUCHAR_ARRAY, PRPC_UNICODE_STRING_ARRAY
from libs.dcerpc.v5.rpcrt import TypeSerialization1
from libs.structure import Structure


PAC_LOGON_INFO       = 1
PAC_CREDENTIALS_INFO = 2
PAC_SERVER_CHECKSUM  = 6
PAC_PRIVSVR_CHECKSUM = 7
PAC_CLIENT_INFO_TYPE = 10
PAC_DELEGATION_INFO  = 11
PAC_UPN_DNS_INFO     = 12


PISID = PRPC_SID

  
class KERB_SID_AND_ATTRIBUTES(NDRSTRUCT):
    structure = (
        ('Sid', PISID),
        ('Attributes', ULONG),
    )

class KERB_SID_AND_ATTRIBUTES_ARRAY(NDRUniConformantArray):
    item = KERB_SID_AND_ATTRIBUTES

class PKERB_SID_AND_ATTRIBUTES_ARRAY(NDRPOINTER):
    referent = (
        ('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),
    )

  
from libs.dcerpc.v5.nrpc import PGROUP_MEMBERSHIP_ARRAY

  
class DOMAIN_GROUP_MEMBERSHIP(NDRSTRUCT):
    structure = (
        ('DomainId', PISID),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
    )

class DOMAIN_GROUP_MEMBERSHIP_ARRAY(NDRUniConformantArray):
    item = DOMAIN_GROUP_MEMBERSHIP

class PDOMAIN_GROUP_MEMBERSHIP_ARRAY(NDRPOINTER):
    referent = (
        ('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),
    )

  
class PACTYPE(Structure):
    structure = (
        ('cBuffers', '<L=0'),
        ('Version', '<L=0'),
        ('Buffers', ':'),
    )

  
class PAC_INFO_BUFFER(Structure):
    structure = (
        ('ulType', '<L=0'),
        ('cbBufferSize', '<L=0'),
        ('Offset', '<Q=0'),
    )

  
class KERB_VALIDATION_INFO(NDRSTRUCT):
    structure = (
        ('LogonTime', FILETIME),
        ('LogoffTime', FILETIME),
        ('KickOffTime', FILETIME),
        ('PasswordLastSet', FILETIME),
        ('PasswordCanChange', FILETIME),
        ('PasswordMustChange', FILETIME),
        ('EffectiveName', RPC_UNICODE_STRING),
        ('FullName', RPC_UNICODE_STRING),
        ('LogonScript', RPC_UNICODE_STRING),
        ('ProfilePath', RPC_UNICODE_STRING),
        ('HomeDirectory', RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', RPC_UNICODE_STRING),
        ('LogonCount', USHORT),
        ('BadPasswordCount', USHORT),
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('GroupCount', ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
        ('UserFlags', ULONG),
        ('UserSessionKey', USER_SESSION_KEY),
        ('LogonServer', RPC_UNICODE_STRING),
        ('LogonDomainName', RPC_UNICODE_STRING),
        ('LogonDomainId', PRPC_SID),

          
        ('LMKey', CHAR_FIXED_8_ARRAY),

        ('UserAccountControl', ULONG),
        ('SubAuthStatus', ULONG),
        ('LastSuccessfulILogon', FILETIME),
        ('LastFailedILogon', FILETIME),
        ('FailedILogonCount', ULONG),
        ('Reserved3', ULONG),

        ('SidCount', ULONG),
          
        ('ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY),
        ('ResourceGroupDomainSid', PISID),
        ('ResourceGroupCount', ULONG),
        ('ResourceGroupIds', PGROUP_MEMBERSHIP_ARRAY),
    )

class PKERB_VALIDATION_INFO(NDRPOINTER):
    referent = (
        ('Data', KERB_VALIDATION_INFO),
    )

  
class PAC_CREDENTIAL_INFO(Structure):
    structure = (
        ('Version', '<L=0'),
        ('EncryptionType', '<L=0'),
        ('SerializedData', ':'),
    )

  
class SECPKG_SUPPLEMENTAL_CRED(NDRSTRUCT):
    structure = (
        ('PackageName', RPC_UNICODE_STRING),
        ('CredentialSize', ULONG),
        ('Credentials', PUCHAR_ARRAY),
    )

class SECPKG_SUPPLEMENTAL_CRED_ARRAY(NDRUniConformantArray):
    item = SECPKG_SUPPLEMENTAL_CRED

  
class PAC_CREDENTIAL_DATA(NDRSTRUCT):
    structure = (
        ('CredentialCount', ULONG),
        ('Credentials', SECPKG_SUPPLEMENTAL_CRED_ARRAY),
    )

  
class NTLM_SUPPLEMENTAL_CREDENTIAL(NDRSTRUCT):
    structure = (
        ('Version', ULONG),
        ('Flags', ULONG),
        ('LmPassword', '16s=b""'),
        ('NtPassword', '16s=b""'),
    )

  
class PAC_CLIENT_INFO(Structure):
    structure = (
        ('ClientId', '<Q=0'),
        ('NameLength', '<H=0'),
        ('_Name', '_-Name', 'self["NameLength"]'),
        ('Name', ':'),
    )

  
class PAC_SIGNATURE_DATA(Structure):
    structure = (
        ('SignatureType', '<l=0'),
        ('Signature', ':'),
    )

  
class S4U_DELEGATION_INFO(NDRSTRUCT):
    structure = (
        ('S4U2proxyTarget', RPC_UNICODE_STRING),
        ('TransitedListSize', ULONG),
        ('S4UTransitedServices', PRPC_UNICODE_STRING_ARRAY ),
    )

  
class UPN_DNS_INFO(Structure):
    structure = (
        ('UpnLength', '<H=0'),
        ('UpnOffset', '<H=0'),
        ('DnsDomainNameLength', '<H=0'),
        ('DnsDomainNameOffset', '<H=0'),
        ('Flags', '<L=0'),
    )

  
class PAC_CLIENT_CLAIMS_INFO(Structure):
    structure = (
        ('Claims', ':'),
    )

  
class PAC_DEVICE_INFO(NDRSTRUCT):
    structure = (
        ('UserId', ULONG),
        ('PrimaryGroupId', ULONG),
        ('AccountDomainId', PISID ),
        ('AccountGroupCount', ULONG ),
        ('AccountGroupIds', PGROUP_MEMBERSHIP_ARRAY ),
        ('SidCount', ULONG ),
        ('ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY ),
        ('DomainGroupCount', ULONG ),
        ('DomainGroup', PDOMAIN_GROUP_MEMBERSHIP_ARRAY ),
    )

  
class PAC_DEVICE_CLAIMS_INFO(Structure):
    structure = (
        ('Claims', ':'),
    )

class VALIDATION_INFO(TypeSerialization1):
    structure = (
        ('Data', PKERB_VALIDATION_INFO),
    )
