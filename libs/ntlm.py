from __future__ import division
from __future__ import print_function
import base64
import struct
import calendar
import time
import hashlib
import random
import string
import binascii
from six import b

from libs.structure import Structure
from libs import LOG

USE_NTLMv2 = True   
TEST_CASE = False   


def computeResponse(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='', nthash='',
                    use_ntlmv2=USE_NTLMv2):
    if use_ntlmv2:
        return computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password,
                                     lmhash, nthash, use_ntlmv2=use_ntlmv2)
    else:
        return computeResponseNTLMv1(flags, serverChallenge, clientChallenge, serverName, domain, user, password,
                                     lmhash, nthash, use_ntlmv2=use_ntlmv2)
try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    LOG.critical("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.critical("See https://pypi.org/project/pycryptodomex/")

NTLM_AUTH_NONE          = 1
NTLM_AUTH_CONNECT       = 2
NTLM_AUTH_CALL          = 3
NTLM_AUTH_PKT           = 4
NTLM_AUTH_PKT_INTEGRITY = 5
NTLM_AUTH_PKT_PRIVACY   = 6

  
  
  
  
  
  
NTLMSSP_NEGOTIATE_56                       = 0x80000000

  
  
  
NTLMSSP_NEGOTIATE_KEY_EXCH                 = 0x40000000

  
  
  
  
  
  
  
NTLMSSP_NEGOTIATE_128                      = 0x20000000

NTLMSSP_RESERVED_1                         = 0x10000000
NTLMSSP_RESERVED_2                         = 0x08000000
NTLMSSP_RESERVED_3                         = 0x04000000

  
  
  
NTLMSSP_NEGOTIATE_VERSION                  = 0x02000000
NTLMSSP_RESERVED_4                         = 0x01000000

  
  
NTLMSSP_NEGOTIATE_TARGET_INFO              = 0x00800000

  
  
NTLMSSP_REQUEST_NON_NT_SESSION_KEY         = 0x00400000
NTLMSSP_RESERVED_5                         = 0x00200000

  
NTLMSSP_NEGOTIATE_IDENTIFY                 = 0x00100000

  
  
  
  
  
  
  
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
NTLMSSP_NEGOTIATE_NTLM2                    = 0x00080000
NTLMSSP_TARGET_TYPE_SHARE                  = 0x00040000

  
  
  
  
NTLMSSP_TARGET_TYPE_SERVER                 = 0x00020000

  
  
  
  
NTLMSSP_TARGET_TYPE_DOMAIN                 = 0x00010000

  
  
  
  
NTLMSSP_NEGOTIATE_ALWAYS_SIGN              = 0x00008000         
NTLMSSP_RESERVED_6                         = 0x00004000

  
  
  
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000

  
  
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      = 0x00001000

  
NTLMSSP_NEGOTIATE_ANONYMOUS                = 0x00000800

  
NTLMSSP_NEGOTIATE_NT_ONLY                  = 0x00000400

  
  
  
NTLMSSP_NEGOTIATE_NTLM                     = 0x00000200
NTLMSSP_RESERVED_8                         = 0x00000100

  
  
  
  
  
  
NTLMSSP_NEGOTIATE_LM_KEY                   = 0x00000080

  
  
  
NTLMSSP_NEGOTIATE_DATAGRAM                 = 0x00000040

  
  
  
  
NTLMSSP_NEGOTIATE_SEAL                     = 0x00000020

  
  
  
NTLMSSP_NEGOTIATE_SIGN                     = 0x00000010         
NTLMSSP_RESERVED_9                         = 0x00000008

  
  
NTLMSSP_REQUEST_TARGET                     = 0x00000004

  
  
NTLM_NEGOTIATE_OEM                         = 0x00000002

  
NTLMSSP_NEGOTIATE_UNICODE                  = 0x00000001

  
NTLMSSP_AV_EOL              = 0x00
NTLMSSP_AV_HOSTNAME         = 0x01
NTLMSSP_AV_DOMAINNAME       = 0x02
NTLMSSP_AV_DNS_HOSTNAME     = 0x03
NTLMSSP_AV_DNS_DOMAINNAME   = 0x04
NTLMSSP_AV_DNS_TREENAME     = 0x05
NTLMSSP_AV_FLAGS            = 0x06
NTLMSSP_AV_TIME             = 0x07
NTLMSSP_AV_RESTRICTIONS     = 0x08
NTLMSSP_AV_TARGET_NAME      = 0x09
NTLMSSP_AV_CHANNEL_BINDINGS = 0x0a

class AV_PAIRS:
    def __init__(self, data = None):
        self.fields = {}
        if data is not None:
            self.fromString(data)

    def __setitem__(self,key,value):
        self.fields[key] = (len(value),value)

    def __getitem__(self, key):
        if key in self.fields:
           return self.fields[key]
        return None

    def __delitem__(self, key):
        del self.fields[key]

    def __len__(self):
        return len(self.getData())

    def __str__(self):
        return len(self.getData())

    def fromString(self, data):
        tInfo = data
        fType = 0xff
        while fType is not NTLMSSP_AV_EOL:
            fType = struct.unpack('<H',tInfo[:struct.calcsize('<H')])[0]
            tInfo = tInfo[struct.calcsize('<H'):]
            length = struct.unpack('<H',tInfo[:struct.calcsize('<H')])[0]
            tInfo = tInfo[struct.calcsize('<H'):]
            content = tInfo[:length]
            self.fields[fType]=(length,content)
            tInfo = tInfo[length:]

    def dump(self):
        for i in list(self.fields.keys()):
            print("%s: {%r}" % (i,self[i]))

    def getData(self):
        if NTLMSSP_AV_EOL in self.fields:
            del self.fields[NTLMSSP_AV_EOL]
        ans = b''
        for i in list(self.fields.keys()):
            ans+= struct.pack('<HH', i, self[i][0])
            ans+= self[i][1]
 
          
        ans += struct.pack('<HH', NTLMSSP_AV_EOL, 0)

        return ans

  
  
class VERSION(Structure):
    NTLMSSP_REVISION_W2K3 = 0x0F

    structure = (
        ('ProductMajorVersion', '<B=0'),
        ('ProductMinorVersion', '<B=0'),
        ('ProductBuild', '<H=0'),
        ('Reserved', '3s=""'),
        ('NTLMRevisionCurrent', '<B=self.NTLMSSP_REVISION_W2K3'),
    )

class NTLMAuthNegotiate(Structure):

    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=1'),
        ('flags','<L'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L=0'),
        ('host_len','<H-host_name'),
        ('host_maxlen','<H-host_name'),
        ('host_offset','<L=0'),
        ('os_version',':'),
        ('host_name',':'),
        ('domain_name',':'))
                                                                                
    def __init__(self):
        Structure.__init__(self)
        self['flags']= (
               NTLMSSP_NEGOTIATE_128     |
               NTLMSSP_NEGOTIATE_KEY_EXCH|
                 
               NTLMSSP_NEGOTIATE_NTLM    |
               NTLMSSP_NEGOTIATE_UNICODE     |
                 
               NTLMSSP_NEGOTIATE_SIGN        |
               NTLMSSP_NEGOTIATE_SEAL        |
                 
               0)
        self['host_name']=''
        self['domain_name']=''
        self['os_version']=''
        self._workstation = ''

    def setWorkstation(self, workstation):
        self._workstation = workstation

    def getWorkstation(self):
        return self._workstation

    def __hasNegotiateVersion(self):
        return (self['flags'] & NTLMSSP_NEGOTIATE_VERSION) == NTLMSSP_NEGOTIATE_VERSION

    def getData(self):
        if len(self.fields['host_name']) > 0:
            self['flags'] |= NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
        if len(self.fields['domain_name']) > 0:
            self['flags'] |= NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
        version_len = len(self.fields['os_version'])
        if version_len > 0:
            self['flags'] |= NTLMSSP_NEGOTIATE_VERSION
        elif self.__hasNegotiateVersion():
            raise Exception('Must provide the os_version field if the NTLMSSP_NEGOTIATE_VERSION flag is set')
        if (self['flags'] & NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED) == NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED:
            self['host_offset']=32 + version_len
        if (self['flags'] & NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED) == NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED:
            self['domain_offset']=32+len(self['host_name']) + version_len
        return Structure.getData(self)

    def fromString(self,data):
        Structure.fromString(self,data)

        domain_offset = self['domain_offset']
        domain_end    = self['domain_len'] + domain_offset
        self['domain_name'] = data[ domain_offset : domain_end ]

        host_offset = self['host_offset']
        host_end    = self['host_len'] + host_offset
        self['host_name'] = data[ host_offset : host_end ]

        if len(data) >= 36 and self.__hasNegotiateVersion():
            self['os_version'] = VERSION(data[32:])
        else:
            self['os_version'] = ''

class NTLMAuthChallenge(Structure):

    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=2'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L=40'),
        ('flags','<L=0'),
        ('challenge','8s'),
        ('reserved','8s=""'),
        ('TargetInfoFields_len','<H-TargetInfoFields'),
        ('TargetInfoFields_max_len','<H-TargetInfoFields'),
        ('TargetInfoFields_offset','<L'),
        ('VersionLen','_-Version','self.checkVersion(self["flags"])'), 
        ('Version',':'),
        ('domain_name',':'),
        ('TargetInfoFields',':'))

    @staticmethod
    def checkVersion(flags):
        if flags is not None:
           if flags & NTLMSSP_NEGOTIATE_VERSION == 0:
              return 0
        return 8

    def getData(self):
        if self['TargetInfoFields'] is not None and type(self['TargetInfoFields']) is not bytes:
            raw_av_fields = self['TargetInfoFields'].getData()
            self['TargetInfoFields'] = raw_av_fields
        return Structure.getData(self)

    def fromString(self,data):
        Structure.fromString(self,data)
        self['domain_name'] = data[self['domain_offset']:][:self['domain_len']]
        self['TargetInfoFields'] = data[self['TargetInfoFields_offset']:][:self['TargetInfoFields_len']]
        return self
        
class NTLMAuthChallengeResponse(Structure):

    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=3'),
        ('lanman_len','<H-lanman'),
        ('lanman_max_len','<H-lanman'),
        ('lanman_offset','<L'),
        ('ntlm_len','<H-ntlm'),
        ('ntlm_max_len','<H-ntlm'),
        ('ntlm_offset','<L'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L'),
        ('user_len','<H-user_name'),
        ('user_max_len','<H-user_name'),
        ('user_offset','<L'),
        ('host_len','<H-host_name'),
        ('host_max_len','<H-host_name'),
        ('host_offset','<L'),
        ('session_key_len','<H-session_key'),
        ('session_key_max_len','<H-session_key'),
        ('session_key_offset','<L'),
        ('flags','<L'),
        ('VersionLen','_-Version','self.checkVersion(self["flags"])'), 
        ('Version',':=""'),
        ('MICLen','_-MIC','self.checkMIC(self["flags"])'),
        ('MIC',':=""'),
        ('domain_name',':'),
        ('user_name',':'),
        ('host_name',':'),
        ('lanman',':'),
        ('ntlm',':'),
        ('session_key',':'))

    def __init__(self, username = '', password = '', challenge = '', lmhash = '', nthash = '', flags = 0):
        Structure.__init__(self)
        self['session_key']=''
        self['user_name']=username.encode('utf-16le')
        self['domain_name']=''   
        self['host_name']=''   
        self['flags'] = (     
              
              
           NTLMSSP_NEGOTIATE_128     |
           NTLMSSP_NEGOTIATE_KEY_EXCH|
             
           NTLMSSP_NEGOTIATE_NTLM    |
           NTLMSSP_NEGOTIATE_UNICODE     |
             
           NTLMSSP_NEGOTIATE_SIGN        |
           NTLMSSP_NEGOTIATE_SEAL        |
             
           0)
          
        if username and ( lmhash != '' or nthash != ''):            
            self['lanman'] = get_ntlmv1_response(lmhash, challenge)
            self['ntlm'] = get_ntlmv1_response(nthash, challenge)
        elif username and password:
            lmhash = compute_lmhash(password)
            nthash = compute_nthash(password)
            self['lanman']=get_ntlmv1_response(lmhash, challenge)
            self['ntlm']=get_ntlmv1_response(nthash, challenge)      
        else:
            self['lanman'] = ''
            self['ntlm'] = ''
            if not self['host_name']:
                self['host_name'] = 'NULL'.encode('utf-16le')        

    @staticmethod
    def checkVersion(flags):
        if flags is not None:
           if flags & NTLMSSP_NEGOTIATE_VERSION == 0:
              return 0
        return 8

    @staticmethod
    def checkMIC(flags):
          
        if flags is not None:
           if flags & NTLMSSP_NEGOTIATE_VERSION == 0:
              return 0
        return 16
                                                                                
    def getData(self):
        self['domain_offset']=64+self.checkMIC(self["flags"])+self.checkVersion(self["flags"])
        self['user_offset']=64+self.checkMIC(self["flags"])+self.checkVersion(self["flags"])+len(self['domain_name'])
        self['host_offset']=self['user_offset']+len(self['user_name'])
        self['lanman_offset']=self['host_offset']+len(self['host_name'])
        self['ntlm_offset']=self['lanman_offset']+len(self['lanman'])
        self['session_key_offset']=self['ntlm_offset']+len(self['ntlm'])
        return Structure.getData(self)

    def fromString(self,data):
        Structure.fromString(self,data)
          
          
          

        domain_offset = self['domain_offset']
        domain_end = self['domain_len'] + domain_offset
        self['domain_name'] = data[ domain_offset : domain_end ]

        host_offset = self['host_offset']
        host_end    = self['host_len'] + host_offset
        self['host_name'] = data[ host_offset: host_end ]

        user_offset = self['user_offset']
        user_end    = self['user_len'] + user_offset
        self['user_name'] = data[ user_offset: user_end ]

        ntlm_offset = self['ntlm_offset'] 
        ntlm_end    = self['ntlm_len'] + ntlm_offset 
        self['ntlm'] = data[ ntlm_offset : ntlm_end ]

        lanman_offset = self['lanman_offset'] 
        lanman_end    = self['lanman_len'] + lanman_offset
        self['lanman'] = data[ lanman_offset : lanman_end]

class libsStructure(Structure):
    def set_parent(self, other):
        self.parent = other

    def get_packet(self):
        return str(self)

    def get_size(self):
        return len(self)

class ExtendedOrNotMessageSignature(Structure):
    def __init__(self, flags = 0, **kargs):
        if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            self.structure = self.extendedMessageSignature
        else:
            self.structure = self.MessageSignature
        return Structure.__init__(self, **kargs)

class NTLMMessageSignature(ExtendedOrNotMessageSignature):
      extendedMessageSignature = (
          ('Version','<L=1'),
          ('Checksum','<q'),
          ('SeqNum','<I'),
      )

      MessageSignature = (
          ('Version','<L=1'),
          ('RandomPad','<I=0'),
          ('Checksum','<I'),
          ('SeqNum','<I'),
      )

KNOWN_DES_INPUT = b"KGS!@#$%"

def __expand_DES_key(key):
      
    if not isinstance(key, bytes):
        key = bytes(key)
    key  = bytearray(key[:7]).ljust(7, b'\x00')
    s = bytearray()
    s.append(((key[0] >> 1) & 0x7f) << 1)
    s.append(((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1)
    s.append(((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1)
    s.append(((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1)
    s.append(((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1)
    s.append(((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1)
    s.append(((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1)
    s.append((key[6] & 0x7f) << 1)
    return bytes(s)

def __DES_block(key, msg):
    cipher = DES.new(__expand_DES_key(key),DES.MODE_ECB)
    return cipher.encrypt(msg)

def ntlmssp_DES_encrypt(key, challenge):
    answer  = __DES_block(key[:7], challenge)
    answer += __DES_block(key[7:14], challenge)
    answer += __DES_block(key[14:], challenge)
    return answer

  

def getNTLMSSPType1(workstation='', domain='', signingRequired = False, use_ntlmv2 = USE_NTLMv2):
      
      
    import sys
    encoding = sys.getfilesystemencoding()
    if encoding is not None:
        try:
            workstation.encode('utf-16le')
        except:
            workstation = workstation.decode(encoding)
        try:
            domain.encode('utf-16le')
        except:
            domain = domain.decode(encoding)

      
    auth = NTLMAuthNegotiate()
    auth['flags']=0
    if signingRequired:
       auth['flags'] = NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
                       NTLMSSP_NEGOTIATE_SEAL
    if use_ntlmv2:
       auth['flags'] |= NTLMSSP_NEGOTIATE_TARGET_INFO
    auth['flags'] |= NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_UNICODE | \
                     NTLMSSP_REQUEST_TARGET |  NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56

      
      
    auth.setWorkstation(workstation)

    return auth

def getNTLMSSPType3(type1, type2, user, password, domain, lmhash = '', nthash = '', use_ntlmv2 = USE_NTLMv2):

      
    if password is None:
        password = ''

      
      
    import sys
    encoding = sys.getfilesystemencoding()
    if encoding is not None:
        try:
            user.encode('utf-16le')
        except:
            user = user.decode(encoding)
        try:
            password.encode('utf-16le')
        except:
            password = password.decode(encoding)
        try:
            domain.encode('utf-16le')
        except:
            domain = user.decode(encoding)

    ntlmChallenge = NTLMAuthChallenge(type2)

      
    responseFlags = type1['flags']

      
      
    ntlmChallengeResponse = NTLMAuthChallengeResponse(user, password, ntlmChallenge['challenge'])

    clientChallenge = b("".join([random.choice(string.digits+string.ascii_letters) for _ in range(8)]))

    serverName = ntlmChallenge['TargetInfoFields']

    ntResponse, lmResponse, sessionBaseKey = computeResponse(ntlmChallenge['flags'], ntlmChallenge['challenge'],
                                                             clientChallenge, serverName, domain, user, password,
                                                             lmhash, nthash, use_ntlmv2)

      
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) == 0:
          
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_128 ) == 0:
          
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_128
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH) == 0:
          
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_KEY_EXCH
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_SEAL) == 0:
          
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_SEAL
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_SIGN) == 0:
          
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_SIGN
    if (ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_ALWAYS_SIGN) == 0:
          
        responseFlags &= 0xffffffff ^ NTLMSSP_NEGOTIATE_ALWAYS_SIGN

    keyExchangeKey = KXKEY(ntlmChallenge['flags'], sessionBaseKey, lmResponse, ntlmChallenge['challenge'], password,
                           lmhash, nthash, use_ntlmv2)

      
    if user == '' and password == '' and lmhash == '' and nthash == '':
      keyExchangeKey = b'\x00'*16

      
    if ntlmChallenge['flags'] & NTLMSSP_NEGOTIATE_KEY_EXCH:
         
         
       exportedSessionKey = b("".join([random.choice(string.digits+string.ascii_letters) for _ in range(16)]))
         
         
         
         
             
         
                 
         
         
                 
         
         
         
         
             
         
         
         

       encryptedRandomSessionKey = generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey)
    else:
       encryptedRandomSessionKey = None
         
       exportedSessionKey        = keyExchangeKey

    ntlmChallengeResponse['flags'] = responseFlags
    ntlmChallengeResponse['domain_name'] = domain.encode('utf-16le')
    ntlmChallengeResponse['host_name'] = type1.getWorkstation().encode('utf-16le')
    if lmResponse == '':
        ntlmChallengeResponse['lanman'] = b'\x00'
    else:
        ntlmChallengeResponse['lanman'] = lmResponse
    ntlmChallengeResponse['ntlm'] = ntResponse
    if encryptedRandomSessionKey is not None: 
        ntlmChallengeResponse['session_key'] = encryptedRandomSessionKey

    return ntlmChallengeResponse, exportedSessionKey


  

def generateSessionKeyV1(password, lmhash, nthash):
    hash = MD4.new()
    hash.update(NTOWFv1(password, lmhash, nthash))
    return hash.digest()


def computeResponseNTLMv1(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                          nthash='', use_ntlmv2=USE_NTLMv2):
    if user == '' and password == '':
          
        lmResponse = ''
        ntResponse = ''
    else:
        lmhash = LMOWFv1(password, lmhash, nthash)
        nthash = NTOWFv1(password, lmhash, nthash)
        if flags & NTLMSSP_NEGOTIATE_LM_KEY:
           ntResponse = ''
           lmResponse = get_ntlmv1_response(lmhash, serverChallenge)
        elif flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
           md5 = hashlib.new('md5')
           chall = (serverChallenge + clientChallenge)
           md5.update(chall)
           ntResponse = ntlmssp_DES_encrypt(nthash, md5.digest()[:8])
           lmResponse = clientChallenge + b'\x00'*16
        else:
           ntResponse = get_ntlmv1_response(nthash,serverChallenge)
           lmResponse = get_ntlmv1_response(lmhash, serverChallenge)
   
    sessionBaseKey = generateSessionKeyV1(password, lmhash, nthash)
    return ntResponse, lmResponse, sessionBaseKey

def compute_lmhash(password):
      
    password = password.upper()
    lmhash  = __DES_block(b(password[:7]), KNOWN_DES_INPUT)
    lmhash += __DES_block(b(password[7:14]), KNOWN_DES_INPUT)
    return lmhash

def NTOWFv1(password, lmhash = '', nthash=''):
    if nthash != '':
       return nthash
    return compute_nthash(password)   

def LMOWFv1(password, lmhash = '', nthash=''):
    if lmhash != '':
       return lmhash
    return compute_lmhash(password)

def compute_nthash(password):
      
    try:
        password = str(password).encode('utf_16le')
    except UnicodeDecodeError:
        import sys
        password = password.decode(sys.getfilesystemencoding()).encode('utf_16le')

    hash = MD4.new()
    hash.update(password)
    return hash.digest()

def get_ntlmv1_response(key, challenge):
    return ntlmssp_DES_encrypt(key, challenge)

  

  

def MAC(flags, handle, signingKey, seqNum, message):
     
     
   messageSignature = NTLMMessageSignature(flags)
   if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
       if flags & NTLMSSP_NEGOTIATE_KEY_EXCH:
           messageSignature['Version'] = 1
           messageSignature['Checksum'] = \
           struct.unpack('<q', handle(hmac_md5(signingKey, struct.pack('<i', seqNum) + message)[:8]))[0]
           messageSignature['SeqNum'] = seqNum
           seqNum += 1
       else:
           messageSignature['Version'] = 1
           messageSignature['Checksum'] = struct.unpack('<q',hmac_md5(signingKey, struct.pack('<i',seqNum)+message)[:8])[0]
           messageSignature['SeqNum'] = seqNum
           seqNum += 1
   else:
       messageSignature['Version'] = 1
       messageSignature['Checksum'] = struct.pack('<I',binascii.crc32(message)& 0xFFFFFFFF)
       messageSignature['RandomPad'] = 0
       messageSignature['RandomPad'] = handle(struct.pack('<I',messageSignature['RandomPad']))
       messageSignature['Checksum'] = struct.unpack('<I',handle(messageSignature['Checksum']))[0]
       messageSignature['SeqNum'] = handle(b'\x00\x00\x00\x00')
       messageSignature['SeqNum'] = struct.unpack('<I',messageSignature['SeqNum'])[0] ^ seqNum
       messageSignature['RandomPad'] = 0
       
   return messageSignature

def SEAL(flags, signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, handle):
   sealedMessage = handle(messageToEncrypt)
   signature = MAC(flags, handle, signingKey, seqNum, messageToSign)
   return sealedMessage, signature

def SIGN(flags, signingKey, message, seqNum, handle):
   return MAC(flags, handle, signingKey, seqNum, message)

def SIGNKEY(flags, randomSessionKey, mode = 'Client'):
   if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
       if mode == 'Client':
           md5 = hashlib.new('md5')
           md5.update(randomSessionKey + b"session key to client-to-server signing key magic constant\x00")
           signKey = md5.digest()
       else:
           md5 = hashlib.new('md5')
           md5.update(randomSessionKey + b"session key to server-to-client signing key magic constant\x00")
           signKey = md5.digest()
   else:
       signKey = None
   return signKey

def SEALKEY(flags, randomSessionKey, mode = 'Client'):
   if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
       if flags & NTLMSSP_NEGOTIATE_128:
           sealKey = randomSessionKey
       elif flags & NTLMSSP_NEGOTIATE_56:
           sealKey = randomSessionKey[:7]
       else:
           sealKey = randomSessionKey[:5]

       if mode == 'Client':
               md5 = hashlib.new('md5')
               md5.update(sealKey + b'session key to client-to-server sealing key magic constant\x00')
               sealKey = md5.digest()
       else:
               md5 = hashlib.new('md5')
               md5.update(sealKey + b'session key to server-to-client sealing key magic constant\x00')
               sealKey = md5.digest()

   elif flags & NTLMSSP_NEGOTIATE_56:
       sealKey = randomSessionKey[:7] + b'\xa0'
   else:
       sealKey = randomSessionKey[:5] + b'\xe5\x38\xb0'

   return sealKey


def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
   cipher = ARC4.new(keyExchangeKey)
   cipher_encrypt = cipher.encrypt

   sessionKey = cipher_encrypt(exportedSessionKey)
   return sessionKey

def KXKEY(flags, sessionBaseKey, lmChallengeResponse, serverChallenge, password, lmhash, nthash, use_ntlmv2 = USE_NTLMv2):
   if use_ntlmv2:
       return sessionBaseKey

   if flags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
       if flags & NTLMSSP_NEGOTIATE_NTLM:
          keyExchangeKey = hmac_md5(sessionBaseKey, serverChallenge + lmChallengeResponse[:8])
       else:
          keyExchangeKey = sessionBaseKey
   elif flags & NTLMSSP_NEGOTIATE_NTLM:
       if flags & NTLMSSP_NEGOTIATE_LM_KEY:
           keyExchangeKey = __DES_block(LMOWFv1(password, lmhash)[:7], lmChallengeResponse[:8]) + __DES_block(
               LMOWFv1(password, lmhash)[7] + b'\xBD\xBD\xBD\xBD\xBD\xBD', lmChallengeResponse[:8])
       elif flags & NTLMSSP_REQUEST_NON_NT_SESSION_KEY:
          keyExchangeKey = LMOWFv1(password,lmhash)[:8] + b'\x00'*8
       else:
          keyExchangeKey = sessionBaseKey
   else:
       raise Exception("Can't create a valid KXKEY!")

   return keyExchangeKey
      
def hmac_md5(key, data):
    import hmac
    h = hmac.new(key, digestmod=hashlib.md5)
    h.update(data)
    return h.digest()

def NTOWFv2( user, password, domain, hash = ''):
    if hash != '':
       theHash = hash 
    else:
       theHash = compute_nthash(password)
    return hmac_md5(theHash, user.upper().encode('utf-16le') + domain.encode('utf-16le'))

def LMOWFv2( user, password, domain, lmhash = ''):
    return NTOWFv2( user, password, domain, lmhash)


def computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                          nthash='', use_ntlmv2=USE_NTLMv2):

    responseServerVersion = b'\x01'
    hiResponseServerVersion = b'\x01'
    responseKeyNT = NTOWFv2(user, password, domain, nthash)

    av_pairs = AV_PAIRS(serverName)
      
      
      
      
    if TEST_CASE is False:
        av_pairs[NTLMSSP_AV_TARGET_NAME] = 'cifs/'.encode('utf-16le') + av_pairs[NTLMSSP_AV_HOSTNAME][1]
        if av_pairs[NTLMSSP_AV_TIME] is not None:
           aTime = av_pairs[NTLMSSP_AV_TIME][1]
        else:
           aTime = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000) )
           av_pairs[NTLMSSP_AV_TIME] = aTime
        serverName = av_pairs.getData()
    else:
        aTime = b'\x00'*8

    temp = responseServerVersion + hiResponseServerVersion + b'\x00' * 6 + aTime + clientChallenge + b'\x00' * 4 + \
           serverName + b'\x00' * 4

    ntProofStr = hmac_md5(responseKeyNT, serverChallenge + temp)

    ntChallengeResponse = ntProofStr + temp
    lmChallengeResponse = hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
    sessionBaseKey = hmac_md5(responseKeyNT, ntProofStr)

    if user == '' and password == '':
          
        ntChallengeResponse = ''
        lmChallengeResponse = ''

    return ntChallengeResponse, lmChallengeResponse, sessionBaseKey

class NTLM_HTTP(object):
      
    MSG_TYPE = None

    @classmethod
    def get_instace(cls,msg_64):
        msg = None
        msg_type = 0
        if msg_64 != '':
            msg = base64.b64decode(msg_64[5:])   
            msg_type = ord(msg[8])
    
        for _cls in NTLM_HTTP.__subclasses__():
            if msg_type == _cls.MSG_TYPE:
                instance = _cls()
                instance.fromString(msg)
                return instance

    
class NTLM_HTTP_AuthRequired(NTLM_HTTP):
    commonHdr = ()
      
    MSG_TYPE = 0

    def fromString(self,data): 
        pass


class NTLM_HTTP_AuthNegotiate(NTLM_HTTP, NTLMAuthNegotiate):
    commonHdr = ()
    MSG_TYPE = 1

    def __init__(self):
        NTLMAuthNegotiate.__init__(self)


class NTLM_HTTP_AuthChallengeResponse(NTLM_HTTP, NTLMAuthChallengeResponse):
    commonHdr = ()
    MSG_TYPE = 3

    def __init__(self):
        NTLMAuthChallengeResponse.__init__(self)
