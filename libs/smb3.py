from __future__ import division
from __future__ import print_function

import socket
import ntpath
import random
import string
import struct
from six import indexbytes, b
from binascii import a2b_hex
from contextlib import contextmanager
from pyasn1.type.univ import noValue
from Cryptodome.Cipher import AES

from libs import nmb, ntlm, uuid, crypto
from libs.smb3structs import *
from libs.nt_errors import STATUS_SUCCESS, STATUS_MORE_PROCESSING_REQUIRED, STATUS_INVALID_PARAMETER, \
    STATUS_NO_MORE_FILES, STATUS_PENDING, STATUS_NOT_IMPLEMENTED, ERROR_MESSAGES
from libs.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp, ASN1_OID, asn1encode, ASN1_AID
from libs.krb5.gssapi import KRB5_AP_REQ


  
import hashlib, hmac, copy

  
try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    pass

  
TREE_CONNECT = {
    'ShareName'       : '',
    'TreeConnectId'   : 0,
    'Session'         : 0,
    'IsDfsShare'      : False,
      
      
    'IsCAShare'       : False,
    'EncryptData'     : False,
    'IsScaleoutShare' : False,
      
    'NumberOfUses'    : 0,
}

FILE = {
    'OpenTable'       : [],
    'LeaseKey'        : '',
    'LeaseState'      : 0,
    'LeaseEpoch'      : 0,
}

OPEN = {
    'FileID'             : '',
    'TreeConnect'        : 0,
    'Connection'         : 0,   
    'Oplocklevel'        : 0,
    'Durable'            : False,
    'FileName'           : '',
    'ResilientHandle'    : False,
    'LastDisconnectTime' : 0,
    'ResilientTimeout'   : 0,
    'OperationBuckets'   : [],
      
      
    'CreateGuid'         : '',
    'IsPersistent'       : False,
    'DesiredAccess'      : '',
    'ShareMode'          : 0,
    'CreateOption'       : '',
    'FileAttributes'     : '',
    'CreateDisposition'  : '',
}

REQUEST = {
    'CancelID'     : '',
    'Message'      : '',
    'Timestamp'    : 0,
}

CHANNEL = {
    'SigningKey' : '',
    'Connection' : 0,
}


class SessionError(Exception):
    def __init__( self, error = 0, packet=0):
        Exception.__init__(self)
        self.error = error
        self.packet = packet

    def get_error_code( self ):
        return self.error

    def get_error_packet( self ):
        return self.packet

    def __str__( self ):
        return 'SMB SessionError: %s(%s)' % (ERROR_MESSAGES[self.error])


class SMB3:
    class HostnameValidationException(Exception):
        pass

    def __init__(self, remote_name, remote_host, my_name=None, host_type=nmb.TYPE_SERVER, sess_port=445, timeout=60,
                 UDP=0, preferredDialect=None, session=None, negSessionResponse=None):

          
        self.RequireMessageSigning = False      
        self.ConnectionTable = {}
        self.GlobalFileTable = {}
        self.ClientGuid = ''.join([random.choice(string.ascii_letters) for i in range(16)])
          
        self.EncryptionAlgorithmList = ['AES-CCM']
        self.MaxDialect = []
        self.RequireSecureNegotiate = False

          
        self._Connection = {
              
              
              
            'OutstandingRequests'      : {},
            'OutstandingResponses'     : {},      
            'SequenceWindow'           : 0,       
            'GSSNegotiateToken'        : '',      
            'MaxTransactSize'          : 0,       
            'MaxReadSize'              : 0,       
            'MaxWriteSize'             : 0,       
            'ServerGuid'               : '',      
            'RequireSigning'           : False,   
            'ServerName'               : '',      
              
              
            'Dialect'                  : 0,      
            'SupportsFileLeasing'      : False,   
            'SupportsMultiCredit'      : False,   
              
              
            'SupportsDirectoryLeasing' : False,   
            'SupportsMultiChannel'     : False,   
            'SupportsPersistentHandles': False,   
            'SupportsEncryption'       : False,   
            'ClientCapabilities'       : 0,
            'ServerCapabilities'       : 0,      
            'ClientSecurityMode'       : 0,      
            'ServerSecurityMode'       : 0,      
              
            'ServerIP'                 : '',      
            'ClientName'               : '',      
              
            'GSSoptions'               : {},
            'PreauthIntegrityHashValue': a2b_hex(b'0'*128)
        }

        self._Session = {
            'SessionID'                : 0,     
            'TreeConnectTable'         : {},      
            'SessionKey'               : b'',      
            'SigningRequired'          : False,   
            'Connection'               : 0,       
            'UserCredentials'          : '',      
            'OpenTable'                : {},      
              
              
            'ChannelList'              : [],
            'ChannelSequence'          : 0,
              
            'EncryptData'              : True,
            'EncryptionKey'            : '',
            'DecryptionKey'            : '',
            'SigningKey'               : '',
            'ApplicationKey'           : b'',
              
            'SessionFlags'             : 0,       
            'ServerName'               : '',      
            'ServerDomain'             : '',      
            'ServerDNSDomainName'      : '',      
            'ServerDNSHostName'        : '',      
            'ServerOS'                 : '',      
            'SigningActivated'         : False,   
            'PreauthIntegrityHashValue': a2b_hex(b'0'*128),
            'CalculatePreAuthHash'     : True,
        }

        self.SMB_PACKET = SMB2Packet

        self._timeout = timeout
        self._Connection['ServerIP'] = remote_host
        self._NetBIOSSession = None
        self._preferredDialect = preferredDialect
        self._doKerberos = False

          
        self._strict_hostname_validation = False
        self._validation_allow_absent = True
        self._accepted_hostname = ''

        self.__userName = ''
        self.__password = ''
        self.__domain   = ''
        self.__lmhash   = ''
        self.__nthash   = ''
        self.__kdc      = ''
        self.__aesKey   = ''
        self.__TGT      = None
        self.__TGS      = None

        if sess_port == 445 and remote_name == '*SMBSERVER':
           self._Connection['ServerName'] = remote_host
        else:
           self._Connection['ServerName'] = remote_name

          
        if my_name is None:
            self._Connection['ClientName'] = ''
        else:
            self._Connection['ClientName'] = my_name

        if session is None:
            if not my_name:
                  
                my_name = socket.gethostname()
                i = my_name.find('.')
                if i > -1:
                    my_name = my_name[:i]

            if UDP:
                self._NetBIOSSession = nmb.NetBIOSUDPSession(my_name, self._Connection['ServerName'], remote_host, host_type, sess_port, self._timeout)
            else:
                self._NetBIOSSession = nmb.NetBIOSTCPSession(my_name, self._Connection['ServerName'], remote_host, host_type, sess_port, self._timeout)

                self.negotiateSession(preferredDialect)
        else:
            self._NetBIOSSession = session
              
            self._Connection['SequenceWindow'] += 1
              
            self.negotiateSession(preferredDialect, negSessionResponse)

    def printStatus(self):
        print("CONNECTION")
        for i in list(self._Connection.items()):
            print("%-40s : %s" % i)
        print()
        print("SESSION")
        for i in list(self._Session.items()):
            print("%-40s : %s" % i)

    def __UpdateConnectionPreAuthHash(self, data):
        from Cryptodome.Hash import SHA512
        calculatedHash =  SHA512.new()
        calculatedHash.update(self._Connection['PreauthIntegrityHashValue'])
        calculatedHash.update(data)
        self._Connection['PreauthIntegrityHashValue'] = calculatedHash.digest()

    def __UpdatePreAuthHash(self, data):
        from Cryptodome.Hash import SHA512
        calculatedHash =  SHA512.new()
        calculatedHash.update(self._Session['PreauthIntegrityHashValue'])
        calculatedHash.update(data)
        self._Session['PreauthIntegrityHashValue'] = calculatedHash.digest()

    def getKerberos(self):
        return self._doKerberos

    def getServerName(self):
        return self._Session['ServerName']

    def getClientName(self):
        return self._Session['ClientName']

    def getRemoteName(self):
        if self._Session['ServerName'] == '':
            return self._Connection['ServerName']
        return self._Session['ServerName']

    def setRemoteName(self, name):
        self._Session['ServerName'] = name
        return True

    def getServerIP(self):
        return self._Connection['ServerIP']

    def getServerDomain(self):
        return self._Session['ServerDomain']

    def getServerDNSDomainName(self):
        return self._Session['ServerDNSDomainName']

    def getServerDNSHostName(self):
        return self._Session['ServerDNSHostName']

    def getServerOS(self):
        return self._Session['ServerOS']

    def getServerOSMajor(self):
        return self._Session['ServerOSMajor']

    def getServerOSMinor(self):
        return self._Session['ServerOSMinor']

    def getServerOSBuild(self):
        return self._Session['ServerOSBuild']

    def isGuestSession(self):
        return self._Session['SessionFlags'] & SMB2_SESSION_FLAG_IS_GUEST

    def setTimeout(self, timeout):
        self._timeout = timeout

    @contextmanager
    def useTimeout(self, timeout):
        prev_timeout = self.getTimeout(timeout)
        try:
            yield
        finally:
            self.setTimeout(prev_timeout)

    def getDialect(self):
        return self._Connection['Dialect']

    def signSMB(self, packet):
        packet['Signature'] = '\x00'*16
        if self._Connection['Dialect'] == SMB2_DIALECT_21 or self._Connection['Dialect'] == SMB2_DIALECT_002:
            if len(self._Session['SessionKey']) > 0:
                signature = hmac.new(self._Session['SessionKey'], packet.getData(), hashlib.sha256).digest()
                packet['Signature'] = signature[:16]
        else:
            if len(self._Session['SessionKey']) > 0:
                p = packet.getData()
                signature = crypto.AES_CMAC(self._Session['SigningKey'], p, len(p))
                packet['Signature'] = signature

    def sendSMB(self, packet):
          
          

          
          
          

          
        if packet['Command'] is not SMB2_CANCEL:
            packet['MessageID'] = self._Connection['SequenceWindow']
            self._Connection['SequenceWindow'] += 1
        packet['SessionID'] = self._Session['SessionID']

          
        if ('CreditCharge' in packet.fields) is False:
            packet['CreditCharge'] = 1

          
        if self._Connection['SequenceWindow'] > 3:
            packet['CreditRequestResponse'] = 127

        messageId = packet['MessageID']

        if self._Session['SigningActivated'] is True and self._Connection['SequenceWindow'] > 2:
            if packet['TreeID'] > 0 and (packet['TreeID'] in self._Session['TreeConnectTable']) is True:
                if self._Session['TreeConnectTable'][packet['TreeID']]['EncryptData'] is False:
                    packet['Flags'] = SMB2_FLAGS_SIGNED
                    self.signSMB(packet)
            elif packet['TreeID'] == 0:
                packet['Flags'] = SMB2_FLAGS_SIGNED
                self.signSMB(packet)

        if packet['Command'] is SMB2_NEGOTIATE:
            data = packet.getData()
            self.__UpdateConnectionPreAuthHash(data)
            self._Session['CalculatePreAuthHash'] = False

        if packet['Command'] is SMB2_SESSION_SETUP:
            self._Session['CalculatePreAuthHash'] = True

        if (self._Session['SessionFlags'] & SMB2_SESSION_FLAG_ENCRYPT_DATA) or ( packet['TreeID'] != 0 and self._Session['TreeConnectTable'][packet['TreeID']]['EncryptData'] is True):
            plainText = packet.getData()
            transformHeader = SMB2_TRANSFORM_HEADER()
            transformHeader['Nonce'] = ''.join([rand.choice(string.ascii_letters) for _ in range(11)])
            transformHeader['OriginalMessageSize'] = len(plainText)
            transformHeader['EncryptionAlgorithm'] = SMB2_ENCRYPTION_AES128_CCM
            transformHeader['SessionID'] = self._Session['SessionID']
            cipher = AES.new(self._Session['EncryptionKey'], AES.MODE_CCM,  b(transformHeader['Nonce']))
            cipher.update(transformHeader.getData()[20:])
            cipherText = cipher.encrypt(plainText)
            transformHeader['Signature'] = cipher.digest()
            packet = transformHeader.getData() + cipherText

            self._NetBIOSSession.send_packet(packet)
        else:
            data = packet.getData()
            if self._Session['CalculatePreAuthHash'] is True:
                self.__UpdatePreAuthHash(data)

            self._NetBIOSSession.send_packet(data)

        return messageId

    def recvSMB(self, packetID = None):
          
        if packetID in self._Connection['OutstandingResponses']:
            return self._Connection['OutstandingResponses'].pop(packetID)

        data = self._NetBIOSSession.recv_packet(self._timeout)

        if data.get_trailer().startswith(b'\xfdSMB'):
              
            transformHeader = SMB2_TRANSFORM_HEADER(data.get_trailer())
            cipher = AES.new(self._Session['DecryptionKey'], AES.MODE_CCM,  transformHeader['Nonce'][:11])
            cipher.update(transformHeader.getData()[20:])
            plainText = cipher.decrypt(data.get_trailer()[len(SMB2_TRANSFORM_HEADER()):])
              
            packet = SMB2Packet(plainText)
        else:
              
              
              
            packet = SMB2Packet(data.get_trailer())

          
        if packet['Status'] == STATUS_PENDING:
            status = STATUS_PENDING
            while status == STATUS_PENDING:
                data = self._NetBIOSSession.recv_packet(self._timeout)
                if data.get_trailer().startswith(b'\xfeSMB'):
                    packet = SMB2Packet(data.get_trailer())
                else:
                      
                    transformHeader = SMB2_TRANSFORM_HEADER(data.get_trailer())
                    cipher = AES.new(self._Session['DecryptionKey'], AES.MODE_CCM,  transformHeader['Nonce'][:11])
                    cipher.update(transformHeader.getData()[20:])
                    plainText = cipher.decrypt(data.get_trailer()[len(SMB2_TRANSFORM_HEADER()):])
                      
                    packet = SMB2Packet(plainText)
                status = packet['Status']

        if packet['MessageID'] == packetID or packetID is None:
              
              
              
              
            if self._Connection['Dialect'] > SMB2_DIALECT_002:
                self._Connection['SequenceWindow'] += (packet['CreditCharge'] - 1)
            return packet
        else:
            self._Connection['OutstandingResponses'][packet['MessageID']] = packet
            return self.recvSMB(packetID)

    def negotiateSession(self, preferredDialect = None, negSessionResponse = None):
          
        self._Connection['ClientSecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED
        if self.RequireMessageSigning is True:
            self._Connection['ClientSecurityMode'] |= SMB2_NEGOTIATE_SIGNING_REQUIRED
        self._Connection['Capabilities'] = SMB2_GLOBAL_CAP_ENCRYPTION
        currentDialect = SMB2_DIALECT_WILDCARD

          
        if negSessionResponse is not None:
              
            negResp = SMB2Negotiate_Response(negSessionResponse['Data'])
            currentDialect = negResp['DialectRevision']

        if currentDialect == SMB2_DIALECT_WILDCARD:
              

            packet = self.SMB_PACKET()
            packet['Command'] = SMB2_NEGOTIATE
            negSession = SMB2Negotiate()

            negSession['SecurityMode'] = self._Connection['ClientSecurityMode']
            negSession['Capabilities'] = self._Connection['Capabilities']
            negSession['ClientGuid'] = self.ClientGuid
            if preferredDialect is not None:
                negSession['Dialects'] = [preferredDialect]
                if preferredDialect == SMB2_DIALECT_311:
                      
                    contextData = SMB311ContextData()
                    contextData['NegotiateContextOffset'] = 64+38+2
                    contextData['NegotiateContextCount'] = 0
                      
                      
                    negotiateContext = SMB2NegotiateContext()
                    negotiateContext['ContextType'] = SMB2_PREAUTH_INTEGRITY_CAPABILITIES

                    preAuthIntegrityCapabilities = SMB2PreAuthIntegrityCapabilities()
                    preAuthIntegrityCapabilities['HashAlgorithmCount'] = 1
                    preAuthIntegrityCapabilities['SaltLength'] = 32
                    preAuthIntegrityCapabilities['HashAlgorithms'] = b'\x01\x00'
                    preAuthIntegrityCapabilities['Salt'] = ''.join([rand.choice(string.ascii_letters) for _ in
                                                                     range(preAuthIntegrityCapabilities['SaltLength'])])

                    negotiateContext['Data'] = preAuthIntegrityCapabilities.getData()
                    negotiateContext['DataLength'] = len(negotiateContext['Data'])
                    contextData['NegotiateContextCount'] += 1
                    pad = b'\xFF' * ((8 - (negotiateContext['DataLength'] % 8)) % 8)

                      
                      
                      

                    negotiateContext2 = SMB2NegotiateContext ()
                    negotiateContext2['ContextType'] = SMB2_ENCRYPTION_CAPABILITIES

                    encryptionCapabilities = SMB2EncryptionCapabilities()
                    encryptionCapabilities['CipherCount'] = 1
                    encryptionCapabilities['Ciphers'] = 1

                    negotiateContext2['Data'] = encryptionCapabilities.getData()
                    negotiateContext2['DataLength'] = len(negotiateContext2['Data'])
                    contextData['NegotiateContextCount'] += 1

                    negSession['ClientStartTime'] = contextData.getData()
                    negSession['Padding'] = b'\xFF\xFF'
                      
                      
                    negSession['NegotiateContextList'] = negotiateContext.getData() + pad + negotiateContext2.getData()

                      
                      

            else:
                negSession['Dialects'] = [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]
            negSession['DialectCount'] = len(negSession['Dialects'])
            packet['Data'] = negSession

            packetID = self.sendSMB(packet)
            ans = self.recvSMB(packetID)
            if ans.isValidAnswer(STATUS_SUCCESS):
                negResp = SMB2Negotiate_Response(ans['Data'])
                if negResp['DialectRevision']  == SMB2_DIALECT_311:
                    self.__UpdateConnectionPreAuthHash(ans.rawData)

        self._Connection['MaxTransactSize']   = min(0x100000,negResp['MaxTransactSize'])
        self._Connection['MaxReadSize']       = min(0x100000,negResp['MaxReadSize'])
        self._Connection['MaxWriteSize']      = min(0x100000,negResp['MaxWriteSize'])
        self._Connection['ServerGuid']        = negResp['ServerGuid']
        self._Connection['GSSNegotiateToken'] = negResp['Buffer']
        self._Connection['Dialect']           = negResp['DialectRevision']
        if (negResp['SecurityMode'] & SMB2_NEGOTIATE_SIGNING_REQUIRED) == SMB2_NEGOTIATE_SIGNING_REQUIRED or \
                self._Connection['Dialect'] == SMB2_DIALECT_311:
            self._Connection['RequireSigning'] = True
        if self._Connection['Dialect'] == SMB2_DIALECT_311:
              
            self._Connection['RequireSigning'] = True

        if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LEASING) == SMB2_GLOBAL_CAP_LEASING:
            self._Connection['SupportsFileLeasing'] = True
        if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_LARGE_MTU) == SMB2_GLOBAL_CAP_LARGE_MTU:
            self._Connection['SupportsMultiCredit'] = True

        if self._Connection['Dialect'] >= SMB2_DIALECT_30:
              
            self.SMB_PACKET = SMB3Packet
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_DIRECTORY_LEASING) == SMB2_GLOBAL_CAP_DIRECTORY_LEASING:
                self._Connection['SupportsDirectoryLeasing'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_MULTI_CHANNEL) == SMB2_GLOBAL_CAP_MULTI_CHANNEL:
                self._Connection['SupportsMultiChannel'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_PERSISTENT_HANDLES) == SMB2_GLOBAL_CAP_PERSISTENT_HANDLES:
                self._Connection['SupportsPersistentHandles'] = True
            if (negResp['Capabilities'] & SMB2_GLOBAL_CAP_ENCRYPTION) == SMB2_GLOBAL_CAP_ENCRYPTION:
                self._Connection['SupportsEncryption'] = True

            self._Connection['ServerCapabilities'] = negResp['Capabilities']
            self._Connection['ServerSecurityMode'] = negResp['SecurityMode']

    def getCredentials(self):
        return (
            self.__userName,
            self.__password,
            self.__domain,
            self.__lmhash,
            self.__nthash,
            self.__aesKey,
            self.__TGT,
            self.__TGS)

    def kerberosLogin(self, user, password, domain = '', lmhash = '', nthash = '', aesKey='', kdcHost = '', TGT=None, TGS=None, mutualAuth=False):
          
          
          
          
          
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            try:   
                lmhash = a2b_hex(lmhash)
                nthash = a2b_hex(nthash)
            except:
                pass

        self.__userName = user
        self.__password = password
        self.__domain   = domain
        self.__lmhash   = lmhash
        self.__nthash   = nthash
        self.__kdc      = kdcHost
        self.__aesKey   = aesKey
        self.__TGT      = TGT
        self.__TGS      = TGS
        self._doKerberos= True

        sessionSetup = SMB2SessionSetup()
        if self.RequireMessageSigning is True:
           sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_REQUIRED
        else:
           sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED

        sessionSetup['Flags'] = 0
          

          
        from libs.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from libs.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from libs.krb5 import constants
        from libs.krb5.types import Principal, KerberosTime, Ticket
        from pyasn1.codec.der import decoder, encoder
        import datetime

          
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

          
          
  
  
  
  
  
  
  
  
  
  
  

          

        if TGS is None:
            serverName = Principal('cifs/%s' % (self._Connection['ServerName']), type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
        else:
            tgs = TGS['KDC_REP']
            cipher = TGS['cipher']
            sessionKey = TGS['sessionKey']

          

        blob = SPNEGO_NegTokenInit()

          
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

          
        tgs = decoder.decode(tgs, asn1Spec = TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

          
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

          
        opts = list()

        if mutualAuth == True:
            from libs.krb5.constants import APOptions
            opts.append(constants.APOptions.mutual_required.value)

        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq,'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = domain
        seq_set(authenticator, 'cname', userName.components_to_asn1)
        now = datetime.datetime.utcnow()

        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        encodedAuthenticator = encoder.encode(authenticator)

          
          
          
          
        encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

        blob['MechToken'] = struct.pack('B', ASN1_AID) + asn1encode( struct.pack('B', ASN1_OID) + asn1encode(
            TypesMech['KRB5 - Kerberos 5'] ) + KRB5_AP_REQ + encoder.encode(apReq))

        sessionSetup['SecurityBufferLength'] = len(blob)
        sessionSetup['Buffer']               = blob.getData()

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup

          
        self._Session['PreauthIntegrityHashValue'] = self._Connection['PreauthIntegrityHashValue']

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
            self._Session['SessionID']       = ans['SessionID']
            self._Session['SigningRequired'] = self._Connection['RequireSigning']
            self._Session['UserCredentials'] = (user, password, domain, lmhash, nthash)
            self._Session['Connection']      = self._NetBIOSSession.get_socket()


            if mutualAuth == True:
                  
                from libs.krb5.asn1 import AP_REP, EncAPRepPart
                from libs.krb5.crypto import Key, _enctype_table
                smbSessSetupResp = SMB2SessionSetup_Response(ans['Data'])

                  
                  
                  
                  
                  
                  
                  
                  
                negTokenResp = SPNEGO_NegTokenResp(smbSessSetupResp['Buffer'])

                  
                ap_rep = decoder.decode(negTokenResp['ResponseToken'][16:], asn1Spec=AP_REP())[0]

                if cipher.enctype != ap_rep['enc-part']['etype']:
                    raise Exception('Unable to decrypt AP_REP: cipher does not match TGS session key')

                  
                  
                  
                  
                cipherText = ap_rep['enc-part']['cipher']
                plainText = cipher.decrypt(sessionKey, 12, cipherText)

                encAPRepPart = decoder.decode(plainText, asn1Spec = EncAPRepPart())[0]

                apCipher = _enctype_table[int(encAPRepPart['subkey']['keytype'])]()
                apSessionKey = Key(apCipher.enctype, encAPRepPart['subkey']['keyvalue'].asOctets())

                sequenceNumber = int(encAPRepPart['seq-number'])
                self._Session['SessionKey'] = apSessionKey.contents

            else:
                self._Session['SessionKey']  = sessionKey.contents[:16]

            if self._Session['SigningRequired'] is True and self._Connection['Dialect'] >= SMB2_DIALECT_30:
                  
                  
                  
                  
                if self._Connection['Dialect'] == SMB2_DIALECT_311:
                    self._Session['SigningKey'] = crypto.KDF_CounterMode (self._Session['SessionKey'], b"SMBSigningKey\x00",
                                                                          self._Session['PreauthIntegrityHashValue'], 128)
                else:
                    self._Session['SigningKey'] = crypto.KDF_CounterMode (self._Session['SessionKey'], b"SMB2AESCMAC\x00",
                                                                          b"SmbSign\x00", 128)

              
            if user == '' or self.isGuestSession():
                self._Connection['SupportsEncryption'] = False

            if self._Session['SigningRequired'] is True:
                self._Session['SigningActivated'] = True
            if self._Connection['Dialect'] >= SMB2_DIALECT_30 and self._Connection['SupportsEncryption'] is True:
                  
                self._Session['SessionFlags'] |= SMB2_SESSION_FLAG_ENCRYPT_DATA
                  
                  
                  
                  
                  
                  
                  
                  
                  
                  
                  
                  
                  
                if self._Connection['Dialect'] == SMB2_DIALECT_311:
                    self._Session['ApplicationKey'] = crypto.KDF_CounterMode (self._Session['SessionKey'], b"SMBAppKey\x00",
                                                                              self._Session['PreauthIntegrityHashValue'], 128)
                    self._Session['EncryptionKey'] = crypto.KDF_CounterMode (self._Session['SessionKey'], b"SMBC2SCipherKey\x00",
                                                                             self._Session['PreauthIntegrityHashValue'], 128)
                    self._Session['DecryptionKey'] = crypto.KDF_CounterMode (self._Session['SessionKey'], b"SMBS2CCipherKey\x00",
                                                                             self._Session['PreauthIntegrityHashValue'], 128)
                else:
                    self._Session['ApplicationKey'] = crypto.KDF_CounterMode (self._Session['SessionKey'], b"SMB2APP\x00",
                                                                              b"SmbRpc\x00", 128)
                    self._Session['EncryptionKey'] = crypto.KDF_CounterMode (self._Session['SessionKey'], b"SMB2AESCCM\x00",
                                                                             b"ServerIn \x00", 128)
                    self._Session['DecryptionKey'] = crypto.KDF_CounterMode (self._Session['SessionKey'], b"SMB2AESCCM\x00",
                                                                             b"ServerOut\x00", 128)

            self._Session['CalculatePreAuthHash'] = False
            return True
        else:
              
              
            self._Session['UserCredentials']   = ''
            self._Session['Connection']        = 0
            self._Session['SessionID']         = 0
            self._Session['SigningRequired']   = False
            self._Session['SigningKey']        = ''
            self._Session['SessionKey']        = ''
            self._Session['SigningActivated']  = False
            self._Session['CalculatePreAuthHash'] = False
            self._Session['PreauthIntegrityHashValue'] = a2b_hex(b'0'*128)
            raise Exception('Unsuccessful Login')


    def login(self, user, password, domain = '', lmhash = '', nthash = ''):
          
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:     lmhash = '0%s' % lmhash
            if len(nthash) % 2:     nthash = '0%s' % nthash
            try:   
                lmhash = a2b_hex(lmhash)
                nthash = a2b_hex(nthash)
            except:
                pass

        self.__userName = user
        self.__password = password
        self.__domain   = domain
        self.__lmhash   = lmhash
        self.__nthash   = nthash
        self.__aesKey   = ''
        self.__TGT      = None
        self.__TGS      = None

        sessionSetup = SMB2SessionSetup()
        if self.RequireMessageSigning is True:
           sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_REQUIRED
        else:
           sessionSetup['SecurityMode'] = SMB2_NEGOTIATE_SIGNING_ENABLED

        sessionSetup['Flags'] = 0
          

          
          

        blob = SPNEGO_NegTokenInit()

          
        blob['MechTypes'] = [TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = ntlm.getNTLMSSPType1(self._Connection['ClientName'],domain, self._Connection['RequireSigning'])
        blob['MechToken'] = auth.getData()

        sessionSetup['SecurityBufferLength'] = len(blob)
        sessionSetup['Buffer']               = blob.getData()

          
          
          
          
          
          
          

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_SESSION_SETUP
        packet['Data']    = sessionSetup

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if self._Connection['Dialect'] == SMB2_DIALECT_311:
            self.__UpdatePreAuthHash (ans.rawData)

        if ans.isValidAnswer(STATUS_MORE_PROCESSING_REQUIRED):
            self._Session['SessionID']       = ans['SessionID']
            self._Session['SigningRequired'] = self._Connection['RequireSigning']
            self._Session['UserCredentials'] = (user, password, domain, lmhash, nthash)
            self._Session['Connection']      = self._NetBIOSSession.get_socket()
            sessionSetupResponse = SMB2SessionSetup_Response(ans['Data'])
            respToken = SPNEGO_NegTokenResp(sessionSetupResponse['Buffer'])

              
            ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
            if ntlmChallenge['TargetInfoFields_len'] > 0:
                av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                   try:
                       self._Session['ServerName'] = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                   except:
                         
                       pass
                if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                   try:
                       if self._Session['ServerName'] != av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le'):
                           self._Session['ServerDomain'] = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')
                   except:
                         
                       pass
                if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
                   try:
                       self._Session['ServerDNSDomainName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode('utf-16le')
                   except:
                         
                       pass

                if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
                   try:
                       self._Session['ServerDNSHostName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode('utf-16le')
                   except:
                         
                       pass

                if self._strict_hostname_validation:
                    self.perform_hostname_validation()

                  
                if 'Version' in ntlmChallenge.fields:
                    version = ntlmChallenge['Version']

                    if len(version) >= 4:
                        self._Session['ServerOS'] = "Windows %d.%d Build %d" % (indexbytes(version,0), indexbytes(version,1), struct.unpack('<H',version[2:4])[0])
                        self._Session["ServerOSMajor"] = indexbytes(version,0)
                        self._Session["ServerOSMinor"] = indexbytes(version,1)
                        self._Session["ServerOSBuild"] = struct.unpack('<H',version[2:4])[0]

            type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, respToken['ResponseToken'], user, password, domain, lmhash, nthash)



            respToken2 = SPNEGO_NegTokenResp()
            respToken2['ResponseToken'] = type3.getData()

              
            sessionSetup['SecurityBufferLength'] = len(respToken2)
            sessionSetup['Buffer']               = respToken2.getData()

            packetID = self.sendSMB(packet)
            packet = self.recvSMB(packetID)

              
            if exportedSessionKey is not None:
                self._Session['SessionKey']  = exportedSessionKey
                if self._Session['SigningRequired'] is True and self._Connection['Dialect'] >= SMB2_DIALECT_30:
                      
                      
                      
                      
                    if self._Connection['Dialect'] == SMB2_DIALECT_311:
                        self._Session['SigningKey'] = crypto.KDF_CounterMode (exportedSessionKey,
                                                                              b"SMBSigningKey\x00",
                                                                              self._Session['PreauthIntegrityHashValue'],
                                                                              128)
                    else:
                        self._Session['SigningKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMB2AESCMAC\x00",
                                                                              b"SmbSign\x00", 128)
            try:
                if packet.isValidAnswer(STATUS_SUCCESS):
                    sessionSetupResponse = SMB2SessionSetup_Response(packet['Data'])
                    self._Session['SessionFlags'] = sessionSetupResponse['SessionFlags']
                    self._Session['SessionID']    = packet['SessionID']

                      
                    if user == '' or self.isGuestSession():
                        self._Connection['SupportsEncryption'] = False

                      
                    if self._Session['SigningRequired'] is True:
                        self._Session['SigningActivated'] = True
                    if self._Connection['Dialect'] >= SMB2_DIALECT_30 and self._Connection['SupportsEncryption'] is True:
                          
                        self._Session['SessionFlags'] |= SMB2_SESSION_FLAG_ENCRYPT_DATA
                          
                          
                          
                          
                          
                          
                          
                          
                          
                          
                          
                          
                          
                        if self._Connection['Dialect'] == SMB2_DIALECT_311:
                            self._Session['ApplicationKey']  = crypto.KDF_CounterMode(exportedSessionKey, b"SMBAppKey\x00",
                                                                             self._Session['PreauthIntegrityHashValue'], 128)
                            self._Session['EncryptionKey']   = crypto.KDF_CounterMode(exportedSessionKey, b"SMBC2SCipherKey\x00",
                                                                             self._Session['PreauthIntegrityHashValue'], 128)
                            self._Session['DecryptionKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMBS2CCipherKey\x00",
                                                                             self._Session['PreauthIntegrityHashValue'], 128)

                        else:
                            self._Session['ApplicationKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMB2APP\x00",
                                                                                      b"SmbRpc\x00", 128)
                            self._Session['EncryptionKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMB2AESCCM\x00",
                                                                                     b"ServerIn \x00", 128)
                            self._Session['DecryptionKey'] = crypto.KDF_CounterMode (exportedSessionKey, b"SMB2AESCCM\x00",
                                                                                     b"ServerOut\x00", 128)
                    self._Session['CalculatePreAuthHash'] = False
                    return True
            except:
                  
                  
                self._Session['UserCredentials']   = ''
                self._Session['Connection']        = 0
                self._Session['SessionID']         = 0
                self._Session['SigningRequired']   = False
                self._Session['SigningKey']        = ''
                self._Session['SessionKey']        = ''
                self._Session['SigningActivated']  = False
                self._Session['CalculatePreAuthHash'] = False
                self._Session['PreauthIntegrityHashValue'] = a2b_hex(b'0'*128)
                raise

    def connectTree(self, share):

          
          

          
        share = share.split('\\')[-1]
        if share in self._Session['TreeConnectTable']:
              
            treeEntry =  self._Session['TreeConnectTable'][share]
            treeEntry['NumberOfUses'] += 1
            self._Session['TreeConnectTable'][treeEntry['TreeConnectId']]['NumberOfUses'] += 1
            return treeEntry['TreeConnectId']

          
        try:
            _, _, _, _, sockaddr = socket.getaddrinfo(self._Connection['ServerIP'], 80, 0, 0, socket.IPPROTO_TCP)[0]
            remoteHost = sockaddr[0]
        except:
            remoteHost = self._Connection['ServerIP']
        path = '\\\\' + remoteHost + '\\' +share

        treeConnect = SMB2TreeConnect()
        treeConnect['Buffer']     = path.encode('utf-16le')
        treeConnect['PathLength'] = len(path)*2

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_TREE_CONNECT
        packet['Data'] = treeConnect
        packetID = self.sendSMB(packet)
        packet = self.recvSMB(packetID)
        if packet.isValidAnswer(STATUS_SUCCESS):
           treeConnectResponse = SMB2TreeConnect_Response(packet['Data'])
           treeEntry = copy.deepcopy(TREE_CONNECT)
           treeEntry['ShareName']     = share
           treeEntry['TreeConnectId'] = packet['TreeID']
           treeEntry['Session']       = packet['SessionID']
           treeEntry['NumberOfUses'] += 1
           if (treeConnectResponse['Capabilities'] & SMB2_SHARE_CAP_DFS) == SMB2_SHARE_CAP_DFS:
               treeEntry['IsDfsShare'] = True
           if (treeConnectResponse['Capabilities'] & SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY) == SMB2_SHARE_CAP_CONTINUOUS_AVAILABILITY:
               treeEntry['IsCAShare'] = True

           if self._Connection['Dialect'] >= SMB2_DIALECT_30:
               if (self._Connection['SupportsEncryption'] is True) and ((treeConnectResponse['ShareFlags'] & SMB2_SHAREFLAG_ENCRYPT_DATA) == SMB2_SHAREFLAG_ENCRYPT_DATA):
                   treeEntry['EncryptData'] = True
                     
                     
                     
                     
               if (treeConnectResponse['Capabilities'] & SMB2_SHARE_CAP_SCALEOUT) == SMB2_SHARE_CAP_SCALEOUT:
                   treeEntry['IsScaleoutShare'] = True

           self._Session['TreeConnectTable'][packet['TreeID']] = treeEntry
           self._Session['TreeConnectTable'][share]            = treeEntry

           return packet['TreeID']

    def disconnectTree(self, treeId):
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        if treeId in self._Session['TreeConnectTable']:
              
            if self._Session['TreeConnectTable'][treeId]['NumberOfUses'] > 1:
                treeEntry =  self._Session['TreeConnectTable'][treeId]
                treeEntry['NumberOfUses'] -= 1
                self._Session['TreeConnectTable'][treeEntry['ShareName']]['NumberOfUses'] -= 1
                return True

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_TREE_DISCONNECT
        packet['TreeID'] = treeId
        treeDisconnect = SMB2TreeDisconnect()
        packet['Data'] = treeDisconnect
        packetID = self.sendSMB(packet)
        packet = self.recvSMB(packetID)
        if packet.isValidAnswer(STATUS_SUCCESS):
            shareName = self._Session['TreeConnectTable'][treeId]['ShareName']
            del(self._Session['TreeConnectTable'][shareName])
            del(self._Session['TreeConnectTable'][treeId])
            filesIDToBeRemoved = []
            for fileID in list(self._Session['OpenTable'].keys()):
                if self._Session['OpenTable'][fileID]['TreeConnect'] == treeId:
                    filesIDToBeRemoved.append(fileID)
            for fileIDToBeRemoved in filesIDToBeRemoved:
                del(self._Session['OpenTable'][fileIDToBeRemoved])
            return True

    def create(self, treeId, fileName, desiredAccess, shareMode, creationOptions, creationDisposition, fileAttributes, impersonationLevel = SMB2_IL_IMPERSONATION, securityFlags = 0, oplockLevel = SMB2_OPLOCK_LEVEL_NONE, createContexts = None):
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        fileName = fileName.replace('/', '\\')
        if len(fileName) > 0:
            fileName = ntpath.normpath(fileName)
            if fileName[0] == '\\':
                fileName = fileName[1:]

        if self._Session['TreeConnectTable'][treeId]['IsDfsShare'] is True:
            pathName = fileName
        else:
            pathName = '\\\\' + self._Connection['ServerName'] + '\\' + fileName

        fileEntry = copy.deepcopy(FILE)
        fileEntry['LeaseKey']   = uuid.generate()
        fileEntry['LeaseState'] = SMB2_LEASE_NONE
        self.GlobalFileTable[pathName] = fileEntry

        if self._Connection['Dialect'] >= SMB2_DIALECT_30 and self._Connection['SupportsDirectoryLeasing'] is True:
             
           if len(fileName.split('\\')) > 2:
               parentDir = ntpath.dirname(pathName)
           if parentDir in self.GlobalFileTable:
               raise Exception("Don't know what to do now! :-o")
           else:
               parentEntry = copy.deepcopy(FILE)
               parentEntry['LeaseKey']   = uuid.generate()
               parentEntry['LeaseState'] = SMB2_LEASE_NONE
               self.GlobalFileTable[parentDir] = parentEntry

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_CREATE
        packet['TreeID']  = treeId
        if self._Session['TreeConnectTable'][treeId]['IsDfsShare'] is True:
            packet['Flags'] = SMB2_FLAGS_DFS_OPERATIONS

        smb2Create = SMB2Create()
        smb2Create['SecurityFlags']        = 0
        smb2Create['RequestedOplockLevel'] = oplockLevel
        smb2Create['ImpersonationLevel']   = impersonationLevel
        smb2Create['DesiredAccess']        = desiredAccess
        smb2Create['FileAttributes']       = fileAttributes
        smb2Create['ShareAccess']          = shareMode
        smb2Create['CreateDisposition']    = creationDisposition
        smb2Create['CreateOptions']        = creationOptions

        smb2Create['NameLength']           = len(fileName)*2
        if fileName != '':
            smb2Create['Buffer']           = fileName.encode('utf-16le')
        else:
            smb2Create['Buffer']           = b'\x00'

        if createContexts is not None:
            contextsBuf = b''.join(x.getData() for x in createContexts)
            smb2Create['CreateContextsOffset'] = len(SMB2Packet()) + SMB2Create.SIZE + len(smb2Create['Buffer'])

              
            if (smb2Create['CreateContextsOffset'] % 8):
                smb2Create['Buffer'] += b'\x00'*(8-(smb2Create['CreateContextsOffset'] % 8))
                smb2Create['CreateContextsOffset'] = len(SMB2Packet()) + SMB2Create.SIZE + len(smb2Create['Buffer'])

            smb2Create['CreateContextsLength'] = len(contextsBuf)
            smb2Create['Buffer'] += contextsBuf
        else:
            smb2Create['CreateContextsOffset'] = 0
            smb2Create['CreateContextsLength'] = 0

        packet['Data'] = smb2Create

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
            createResponse = SMB2Create_Response(ans['Data'])

            openFile = copy.deepcopy(OPEN)
            openFile['FileID']      = createResponse['FileID']
            openFile['TreeConnect'] = treeId
            openFile['Oplocklevel'] = oplockLevel
            openFile['Durable']     = False
            openFile['ResilientHandle']    = False
            openFile['LastDisconnectTime'] = 0
            openFile['FileName'] = pathName

              
            if self._Connection['Dialect'] >= SMB2_DIALECT_30:
                openFile['DesiredAccess']     = oplockLevel
                openFile['ShareMode']         = oplockLevel
                openFile['CreateOptions']     = oplockLevel
                openFile['FileAttributes']    = oplockLevel
                openFile['CreateDisposition'] = oplockLevel

              
            self._Session['OpenTable'][createResponse['FileID'].getData()] = openFile

              
              
              
            return createResponse['FileID'].getData()

    def close(self, treeId, fileId):
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if (fileId in self._Session['OpenTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_CLOSE
        packet['TreeID']  = treeId

        smbClose = SMB2Close()
        smbClose['Flags']  = 0
        smbClose['FileID'] = fileId

        packet['Data'] = smbClose

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            del(self.GlobalFileTable[self._Session['OpenTable'][fileId]['FileName']])
            del(self._Session['OpenTable'][fileId])

              
            return True

    def read(self, treeId, fileId, offset = 0, bytesToRead = 0, waitAnswer = True):
          
          
          
          

        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if (fileId in self._Session['OpenTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_READ
        packet['TreeID']  = treeId

        if self._Connection['MaxReadSize'] < bytesToRead:
            maxBytesToRead = self._Connection['MaxReadSize']
        else:
            maxBytesToRead = bytesToRead

        if self._Connection['Dialect'] != SMB2_DIALECT_002 and self._Connection['SupportsMultiCredit'] is True:
            packet['CreditCharge'] = ( 1 + (maxBytesToRead - 1) // 65536)
        else:
            maxBytesToRead = min(65536,bytesToRead)

        smbRead = SMB2Read()
        smbRead['Padding']  = 0x50
        smbRead['FileID']   = fileId
        smbRead['Length']   = maxBytesToRead
        smbRead['Offset']   = offset
        packet['Data'] = smbRead

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            readResponse = SMB2Read_Response(ans['Data'])
            retData = readResponse['Buffer']
            if readResponse['DataRemaining'] > 0:
                retData += self.read(treeId, fileId, offset+len(retData), readResponse['DataRemaining'], waitAnswer)
            return retData

    def write(self, treeId, fileId, data, offset = 0, bytesToWrite = 0, waitAnswer = True):
          
          
          
          

        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if (fileId in self._Session['OpenTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_WRITE
        packet['TreeID']  = treeId

        if self._Connection['MaxWriteSize'] < bytesToWrite:
            maxBytesToWrite = self._Connection['MaxWriteSize']
        else:
            maxBytesToWrite = bytesToWrite

        if self._Connection['Dialect'] != SMB2_DIALECT_002 and self._Connection['SupportsMultiCredit'] is True:
            packet['CreditCharge'] = ( 1 + (maxBytesToWrite - 1) // 65536)
        else:
            maxBytesToWrite = min(65536,bytesToWrite)

        smbWrite = SMB2Write()
        smbWrite['FileID'] = fileId
        smbWrite['Length'] = maxBytesToWrite
        smbWrite['Offset'] = offset
        smbWrite['WriteChannelInfoOffset'] = 0
        smbWrite['Buffer'] = data[:maxBytesToWrite]
        packet['Data'] = smbWrite

        packetID = self.sendSMB(packet)
        if waitAnswer is True:
            ans = self.recvSMB(packetID)
        else:
            return maxBytesToWrite

        if ans.isValidAnswer(STATUS_SUCCESS):
            writeResponse = SMB2Write_Response(ans['Data'])
            bytesWritten = writeResponse['Count']
            if bytesWritten < bytesToWrite:
                bytesWritten += self.write(treeId, fileId, data[bytesWritten:], offset+bytesWritten, bytesToWrite-bytesWritten, waitAnswer)
            return bytesWritten

    def queryDirectory(self, treeId, fileId, searchString = '*', resumeIndex = 0, informationClass = FILENAMES_INFORMATION, maxBufferSize = None, enumRestart = False, singleEntry = False):
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if (fileId in self._Session['OpenTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_QUERY_DIRECTORY
        packet['TreeID']  = treeId

        queryDirectory = SMB2QueryDirectory()
        queryDirectory['FileInformationClass'] = informationClass
        if resumeIndex != 0 :
            queryDirectory['Flags'] = SMB2_INDEX_SPECIFIED
        queryDirectory['FileIndex'] = resumeIndex
        queryDirectory['FileID']    = fileId
        if maxBufferSize is None:
            maxBufferSize = self._Connection['MaxReadSize']
        queryDirectory['OutputBufferLength'] = maxBufferSize
        queryDirectory['FileNameLength']     = len(searchString)*2
        queryDirectory['Buffer']             = searchString.encode('utf-16le')

        packet['Data'] = queryDirectory

        if self._Connection['Dialect'] != SMB2_DIALECT_002 and self._Connection['SupportsMultiCredit'] is True:
            packet['CreditCharge'] = ( 1 + (maxBufferSize - 1) // 65536)

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
            queryDirectoryResponse = SMB2QueryDirectory_Response(ans['Data'])
            return queryDirectoryResponse['Buffer']

    def echo(self):
        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_ECHO
        smbEcho = SMB2Echo()
        packet['Data'] = smbEcho
        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if ans.isValidAnswer(STATUS_SUCCESS):
            return True

    def cancel(self, packetID):
        packet = self.SMB_PACKET()
        packet['Command']   = SMB2_CANCEL
        packet['MessageID'] = packetID

        smbCancel = SMB2Cancel()

        packet['Data']      = smbCancel
        self.sendSMB(packet)

    def ioctl(self, treeId, fileId = None, ctlCode = -1, flags = 0, inputBlob = '',  maxInputResponse = None, maxOutputResponse = None, waitAnswer = 1):
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if fileId is None:
            fileId = '\xff'*16
        else:
            if (fileId in self._Session['OpenTable']) is False:
                raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command']            = SMB2_IOCTL
        packet['TreeID']             = treeId

        smbIoctl = SMB2Ioctl()
        smbIoctl['FileID']             = fileId
        smbIoctl['CtlCode']            = ctlCode
        smbIoctl['MaxInputResponse']   = maxInputResponse
        smbIoctl['MaxOutputResponse']  = maxOutputResponse
        smbIoctl['InputCount']         = len(inputBlob)
        if len(inputBlob) == 0:
            smbIoctl['InputOffset'] = 0
            smbIoctl['Buffer']      = '\x00'
        else:
            smbIoctl['Buffer']             = inputBlob
        smbIoctl['OutputOffset']       = 0
        smbIoctl['MaxOutputResponse']  = maxOutputResponse
        smbIoctl['Flags']              = flags

        packet['Data'] = smbIoctl

        packetID = self.sendSMB(packet)

        if waitAnswer == 0:
            return True

        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            smbIoctlResponse = SMB2Ioctl_Response(ans['Data'])
            return smbIoctlResponse['Buffer']

    def flush(self,treeId, fileId):
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if (fileId in self._Session['OpenTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_FLUSH
        packet['TreeID']  = treeId

        smbFlush = SMB2Flush()
        smbFlush['FileID'] = fileId

        packet['Data'] = smbFlush

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            return True

    def lock(self, treeId, fileId, locks, lockSequence = 0):
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if (fileId in self._Session['OpenTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_LOCK
        packet['TreeID']  = treeId

        smbLock = SMB2Lock()
        smbLock['FileID']       = fileId
        smbLock['LockCount']    = len(locks)
        smbLock['LockSequence'] = lockSequence
        smbLock['Locks']        = ''.join(str(x) for x in locks)

        packet['Data'] = smbLock

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            smbFlushResponse = SMB2Lock_Response(ans['Data'])
            return True

          
          
          
          
          
          
          
          
          
          
          
          
          

    def logoff(self):
        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_LOGOFF

        smbLogoff = SMB2Logoff()

        packet['Data'] = smbLogoff

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
              
              
            self._Session['UserCredentials']   = ''
            self._Session['Connection']        = 0
            self._Session['SessionID']         = 0
            self._Session['SigningRequired']   = False
            self._Session['SigningKey']        = ''
            self._Session['SessionKey']        = ''
            self._Session['SigningActivated']  = False
            return True

    def queryInfo(self, treeId, fileId, inputBlob = '', infoType = SMB2_0_INFO_FILE, fileInfoClass = SMB2_FILE_STANDARD_INFO, additionalInformation = 0, flags = 0 ):
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if (fileId in self._Session['OpenTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_QUERY_INFO
        packet['TreeID']  = treeId

        queryInfo = SMB2QueryInfo()
        queryInfo['FileID']                = fileId
        queryInfo['InfoType']              = infoType
        queryInfo['FileInfoClass']         = fileInfoClass
        queryInfo['OutputBufferLength']    = 65535
        queryInfo['AdditionalInformation'] = additionalInformation
        if len(inputBlob) == 0:
            queryInfo['InputBufferOffset'] = 0
            queryInfo['Buffer']            = '\x00'
        else:
            queryInfo['InputBufferLength'] = len(inputBlob)
            queryInfo['Buffer']            = inputBlob
        queryInfo['Flags']                 = flags

        packet['Data'] = queryInfo
        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            queryResponse = SMB2QueryInfo_Response(ans['Data'])
            return queryResponse['Buffer']

    def setInfo(self, treeId, fileId, inputBlob = '', infoType = SMB2_0_INFO_FILE, fileInfoClass = SMB2_FILE_STANDARD_INFO, additionalInformation = 0 ):
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if (fileId in self._Session['OpenTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)

        packet = self.SMB_PACKET()
        packet['Command'] = SMB2_SET_INFO
        packet['TreeID']  = treeId

        setInfo = SMB2SetInfo()
        setInfo['InfoType']              = infoType
        setInfo['FileInfoClass']         = fileInfoClass
        setInfo['BufferLength']          = len(inputBlob)
        setInfo['AdditionalInformation'] = additionalInformation
        setInfo['FileID']                = fileId
        setInfo['Buffer']                = inputBlob

        packet['Data'] = setInfo
        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)

        if ans.isValidAnswer(STATUS_SUCCESS):
            return True

    def getSessionKey(self):
        if self.getDialect() >= SMB2_DIALECT_30:
           return self._Session['ApplicationKey']
        else:
           return self._Session['SessionKey']

    def setSessionKey(self, key):
        if self.getDialect() >= SMB2_DIALECT_30:
           self._Session['ApplicationKey'] = key
        else:
           self._Session['SessionKey'] = key

      
      

    def rename(self, shareName, oldPath, newPath):
        oldPath = oldPath.replace('/', '\\')
        oldPath = ntpath.normpath(oldPath)
        if len(oldPath) > 0 and oldPath[0] == '\\':
            oldPath = oldPath[1:]

        newPath = newPath.replace('/', '\\')
        newPath = ntpath.normpath(newPath)
        if len(newPath) > 0 and newPath[0] == '\\':
            newPath = newPath[1:]

        treeId = self.connectTree(shareName)
        fileId = None
        try:
            fileId = self.create(treeId, oldPath, MAXIMUM_ALLOWED ,FILE_SHARE_READ | FILE_SHARE_WRITE |FILE_SHARE_DELETE, 0x200020, FILE_OPEN, 0)
            renameReq = FILE_RENAME_INFORMATION_TYPE_2()
            renameReq['ReplaceIfExists'] = 1
            renameReq['RootDirectory']   = '\x00'*8
            renameReq['FileNameLength']  = len(newPath)*2
            renameReq['FileName']        = newPath.encode('utf-16le')
            self.setInfo(treeId, fileId, renameReq, infoType = SMB2_0_INFO_FILE, fileInfoClass = SMB2_FILE_RENAME_INFO)
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId)

        return True

    def writeFile(self, treeId, fileId, data, offset = 0):
        finished = False
        writeOffset = offset
        while not finished:
            if len(data) == 0:
                break
            writeData = data[:self._Connection['MaxWriteSize']]
            data = data[self._Connection['MaxWriteSize']:]
            written = self.write(treeId, fileId, writeData, writeOffset, len(writeData))
            writeOffset += written
        return writeOffset - offset

    def isSnapshotRequest(self, path):
          
        return '@GMT-' in path

    def timestampForSnapshot(self, path):
        timestamp = path[path.index("@GMT-"):path.index("@GMT-")+24]
        path = path.replace(timestamp, '')
        from datetime import datetime
        fTime = int((datetime.strptime(timestamp, '@GMT-%Y.%m.%d-%H.%M.%S') - datetime(1970,1,1)).total_seconds())
        fTime *= 10000000
        fTime += 116444736000000000

        token = SMB2_CREATE_TIMEWARP_TOKEN()
        token['Timestamp'] = fTime

        ctx = SMB2CreateContext()
        ctx['Next'] = 0
        ctx['NameOffset'] = 16
        ctx['NameLength'] = len('TWrp')
        ctx['DataOffset'] = 24
        ctx['DataLength'] = 8
        ctx['Buffer'] = b'TWrp'
        ctx['Buffer'] += b'\x00'*4   
        ctx['Buffer'] += token.getData()

          
        path = path.replace(timestamp, '').replace('\\\\', '\\')
        if path == '\\':
            path += '*'
        return path, ctx

    def listPath(self, shareName, path, password = None):
        createContexts = None

        if self.isSnapshotRequest(path):
            createContexts = []
            path, ctx = self.timestampForSnapshot(path)
            createContexts.append(ctx)

          
        path = path.replace('/', '\\')
        path = ntpath.normpath(path)
        if len(path) > 0 and path[0] == '\\':
            path = path[1:]

        treeId = self.connectTree(shareName)

        fileId = None
        try:
              
            fileId = self.create(treeId, ntpath.dirname(path), FILE_READ_ATTRIBUTES | FILE_READ_DATA, FILE_SHARE_READ |
                                 FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, FILE_OPEN, 0,
                                 createContexts=createContexts)
            res = ''
            files = []
            from libs import smb
            while True:
                try:
                    res = self.queryDirectory(treeId, fileId, ntpath.basename(path), maxBufferSize=65535,
                                              informationClass=FILE_FULL_DIRECTORY_INFORMATION)
                    nextOffset = 1
                    while nextOffset != 0:
                        fileInfo = smb.SMBFindFileFullDirectoryInfo(smb.SMB.FLAGS2_UNICODE)
                        fileInfo.fromString(res)
                        files.append(smb.SharedFile(fileInfo['CreationTime'], fileInfo['LastAccessTime'],
                                                    fileInfo['LastChangeTime'], fileInfo['EndOfFile'],
                                                    fileInfo['AllocationSize'], fileInfo['ExtFileAttributes'],
                                                    fileInfo['FileName'].decode('utf-16le'),
                                                    fileInfo['FileName'].decode('utf-16le')))
                        nextOffset = fileInfo['NextEntryOffset']
                        res = res[nextOffset:]
                except SessionError as e:
                    if (e.get_error_code()) != STATUS_NO_MORE_FILES:
                        raise
                    break
                except Exception as e:
                    print(str(e))
                    raise
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId)

        return files

    def mkdir(self, shareName, pathName, password = None):
          
        pathName = pathName.replace('/', '\\')
        pathName = ntpath.normpath(pathName)
        if len(pathName) > 0 and pathName[0] == '\\':
            pathName = pathName[1:]

        treeId = self.connectTree(shareName)

        fileId = None
        try:
            fileId = self.create(treeId, pathName, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATE, 0)
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId)

        return True

    def rmdir(self, shareName, pathName, password = None):
          
        pathName = pathName.replace('/', '\\')
        pathName = ntpath.normpath(pathName)
        if len(pathName) > 0 and pathName[0] == '\\':
            pathName = pathName[1:]

        treeId = self.connectTree(shareName)

        fileId = None
        try:
            fileId = self.create(treeId, pathName, desiredAccess=DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                                 shareMode=FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                                 creationOptions=FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,
                                 creationDisposition=FILE_OPEN, fileAttributes=0)
            from libs import smb
            delete_req = smb.SMBSetFileDispositionInfo()
            delete_req['DeletePending'] = True
            self.setInfo(treeId, fileId, inputBlob=delete_req, fileInfoClass=SMB2_FILE_DISPOSITION_INFO)
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId)

        return True

    def remove(self, shareName, pathName, password = None):
          
        pathName = pathName.replace('/', '\\')
        pathName = ntpath.normpath(pathName)
        if len(pathName) > 0 and pathName[0] == '\\':
            pathName = pathName[1:]

        treeId = self.connectTree(shareName)

        fileId = None
        try:
            fileId = self.create(treeId, pathName,DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, FILE_OPEN, 0)
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId)

        return True

    def retrieveFile(self, shareName, path, callback, mode = FILE_OPEN, offset = 0, password = None, shareAccessMode = FILE_SHARE_READ):
        createContexts = None

        if self.isSnapshotRequest(path):
            createContexts = []
            path, ctx = self.timestampForSnapshot(path)
            createContexts.append(ctx)

          
        path = path.replace('/', '\\')
        path = ntpath.normpath(path)
        if len(path) > 0 and path[0] == '\\':
            path = path[1:]

        treeId = self.connectTree(shareName)
        fileId = None
        from libs import smb
        try:
            fileId = self.create(treeId, path, FILE_READ_DATA, shareAccessMode, FILE_NON_DIRECTORY_FILE, mode, 0, createContexts=createContexts)
            res = self.queryInfo(treeId, fileId)
            fileInfo = smb.SMBQueryFileStandardInfo(res)
            fileSize = fileInfo['EndOfFile']
            if (fileSize-offset) < self._Connection['MaxReadSize']:
                  
                if (fileSize-offset) > 0:
                    data = self.read(treeId, fileId, offset, fileSize-offset)
                    callback(data)
            else:
                written = 0
                toBeRead = fileSize-offset
                while written < toBeRead:
                    data = self.read(treeId, fileId, offset, self._Connection['MaxReadSize'])
                    written += len(data)
                    offset  += len(data)
                    callback(data)
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId)

    def storeFile(self, shareName, path, callback, mode = FILE_OVERWRITE_IF, offset = 0, password = None, shareAccessMode = FILE_SHARE_WRITE):
          
        path = path.replace('/', '\\')
        path = ntpath.normpath(path)
        if len(path) > 0 and path[0] == '\\':
            path = path[1:]

        treeId = self.connectTree(shareName)
        fileId = None
        try:
            fileId = self.create(treeId, path, FILE_WRITE_DATA, shareAccessMode, FILE_NON_DIRECTORY_FILE, mode, 0)
            finished = False
            writeOffset = offset
            while not finished:
                data = callback(self._Connection['MaxWriteSize'])
                if len(data) == 0:
                    break
                written = self.write(treeId, fileId, data, writeOffset, len(data))
                writeOffset += written
        finally:
            if fileId is not None:
                self.close(treeId, fileId)
            self.disconnectTree(treeId)

    def waitNamedPipe(self, treeId, pipename, timeout = 5):
        pipename = ntpath.basename(pipename)
        if (treeId in self._Session['TreeConnectTable']) is False:
            raise SessionError(STATUS_INVALID_PARAMETER)
        if len(pipename) > 0xffff:
            raise SessionError(STATUS_INVALID_PARAMETER)

        pipeWait = FSCTL_PIPE_WAIT_STRUCTURE()
        pipeWait['Timeout']          = timeout*100000
        pipeWait['NameLength']       = len(pipename)*2
        pipeWait['TimeoutSpecified'] = 1
        pipeWait['Name']             = pipename.encode('utf-16le')

        return self.ioctl(treeId, None, FSCTL_PIPE_WAIT,flags=SMB2_0_IOCTL_IS_FSCTL, inputBlob=pipeWait, maxInputResponse = 0, maxOutputResponse=0)

    def getIOCapabilities(self):
        res = dict()

        res['MaxReadSize'] = self._Connection['MaxReadSize']
        res['MaxWriteSize'] = self._Connection['MaxWriteSize']
        return res


      
      
      
      
    get_server_name            = getServerName
    get_client_name            = getClientName
    get_server_domain          = getServerDomain
    get_server_dns_domain_name = getServerDNSDomainName
    get_server_dns_host_name   = getServerDNSHostName
    get_remote_name            = getRemoteName
    set_remote_name            = setRemoteName
    get_remote_host            = getServerIP
    get_server_os              = getServerOS
    get_server_os_major        = getServerOSMajor
    get_server_os_minor        = getServerOSMinor
    get_server_os_build        = getServerOSBuild
    tree_connect_andx          = connectTree
    tree_connect               = connectTree
    connect_tree               = connectTree
    disconnect_tree            = disconnectTree
    set_timeout                = setTimeout
    use_timeout                = useTimeout
    stor_file                  = storeFile
    retr_file                  = retrieveFile
    list_path                  = listPath

    def close_session(self):
        if self._NetBIOSSession:
            self._NetBIOSSession.close()
            self._NetBIOSSession = None

    def doesSupportNTLMv2(self):
          
        return True

    def is_login_required(self):
          
        return True

    def is_signing_required(self):
        return self._Connection['RequireSigning']

    def nt_create_andx(self, treeId, fileName, smb_packet=None, cmd = None):
        if len(fileName) > 0 and fileName[0] == '\\':
            fileName = fileName[1:]

        if cmd is not None:
            from libs import smb
            ntCreate = smb.SMBCommand(data = cmd.getData())
            params = smb.SMBNtCreateAndX_Parameters(ntCreate['Parameters'])
            return self.create(treeId, fileName, params['AccessMask'], params['ShareAccess'],
                               params['CreateOptions'], params['Disposition'], params['FileAttributes'],
                               params['Impersonation'], params['SecurityFlags'])

        else:
            return self.create(treeId, fileName,
                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA |
                    FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, 0 )

    def get_socket(self):
        return self._NetBIOSSession.get_socket()


    def write_andx(self,tid,fid,data, offset = 0, wait_answer=1, write_pipe_mode = False, smb_packet=None):
          
        return self.write(tid, fid, data, offset, len(data))

    def TransactNamedPipe(self, tid, fid, data, noAnswer = 0, waitAnswer = 1, offset = 0):
        return self.ioctl(tid, fid, FSCTL_PIPE_TRANSCEIVE, SMB2_0_IOCTL_IS_FSCTL, data, maxOutputResponse = 65535, waitAnswer = noAnswer | waitAnswer)

    def TransactNamedPipeRecv(self):
        ans = self.recvSMB()

        if ans.isValidAnswer(STATUS_SUCCESS):
            smbIoctlResponse = SMB2Ioctl_Response(ans['Data'])
            return smbIoctlResponse['Buffer']


    def read_andx(self, tid, fid, offset=0, max_size = None, wait_answer=1, smb_packet=None):
          
        if max_size is None:
            max_size = self._Connection['MaxReadSize']
        return self.read(tid, fid, offset, max_size, wait_answer)

    def list_shared(self):
          
        raise SessionError(STATUS_NOT_IMPLEMENTED)

    def open_andx(self, tid, fileName, open_mode, desired_access):
          
        if len(fileName) > 0 and fileName[0] == '\\':
            fileName = fileName[1:]

        fileId = self.create(tid,fileName,desired_access, open_mode, FILE_NON_DIRECTORY_FILE, open_mode, 0)
        return fileId, 0, 0, 0, 0, 0, 0, 0, 0

    def set_session_key(self, signingKey):
        self._Session['SessionKey'] = signingKey
        self._Session['SigningActivated'] = True
        self._Session['SigningRequired'] = True

    def set_hostname_validation(self, validate, accept_empty, hostname):
        self._strict_hostname_validation = validate
        self._validation_allow_absent = accept_empty
        self._accepted_hostname = hostname

    def perform_hostname_validation(self):
        if self._Session['ServerName'] == '':
            if not self._validation_allow_absent:
                raise self.HostnameValidationException('Hostname was not supplied by target host and absent validation is disallowed')
            return
        if self._Session['ServerName'].lower() != self._accepted_hostname.lower() and self._Session['ServerDNSHostName'].lower() != self._accepted_hostname.lower():
            raise self.HostnameValidationException('Supplied hostname %s does not match reported hostnames %s or %s' %
                (self._accepted_hostname.lower(), self._Session['ServerName'].lower(), self._Session['ServerDNSHostName'].lower()))
