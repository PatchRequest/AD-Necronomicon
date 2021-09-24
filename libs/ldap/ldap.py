import os
import re
import socket
from binascii import unhexlify
import random

from pyasn1.codec.ber import encoder, decoder
from pyasn1.error import SubstrateUnderrunError
from pyasn1.type.univ import noValue

from libs import LOG
from libs.ldap.ldapasn1 import Filter, Control, SimplePagedResultsControl, ResultCode, Scope, DerefAliases, Operation, \
    KNOWN_CONTROLS, CONTROL_PAGEDRESULTS, NOTIFICATION_DISCONNECT, KNOWN_NOTIFICATIONS, BindRequest, SearchRequest, \
    SearchResultDone, LDAPMessage
from libs.ntlm import getNTLMSSPType1, getNTLMSSPType3
from libs.spnego import SPNEGO_NegTokenInit, TypesMech

try:
    import OpenSSL
    from OpenSSL import SSL, crypto
except:
    LOG.critical("pyOpenSSL is not installed, can't continue")
    raise

__all__ = [
    'LDAPConnection', 'LDAPFilterSyntaxError', 'LDAPFilterInvalidException', 'LDAPSessionError', 'LDAPSearchError',
    'Control', 'SimplePagedResultsControl', 'ResultCode', 'Scope', 'DerefAliases', 'Operation',
    'CONTROL_PAGEDRESULTS', 'KNOWN_CONTROLS', 'NOTIFICATION_DISCONNECT', 'KNOWN_NOTIFICATIONS',
]

  
DESCRIPTION = r'(?:[a-z][a-z0-9\-]*)'
NUMERIC_OID = r'(?:(?:\d|[1-9]\d+)(?:\.(?:\d|[1-9]\d+))*)'
OID = r'(?:%s|%s)' % (DESCRIPTION, NUMERIC_OID)
OPTIONS = r'(?:(?:;[a-z0-9\-]+)*)'
ATTRIBUTE = r'(%s%s)' % (OID, OPTIONS)
DN = r'(:dn)'
MATCHING_RULE = r'(?::(%s))' % OID

RE_OPERATOR = re.compile(r'([:<>~]?=)')
RE_ATTRIBUTE = re.compile(r'^%s$' % ATTRIBUTE, re.I)
RE_EX_ATTRIBUTE_1 = re.compile(r'^%s%s?%s?$' % (ATTRIBUTE, DN, MATCHING_RULE), re.I)
RE_EX_ATTRIBUTE_2 = re.compile(r'^(){0}%s?%s$' % (DN, MATCHING_RULE), re.I)


class LDAPConnection:
    def __init__(self, url, baseDN='', dstIp=None):
        """
        LDAPConnection class

        :param string url:
        :param string baseDN:
        :param string dstIp:

        :return: a LDAP instance, if not raises a LDAPSessionError exception
        """
        self._SSL = False
        self._dstPort = 0
        self._dstHost = 0
        self._socket = None
        self._baseDN = baseDN
        self._dstIp = dstIp

        if url.startswith('ldap://'):
            self._dstPort = 389
            self._SSL = False
            self._dstHost = url[7:]
        elif url.startswith('ldaps://'):
            self._dstPort = 636
            self._SSL = True
            self._dstHost = url[8:]
        elif url.startswith('gc://'):
            self._dstPort = 3268
            self._SSL = False
            self._dstHost = url[5:]
        else:
            raise LDAPSessionError(errorString="Unknown URL prefix: '%s'" % url)

          
        if self._dstIp is not None:
            targetHost = self._dstIp
        else:
            targetHost = self._dstHost

        LOG.debug('Connecting to %s, port %d, SSL %s' % (targetHost, self._dstPort, self._SSL))
        try:
            af, socktype, proto, _, sa = socket.getaddrinfo(targetHost, self._dstPort, 0, socket.SOCK_STREAM)[0]
            self._socket = socket.socket(af, socktype, proto)
        except socket.error as e:
            raise socket.error('Connection error (%s:%d)' % (targetHost, 88), e)

        if self._SSL is False:
            self._socket.connect(sa)
        else:
              
            ctx = SSL.Context(SSL.TLSv1_METHOD)
              
            self._socket = SSL.Connection(ctx, self._socket)
            self._socket.connect(sa)
            self._socket.do_handshake()

    def kerberosLogin(self, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None,
                      TGS=None, useCache=True):
        """
        logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for (required)
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
        :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
        :param struct TGT: If there's a TGT available, send the structure here and it will be used
        :param struct TGS: same for TGS. See smb3.py for the format
        :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False

        :return: True, raises a LDAPSessionError if error.
        """

        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0' + lmhash
            if len(nthash) % 2:
                nthash = '0' + nthash
            try:    
                lmhash = unhexlify(lmhash)
                nthash = unhexlify(nthash)
            except TypeError:
                pass

          
        from libs.krb5.ccache import CCache
        from libs.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from libs.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from libs.krb5 import constants
        from libs.krb5.types import Principal, KerberosTime, Ticket
        import datetime

        if TGT is not None or TGS is not None:
            useCache = False

        if useCache:
            try:
                ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
            except:
                  
                pass
            else:
                  
                if domain == '':
                    domain = ccache.principal.realm['data'].decode('utf-8')
                    LOG.debug('Domain retrieved from CCache: %s' % domain)

                LOG.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
                principal = 'ldap/%s@%s' % (self._dstHost.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is None:
                      
                    principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                    creds = ccache.getCredential(principal)
                    if creds is not None:
                        TGT = creds.toTGT()
                        LOG.debug('Using TGT from cache')
                    else:
                        LOG.debug('No valid credentials found in cache')
                else:
                    TGS = creds.toTGS(principal)
                    LOG.debug('Using TGS from cache')

                  
                if user == '' and creds is not None:
                    user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                    LOG.debug('Username retrieved from CCache: %s' % user)
                elif user == '' and len(ccache.principal.components) > 0:
                    user = ccache.principal.components[0]['data'].decode('utf-8')
                    LOG.debug('Username retrieved from CCache: %s' % user)

          
        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        if TGT is None:
            if TGS is None:
                tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash,
                                                                        aesKey, kdcHost)
        else:
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']

        if TGS is None:
            serverName = Principal('ldap/%s' % self._dstHost, type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher,
                                                                    sessionKey)
        else:
            tgs = TGS['KDC_REP']
            cipher = TGS['cipher']
            sessionKey = TGS['sessionKey']

              

        blob = SPNEGO_NegTokenInit()

          
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

          
        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

          
        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

        opts = []
        apReq['ap-options'] = constants.encodeFlags(opts)
        seq_set(apReq, 'ticket', ticket.to_asn1)

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

        blob['MechToken'] = encoder.encode(apReq)

          

        bindRequest = BindRequest()
        bindRequest['version'] = 3
        bindRequest['name'] = user
        bindRequest['authentication']['sasl']['mechanism'] = 'GSS-SPNEGO'
        bindRequest['authentication']['sasl']['credentials'] = blob.getData()

        response = self.sendReceive(bindRequest)[0]['protocolOp']

        if response['bindResponse']['resultCode'] != ResultCode('success'):
            raise LDAPSessionError(
                errorString='Error in bindRequest -> %s: %s' % (response['bindResponse']['resultCode'].prettyPrint(),
                                                                response['bindResponse']['diagnosticMessage'])
            )

        return True

    def login(self, user='', password='', domain='', lmhash='', nthash='', authenticationChoice='sicilyNegotiate'):
        """
        logins into the target system

        :param string user: username
        :param string password: password for the user
        :param string domain: domain where the account is valid for
        :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
        :param string nthash: NTHASH used to authenticate using hashes (password is not used)
        :param string authenticationChoice: type of authentication protocol to use (default NTLM)

        :return: True, raises a LDAPSessionError if error.
        """
        bindRequest = BindRequest()
        bindRequest['version'] = 3

        if authenticationChoice == 'simple':
            if '.' in domain:
                bindRequest['name'] = user + '@' + domain
            elif domain:
                bindRequest['name'] = domain + '\\' + user
            else:
                bindRequest['name'] = user
            bindRequest['authentication']['simple'] = password
            response = self.sendReceive(bindRequest)[0]['protocolOp']
        elif authenticationChoice == 'sicilyPackageDiscovery':
            bindRequest['name'] = user
            bindRequest['authentication']['sicilyPackageDiscovery'] = ''
            response = self.sendReceive(bindRequest)[0]['protocolOp']
        elif authenticationChoice == 'sicilyNegotiate':
              
            if lmhash != '' or nthash != '':
                if len(lmhash) % 2:
                    lmhash = '0' + lmhash
                if len(nthash) % 2:
                    nthash = '0' + nthash
                try:    
                    lmhash = unhexlify(lmhash)
                    nthash = unhexlify(nthash)
                except TypeError:
                    pass

            bindRequest['name'] = user

              
            negotiate = getNTLMSSPType1('', domain)
            bindRequest['authentication']['sicilyNegotiate'] = negotiate.getData()
            response = self.sendReceive(bindRequest)[0]['protocolOp']

              
            type2 = response['bindResponse']['matchedDN']

              
            type3, exportedSessionKey = getNTLMSSPType3(negotiate, bytes(type2), user, password, domain, lmhash, nthash)
            bindRequest['authentication']['sicilyResponse'] = type3.getData()
            response = self.sendReceive(bindRequest)[0]['protocolOp']
        else:
            raise LDAPSessionError(errorString="Unknown authenticationChoice: '%s'" % authenticationChoice)

        if response['bindResponse']['resultCode'] != ResultCode('success'):
            raise LDAPSessionError(
                errorString='Error in bindRequest -> %s: %s' % (response['bindResponse']['resultCode'].prettyPrint(),
                                                                response['bindResponse']['diagnosticMessage'])
            )

        return True

    def search(self, searchBase=None, scope=None, derefAliases=None, sizeLimit=0, timeLimit=0, typesOnly=False,
               searchFilter='(objectClass=*)', attributes=None, searchControls=None, perRecordCallback=None):
        if searchBase is None:
            searchBase = self._baseDN
        if scope is None:
            scope = Scope('wholeSubtree')
        if derefAliases is None:
            derefAliases = DerefAliases('neverDerefAliases')
        if attributes is None:
            attributes = []

        searchRequest = SearchRequest()
        searchRequest['baseObject'] = searchBase
        searchRequest['scope'] = scope
        searchRequest['derefAliases'] = derefAliases
        searchRequest['sizeLimit'] = sizeLimit
        searchRequest['timeLimit'] = timeLimit
        searchRequest['typesOnly'] = typesOnly
        searchRequest['filter'] = self._parseFilter(searchFilter)
        searchRequest['attributes'].setComponents(*attributes)

        done = False
        answers = []
          
        while not done:
            response = self.sendReceive(searchRequest, searchControls)
            for message in response:
                searchResult = message['protocolOp'].getComponent()
                if searchResult.isSameTypeWith(SearchResultDone()):
                    if searchResult['resultCode'] == ResultCode('success'):
                        done = self._handleControls(searchControls, message['controls'])
                    else:
                        raise LDAPSearchError(
                            error=int(searchResult['resultCode']),
                            errorString='Error in searchRequest -> %s: %s' % (searchResult['resultCode'].prettyPrint(),
                                                                              searchResult['diagnosticMessage']),
                            answers=answers
                        )
                else:
                    if perRecordCallback is None:
                        answers.append(searchResult)
                    else:
                        perRecordCallback(searchResult)

        return answers

    def _handleControls(self, requestControls, responseControls):
        done = True
        if requestControls is not None:
            for requestControl in requestControls:
                if responseControls is not None:
                    for responseControl in responseControls:
                        if str(requestControl['controlType']) == CONTROL_PAGEDRESULTS:
                            if str(responseControl['controlType']) == CONTROL_PAGEDRESULTS:
                                if hasattr(responseControl, 'getCookie') is not True:
                                    responseControl = decoder.decode(encoder.encode(responseControl),
                                                                 asn1Spec=KNOWN_CONTROLS[CONTROL_PAGEDRESULTS]())[0]
                                if responseControl.getCookie():
                                    done = False
                                requestControl.setCookie(responseControl.getCookie())
                                break
                        else:
                              
                            pass
        return done

    def close(self):
        if self._socket is not None:
            self._socket.close()

    def send(self, request, controls=None):
        message = LDAPMessage()
        message['messageID'] = random.randrange(1, 2147483647)
        message['protocolOp'].setComponentByType(request.getTagSet(), request)
        if controls is not None:
            message['controls'].setComponents(*controls)

        data = encoder.encode(message)

        return self._socket.sendall(data)

    def recv(self):
        REQUEST_SIZE = 8192
        data = b''
        done = False
        while not done:
            recvData = self._socket.recv(REQUEST_SIZE)
            if len(recvData) < REQUEST_SIZE:
                done = True
            data += recvData

        response = []
        while len(data) > 0:
            try:
                message, remaining = decoder.decode(data, asn1Spec=LDAPMessage())
            except SubstrateUnderrunError:
                  
                remaining = data + self._socket.recv(REQUEST_SIZE)
            else:
                if message['messageID'] == 0:    
                    name = message['protocolOp']['extendedResp']['responseName'] or message['responseName']
                    notification = KNOWN_NOTIFICATIONS.get(name, "Unsolicited Notification '%s'" % name)
                    if name == NOTIFICATION_DISCONNECT:    
                        self.close()
                    raise LDAPSessionError(
                        error=int(message['protocolOp']['extendedResp']['resultCode']),
                        errorString='%s -> %s: %s' % (notification,
                                                      message['protocolOp']['extendedResp']['resultCode'].prettyPrint(),
                                                      message['protocolOp']['extendedResp']['diagnosticMessage'])
                    )
                response.append(message)
            data = remaining

        return response

    def sendReceive(self, request, controls=None):
        self.send(request, controls)
        return self.recv()

    def _parseFilter(self, filterStr):
        try:
            filterStr = filterStr.decode()
        except AttributeError:
            pass
        filterList = list(reversed(filterStr))
        searchFilter = self._consumeCompositeFilter(filterList)
        if filterList:    
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % filterList[-1])
        return searchFilter

    def _consumeCompositeFilter(self, filterList):
        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != '(':    
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % c)

        try:
            operator = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if operator not in ['!', '&', '|']:    
            filterList.extend([operator, c])
            return self._consumeSimpleFilter(filterList)

        filters = []
        while True:
            try:
                filters.append(self._consumeCompositeFilter(filterList))
            except LDAPFilterSyntaxError:
                break

        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != ')':    
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % c)

        return self._compileCompositeFilter(operator, filters)

    def _consumeSimpleFilter(self, filterList):
        try:
            c = filterList.pop()
        except IndexError:
            raise LDAPFilterSyntaxError('EOL while parsing search filter')
        if c != '(':    
            filterList.append(c)
            raise LDAPFilterSyntaxError("unexpected token: '%s'" % c)

        filter = []
        while True:
            try:
                c = filterList.pop()
            except IndexError:
                raise LDAPFilterSyntaxError('EOL while parsing search filter')
            if c == ')':    
                break
            elif c == '(':    
                filterList.append(c)
                raise LDAPFilterSyntaxError("unexpected token: '('")
            else:
                filter.append(c)

        filterStr = ''.join(filter)
        try:
              
            attribute, operator, value = RE_OPERATOR.split(filterStr, 1)
        except ValueError:
            raise LDAPFilterInvalidException("invalid filter: '(%s)'" % filterStr)

        return self._compileSimpleFilter(attribute, operator, value)

    @staticmethod
    def _compileCompositeFilter(operator, filters):
        searchFilter = Filter()
        if operator == '!':
            if len(filters) != 1:
                raise LDAPFilterInvalidException("'not' filter must have exactly one element")
            searchFilter['not'].setComponents(*filters)
        elif operator == '&':
            if len(filters) == 0:
                raise LDAPFilterInvalidException("'and' filter must have at least one element")
            searchFilter['and'].setComponents(*filters)
        elif operator == '|':
            if len(filters) == 0:
                raise LDAPFilterInvalidException("'or' filter must have at least one element")
            searchFilter['or'].setComponents(*filters)

        return searchFilter

    @staticmethod
    def _compileSimpleFilter(attribute, operator, value):
        searchFilter = Filter()
        if operator == ':=':    
            match = RE_EX_ATTRIBUTE_1.match(attribute) or RE_EX_ATTRIBUTE_2.match(attribute)
            if not match:
                raise LDAPFilterInvalidException("invalid filter attribute: '%s'" % attribute)
            attribute, dn, matchingRule = match.groups()
            if attribute:
                searchFilter['extensibleMatch']['type'] = attribute
            if dn:
                searchFilter['extensibleMatch']['dnAttributes'] = bool(dn)
            if matchingRule:
                searchFilter['extensibleMatch']['matchingRule'] = matchingRule
            searchFilter['extensibleMatch']['matchValue'] = value
        else:
            if not RE_ATTRIBUTE.match(attribute):
                raise LDAPFilterInvalidException("invalid filter attribute: '%s'" % attribute)
            if value == '*' and operator == '=':    
                searchFilter['present'] = attribute
            elif '*' in value and operator == '=':    
                assertions = value.split('*')
                choice = searchFilter['substrings']['substrings'].getComponentType()
                substrings = []
                if assertions[0]:
                    substrings.append(choice.clone().setComponentByName('initial', assertions[0]))
                for assertion in assertions[1:-1]:
                    substrings.append(choice.clone().setComponentByName('any', assertion))
                if assertions[-1]:
                    substrings.append(choice.clone().setComponentByName('final', assertions[-1]))
                searchFilter['substrings']['type'] = attribute
                searchFilter['substrings']['substrings'].setComponents(*substrings)
            elif '*' not in value:    
                if operator == '=':
                    searchFilter['equalityMatch'].setComponents(attribute, value)
                elif operator == '~=':
                    searchFilter['approxMatch'].setComponents(attribute, value)
                elif operator == '>=':
                    searchFilter['greaterOrEqual'].setComponents(attribute, value)
                elif operator == '<=':
                    searchFilter['lessOrEqual'].setComponents(attribute, value)
            else:
                raise LDAPFilterInvalidException("invalid filter '(%s%s%s)'" % (attribute, operator, value))

        return searchFilter


class LDAPFilterSyntaxError(SyntaxError):
    pass


class LDAPFilterInvalidException(Exception):
    pass


class LDAPSessionError(Exception):
    """
    This is the exception every client should catch
    """

    def __init__(self, error=0, packet=0, errorString=''):
        Exception.__init__(self)
        self.error = error
        self.packet = packet
        self.errorString = errorString

    def getErrorCode(self):
        return self.error

    def getErrorPacket(self):
        return self.packet

    def getErrorString(self):
        return self.errorString

    def __str__(self):
        return self.errorString


class LDAPSearchError(LDAPSessionError):
    def __init__(self, error=0, packet=0, errorString='', answers=None):
        LDAPSessionError.__init__(self, error, packet, errorString)
        if answers is None:
            answers = []
        self.answers = answers

    def getAnswers(self):
        return self.answers
