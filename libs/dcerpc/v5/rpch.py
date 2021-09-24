import re
import binascii
from struct import unpack

from libs import uuid, ntlm, system_errors, nt_errors, LOG
from libs.dcerpc.v5.rpcrt import DCERPCException

from libs.uuid import EMPTY_UUID
from libs.http import HTTPClientSecurityProvider, AUTH_BASIC
from libs.structure import Structure
from libs.dcerpc.v5.rpcrt import MSRPCHeader, \
    MSRPC_RTS, PFC_FIRST_FRAG, PFC_LAST_FRAG

class RPCProxyClientException(DCERPCException):
    parser = re.compile(r'RPC Error: ([a-fA-F0-9]{1,8})')

    def __init__(self, error_string=None, proxy_error=None):
        rpc_error_code = None

        if proxy_error is not None:
            try:
                search = self.parser.search(proxy_error)
                rpc_error_code = int(search.group(1), 16)
            except:
                error_string += ': ' + proxy_error

        DCERPCException.__init__(self, error_string, rpc_error_code)

    def __str__(self):
        if self.error_code is not None:
            key = self.error_code
            if key in system_errors.ERROR_MESSAGES:
                error_msg_short = system_errors.ERROR_MESSAGES[key][0]
                return '%s, code: 0x%x - %s' % (self.error_string, self.error_code, error_msg_short)
            elif key in nt_errors.ERROR_MESSAGES:
                error_msg_short = nt_errors.ERROR_MESSAGES[key][0]
                return '%s, code: 0x%x - %s' % (self.error_string, self.error_code, error_msg_short)
            else:
                return '%s: unknown code: 0x%x' % (self.error_string, self.error_code)
        else:
            return self.error_string

  
  
  

RPC_OVER_HTTP_v1 = 1
RPC_OVER_HTTP_v2 = 2

  

  
RPC_PROXY_REMOTE_NAME_NEEDED_ERR = 'Basic authentication in RPC proxy is used, ' \
                                   'so coudn\'t obtain a target NetBIOS name from NTLMSSP to connect.'

  
RPC_PROXY_INVALID_RPC_PORT_ERR = 'Invalid RPC Port'
RPC_PROXY_CONN_A1_0X6BA_ERR    = 'RPC Proxy CONN/A1 request failed, code: 0x6ba'
RPC_PROXY_CONN_A1_404_ERR      = 'CONN/A1 request failed: HTTP/1.1 404 Not Found'
RPC_PROXY_RPC_OUT_DATA_404_ERR = 'RPC_OUT_DATA channel: HTTP/1.1 404 Not Found'
RPC_PROXY_CONN_A1_401_ERR      = 'CONN/A1 request failed: HTTP/1.1 401 Unauthorized'
RPC_PROXY_HTTP_IN_DATA_401_ERR = 'RPC_IN_DATA channel: HTTP/1.1 401 Unauthorized'


  
FDClient   = 0x00000000
FDInProxy  = 0x00000001
FDServer   = 0x00000002
FDOutProxy = 0x00000003

RTS_FLAG_NONE            = 0x0000
RTS_FLAG_PING            = 0x0001
RTS_FLAG_OTHER_CMD       = 0x0002
RTS_FLAG_RECYCLE_CHANNEL = 0x0004
RTS_FLAG_IN_CHANNEL      = 0x0008
RTS_FLAG_OUT_CHANNEL     = 0x0010
RTS_FLAG_EOF             = 0x0020
RTS_FLAG_ECHO            = 0x0040

  
RTS_CMD_RECEIVE_WINDOW_SIZE      = 0x00000000
RTS_CMD_FLOW_CONTROL_ACK         = 0x00000001
RTS_CMD_CONNECTION_TIMEOUT       = 0x00000002
RTS_CMD_COOKIE                   = 0x00000003
RTS_CMD_CHANNEL_LIFETIME         = 0x00000004
RTS_CMD_CLIENT_KEEPALIVE         = 0x00000005
RTS_CMD_VERSION                  = 0x00000006
RTS_CMD_EMPTY                    = 0x00000007
RTS_CMD_PADDING                  = 0x00000008
RTS_CMD_NEGATIVE_ANCE            = 0x00000009
RTS_CMD_ANCE                     = 0x0000000A
RTS_CMD_CLIENT_ADDRESS           = 0x0000000B
RTS_CMD_ASSOCIATION_GROUP_ID     = 0x0000000C
RTS_CMD_DESTINATION              = 0x0000000D
RTS_CMD_PING_TRAFFIC_SENT_NOTIFY = 0x0000000E

  
  
  

  
class RTSCookie(Structure):
    structure = (
        ('Cookie','16s=b"\\x00"*16'),
    )

  
class EncodedClientAddress(Structure):
    structure = (
        ('AddressType','<L=(0 if len(ClientAddress) == 4 else 1)'),
        ('_ClientAddress','_-ClientAddress','4 if AddressType == 0 else 16'),
        ('ClientAddress',':'),
        ('Padding','12s=b"\\x00"*12'),
    )

  
class Ack(Structure):
    structure = (
        ('BytesReceived','<L=0'),
        ('AvailableWindow','<L=0'),
        ('ChannelCookie',':',RTSCookie),
    )

  
class ReceiveWindowSize(Structure):
    structure = (
        ('CommandType','<L=0'),
        ('ReceiveWindowSize','<L=262144'),
    )

  
class FlowControlAck(Structure):
    structure = (
        ('CommandType','<L=1'),
        ('Ack',':',Ack),
    )

  
class ConnectionTimeout(Structure):
    structure = (
        ('CommandType','<L=2'),
        ('ConnectionTimeout','<L=120000'),
    )

  
class Cookie(Structure):
    structure = (
        ('CommandType','<L=3'),
        ('Cookie',':',RTSCookie),
    )

  
class ChannelLifetime(Structure):
    structure = (
        ('CommandType','<L=4'),
        ('ChannelLifetime','<L=1073741824'),
    )

  
  
  
  
  
  
  
class ClientKeepalive(Structure):
    structure = (
        ('CommandType','<L=5'),
        ('ClientKeepalive','<L=300000'),
    )

  
class Version(Structure):
    structure = (
        ('CommandType','<L=6'),
        ('Version','<L=1'),
    )

  
class Empty(Structure):
    structure = (
        ('CommandType','<L=7'),
    )

  
class Padding(Structure):
    structure = (
        ('CommandType','<L=8'),
        ('ConformanceCount','<L=len(Padding)'),
        ('Padding','*ConformanceCount'),
    )

  
class NegativeANCE(Structure):
    structure = (
        ('CommandType','<L=9'),
    )

  
class ANCE(Structure):
    structure = (
        ('CommandType','<L=0xA'),
    )

  
class ClientAddress(Structure):
    structure = (
        ('CommandType','<L=0xB'),
        ('ClientAddress',':',EncodedClientAddress),
    )

  
class AssociationGroupId(Structure):
    structure = (
        ('CommandType','<L=0xC'),
        ('AssociationGroupId',':',RTSCookie),
    )

  
class Destination(Structure):
    structure = (
        ('CommandType','<L=0xD'),
        ('Destination','<L'),
    )

  
class PingTrafficSentNotify(Structure):
    structure = (
        ('CommandType','<L=0xE'),
        ('PingTrafficSent','<L'),
    )

COMMANDS = {
    0x0: ReceiveWindowSize,
    0x1: FlowControlAck,
    0x2: ConnectionTimeout,
    0x3: Cookie,
    0x4: ChannelLifetime,
    0x5: ClientKeepalive,
    0x6: Version,
    0x7: Empty,
    0x8: Padding,
    0x9: NegativeANCE,
    0xA: ANCE,
    0xB: ClientAddress,
    0xC: AssociationGroupId,
    0xD: Destination,
    0xE: PingTrafficSentNotify,
}

  
  
  
  
class RTSHeader(MSRPCHeader):
    _SIZE = 20
    commonHdr = MSRPCHeader.commonHdr + (
        ('Flags','<H=0'),               
        ('NumberOfCommands','<H=0'),    
    )

    def __init__(self, data=None, alignment=0):
        MSRPCHeader.__init__(self, data, alignment)
        self['type'] = MSRPC_RTS
        self['flags'] = PFC_FIRST_FRAG | PFC_LAST_FRAG
        self['auth_length'] = 0
        self['call_id'] = 0

  
  
  
  
class CONN_A1_RTS_PDU(Structure):
    structure = (
        ('Version',':',Version),
        ('VirtualConnectionCookie',':',Cookie),
        ('OutChannelCookie',':',Cookie),
        ('ReceiveWindowSize',':',ReceiveWindowSize),
    )

  
  
  
  
class CONN_B1_RTS_PDU(Structure):
    structure = (
        ('Version',':',Version),
        ('VirtualConnectionCookie',':',Cookie),
        ('INChannelCookie',':',Cookie),
        ('ChannelLifetime',':',ChannelLifetime),
        ('ClientKeepalive',':',ClientKeepalive),
        ('AssociationGroupId',':',AssociationGroupId),
    )

  
  
  
  
class CONN_A3_RTS_PDU(Structure):
    structure = (
        ('ConnectionTimeout',':',ConnectionTimeout),
    )

  
  
  
  
class CONN_C2_RTS_PDU(Structure):
    structure = (
        ('Version',':',Version),
        ('ReceiveWindowSize',':',ReceiveWindowSize),
        ('ConnectionTimeout',':',ConnectionTimeout),
    )

  
class FlowControlAckWithDestination_RTS_PDU(Structure):
    structure = (
        ('Destination',':',Destination),
        ('FlowControlAck',':',FlowControlAck),
    )

  
  
  
def hCONN_A1(virtualConnectionCookie=EMPTY_UUID, outChannelCookie=EMPTY_UUID, receiveWindowSize=262144):
    conn_a1 = CONN_A1_RTS_PDU()
    conn_a1['Version'] = Version()
    conn_a1['VirtualConnectionCookie'] = Cookie()
    conn_a1['VirtualConnectionCookie']['Cookie'] = virtualConnectionCookie
    conn_a1['OutChannelCookie'] = Cookie()
    conn_a1['OutChannelCookie']['Cookie'] = outChannelCookie
    conn_a1['ReceiveWindowSize'] = ReceiveWindowSize()
    conn_a1['ReceiveWindowSize']['ReceiveWindowSize'] = receiveWindowSize

    packet = RTSHeader()
    packet['Flags'] = RTS_FLAG_NONE
    packet['NumberOfCommands'] = len(conn_a1.structure)
    packet['pduData'] = conn_a1.getData()

    return packet.getData()

def hCONN_B1(virtualConnectionCookie=EMPTY_UUID, inChannelCookie=EMPTY_UUID, associationGroupId=EMPTY_UUID):
    conn_b1 = CONN_B1_RTS_PDU()
    conn_b1['Version'] = Version()
    conn_b1['VirtualConnectionCookie'] = Cookie()
    conn_b1['VirtualConnectionCookie']['Cookie'] = virtualConnectionCookie
    conn_b1['INChannelCookie'] = Cookie()
    conn_b1['INChannelCookie']['Cookie'] = inChannelCookie
    conn_b1['ChannelLifetime'] = ChannelLifetime()
    conn_b1['ClientKeepalive'] = ClientKeepalive()
    conn_b1['AssociationGroupId'] = AssociationGroupId()
    conn_b1['AssociationGroupId']['AssociationGroupId'] = RTSCookie()
    conn_b1['AssociationGroupId']['AssociationGroupId']['Cookie'] = associationGroupId

    packet = RTSHeader()
    packet['Flags'] = RTS_FLAG_NONE
    packet['NumberOfCommands'] = len(conn_b1.structure)
    packet['pduData'] = conn_b1.getData()

    return packet.getData()

def hFlowControlAckWithDestination(destination, bytesReceived, availableWindow, channelCookie):
    rts_pdu = FlowControlAckWithDestination_RTS_PDU()
    rts_pdu['Destination'] = Destination()
    rts_pdu['Destination']['Destination'] = destination
    rts_pdu['FlowControlAck'] = FlowControlAck()
    rts_pdu['FlowControlAck']['Ack'] = Ack()
    rts_pdu['FlowControlAck']['Ack']['BytesReceived'] = bytesReceived
    rts_pdu['FlowControlAck']['Ack']['AvailableWindow'] = availableWindow

      
    rts_pdu['FlowControlAck']['Ack']['ChannelCookie'] = RTSCookie()
    rts_pdu['FlowControlAck']['Ack']['ChannelCookie']['Cookie'] = channelCookie

    packet = RTSHeader()
    packet['Flags'] = RTS_FLAG_OTHER_CMD
    packet['NumberOfCommands'] = len(rts_pdu.structure)
    packet['pduData'] = rts_pdu.getData()

    return packet.getData()

def hPing():
    packet = RTSHeader()
    packet['Flags'] = RTS_FLAG_PING

    return packet.getData()

  
  
  
class RPCProxyClient(HTTPClientSecurityProvider):
    RECV_SIZE = 8192
    default_headers = {'User-Agent'   : 'MSRPC',
                       'Cache-Control': 'no-cache',
                       'Connection'   : 'Keep-Alive',
                       'Expect'       : '100-continue',
                       'Accept'       : 'application/rpc',
                       'Pragma'       : 'No-cache'
                      }

    def __init__(self, remoteName=None, dstport=593):
        HTTPClientSecurityProvider.__init__(self)
        self.__remoteName  = remoteName
        self.__dstport     = dstport

          
        self.__auth_type = None

        self.init_state()

    def init_state(self):
        self.__channels    = {}

        self.__inChannelCookie         = uuid.generate()
        self.__outChannelCookie        = uuid.generate()
        self.__associationGroupId      = uuid.generate()
        self.__virtualConnectionCookie = uuid.generate()

        self.__serverConnectionTimeout = None
        self.__serverReceiveWindowSize = None
        self.__availableWindowAdvertised = 262144   
        self.__receiverAvailableWindow = self.__availableWindowAdvertised
        self.__bytesReceived = 0

        self.__serverChunked = False
        self.__readBuffer = b''
        self.__chunkLeft = 0

        self.rts_ping_received = False

    def set_proxy_credentials(self, username, password, domain='', lmhash='', nthash=''):
        LOG.error("DeprecationWarning: Call to deprecated method set_proxy_credentials (use set_credentials).")
        self.set_credentials(username, password, domain, lmhash, nthash)

    def set_credentials(self, username, password, domain='', lmhash='', nthash='', aesKey='', TGT=None, TGS=None):
        HTTPClientSecurityProvider.set_credentials(self, username, password,
            domain, lmhash, nthash, aesKey, TGT, TGS)

    def create_rpc_in_channel(self):
        headers = self.default_headers.copy()
        headers['Content-Length'] = '1073741824'

        self.create_channel('RPC_IN_DATA', headers)

    def create_rpc_out_channel(self):
        headers = self.default_headers.copy()
        headers['Content-Length'] = '76'

        self.create_channel('RPC_OUT_DATA', headers)

    def create_channel(self, method, headers):
        self.__channels[method] = HTTPClientSecurityProvider.connect(self, self._rpcProxyUrl.scheme,
                                    self._rpcProxyUrl.netloc)

        auth_headers = HTTPClientSecurityProvider.get_auth_headers(self, self.__channels[method],
                           method, self._rpcProxyUrl.path, headers)[0]

        headers_final = {}
        headers_final.update(headers)
        headers_final.update(auth_headers)

        self.__auth_type = HTTPClientSecurityProvider.get_auth_type(self)

          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
        if not self.__remoteName and self.__auth_type == AUTH_BASIC:
            raise RPCProxyClientException(RPC_PROXY_REMOTE_NAME_NEEDED_ERR)

        if not self.__remoteName:
            ntlmssp = self.get_ntlmssp_info()
            self.__remoteName = ntlmssp[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
            self._stringbinding.set_network_address(self.__remoteName)
            LOG.debug('StringBinding has been changed to %s' % self._stringbinding)

        if not self._rpcProxyUrl.query:
            query = self.__remoteName + ':' + str(self.__dstport)
            self._rpcProxyUrl = self._rpcProxyUrl._replace(query=query)

        path = self._rpcProxyUrl.path + '?' + self._rpcProxyUrl.query

        self.__channels[method].request(method, path, headers=headers_final)
        self._read_100_continue(method)

    def _read_100_continue(self, method):
        resp = self.__channels[method].sock.recv(self.RECV_SIZE)

        while resp.find(b'\r\n\r\n') == -1:
            resp += self.__channels[method].sock.recv(self.RECV_SIZE)

          
          
          
          
          
          
        if resp[9:23] != b'100 Continue\r\n':
            try:
                  
                  
                resp = resp.split(b'\r\n')[0].decode("UTF-8", errors='replace')

                raise RPCProxyClientException('RPC Proxy Client: %s authentication failed in %s channel' %
                    (self.__auth_type, method), proxy_error=resp)
            except (IndexError, KeyError, AttributeError):
                raise RPCProxyClientException('RPC Proxy Client: %s authentication failed in %s channel' %
                    (self.__auth_type, method))

    def create_tunnel(self):
          
        packet = hCONN_A1(self.__virtualConnectionCookie, self.__outChannelCookie, self.__availableWindowAdvertised)
        self.get_socket_out().send(packet)

        packet = hCONN_B1(self.__virtualConnectionCookie, self.__inChannelCookie, self.__associationGroupId)
        self.get_socket_in().send(packet)

        resp = self.get_socket_out().recv(self.RECV_SIZE)

        while resp.find(b'\r\n\r\n') == -1:
            resp += self.get_socket_out().recv(self.RECV_SIZE)

        if resp[9:12] != b'200':
            try:
                  
                  
                resp = resp.split(b'\r\n')[0].decode("UTF-8", errors='replace')

                raise RPCProxyClientException('RPC Proxy CONN/A1 request failed', proxy_error=resp)
            except (IndexError, KeyError, AttributeError):
                raise RPCProxyClientException('RPC Proxy CONN/A1 request failed')

        resp_ascii = resp.decode("ASCII", errors='replace')
        if "transfer-encoding: chunked" in resp_ascii.lower():
            self.__serverChunked = True

          
        self.__readBuffer = resp[resp.find(b'\r\n\r\n') + 4:]

          
        conn_a3_rpc = self.rpc_out_read_pkt()
        conn_a3_pdu = RTSHeader(conn_a3_rpc)['pduData']
        conn_a3 = CONN_A3_RTS_PDU(conn_a3_pdu)
        self.__serverConnectionTimeout = conn_a3['ConnectionTimeout']['ConnectionTimeout']

          
        conn_c2_rpc = self.rpc_out_read_pkt()
        conn_c2_pdu = RTSHeader(conn_c2_rpc)['pduData']
        conn_c2 = CONN_C2_RTS_PDU(conn_c2_pdu)
        self.__serverReceiveWindowSize = conn_c2['ReceiveWindowSize']['ReceiveWindowSize']

    def get_socket_in(self):
        return self.__channels['RPC_IN_DATA'].sock

    def get_socket_out(self):
        return self.__channels['RPC_OUT_DATA'].sock

    def close_rpc_in_channel(self):
        return self.__channels['RPC_IN_DATA'].close()

    def close_rpc_out_channel(self):
        return self.__channels['RPC_OUT_DATA'].close()

    def check_http_error(self, buffer):
        if buffer[:22] == b'HTTP/1.0 503 RPC Error':
            raise RPCProxyClientException('RPC Proxy request failed', proxy_error=buffer)

    def rpc_out_recv1(self, amt=None):
          
          
          
          
          
        sock = self.get_socket_out()

        if self.__serverChunked is False:
            if len(self.__readBuffer) > 0:
                buffer = self.__readBuffer
                self.__readBuffer = b''
            else:
                  
                  
                  
                buffer = sock.recv(self.RECV_SIZE)

            self.check_http_error(buffer)

            if len(buffer) <= amt:
                return buffer

              
            self.__readBuffer = buffer[amt:]
            return buffer[:amt]

          
        if self.__chunkLeft > 0:
              
              
            if amt >= self.__chunkLeft:
                buffer = self.__readBuffer[:self.__chunkLeft]
                  
                self.__readBuffer = self.__readBuffer[self.__chunkLeft + 2:]
                self.__chunkLeft = 0

                return buffer
            else:
                buffer = self.__readBuffer[:amt]
                self.__readBuffer = self.__readBuffer[amt:]
                self.__chunkLeft -= amt

                return buffer

          
        buffer = self.__readBuffer
        self.__readBuffer = b''

        self.check_http_error(buffer)

          
          
        while buffer.find(b'\r\n') == -1:
            buffer += sock.recv(self.RECV_SIZE)
            self.check_http_error(buffer)

        chunksize = int(buffer[:buffer.find(b'\r\n')], 16)
        buffer = buffer[buffer.find(b'\r\n') + 2:]

          
        while len(buffer) - 2 < chunksize:
            buffer += sock.recv(chunksize - len(buffer) + 2)

          
          
          
        if len(buffer) - 2 > chunksize:
            self.__readBuffer = buffer[chunksize + 2:]
            buffer = buffer[:chunksize + 2]

          
        if len(buffer) - 2 > amt:
            self.__chunkLeft = chunksize - amt
              
              
            self.__readBuffer = buffer[amt:] + self.__readBuffer

            return buffer[:amt]
        else:
              
            return buffer[:-2]

    def send(self, data, forceWriteAndx=0, forceRecv=0):
          
          
          
        self.get_socket_in().send(data)

    def rpc_out_read_pkt(self, handle_rts=False):
        while True:
            response_data = b''

              
              
              
              
              
              
              
              
              
              
            while len(response_data) < MSRPCHeader._SIZE:
                response_data += self.rpc_out_recv1(MSRPCHeader._SIZE - len(response_data))

            response_header = MSRPCHeader(response_data)

              
              
            frag_len = response_header['frag_len']

              
            while len(response_data) < frag_len:
               response_data += self.rpc_out_recv1(frag_len - len(response_data))

              
              
              
              
              
            if response_header['type'] != MSRPC_RTS:
                self.flow_control(frag_len)

            if handle_rts is True and response_header['type'] == MSRPC_RTS:
                self.handle_out_of_sequence_rts(response_data)
            else:
                return response_data

    def recv(self, forceRecv=0, count=0):
        return self.rpc_out_read_pkt(handle_rts=True)

    def handle_out_of_sequence_rts(self, response_data):
        packet = RTSHeader(response_data)

          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          
          

          
        if packet['Flags'] == RTS_FLAG_PING:
              
              
              
              
              
              

              
              
            self.rts_ping_received = True
            LOG.error("Ping RTS PDU packet received. Is the RPC Server alive?")

              
              
            packet = hPing()
            self.send(packet)
            self.send(packet)
          
        elif packet['Flags'] == RTS_FLAG_RECYCLE_CHANNEL:
            raise RPCProxyClientException("The server requested recycling of a virtual OUT channel, " \
                "but this function is not supported!")
          
        else:
            pass

    def flow_control(self, frag_len):
        self.__bytesReceived += frag_len
        self.__receiverAvailableWindow -= frag_len

        if (self.__receiverAvailableWindow < self.__availableWindowAdvertised // 2):
            self.__receiverAvailableWindow = self.__availableWindowAdvertised
            packet = hFlowControlAckWithDestination(FDOutProxy, self.__bytesReceived,
                self.__availableWindowAdvertised, self.__outChannelCookie)
            self.send(packet)

    def connect(self):
        self.create_rpc_in_channel()
        self.create_rpc_out_channel()
        self.create_tunnel()

    def disconnect(self):
        self.close_rpc_in_channel()
        self.close_rpc_out_channel()
        self.init_state()
