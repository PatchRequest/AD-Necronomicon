import datetime
import socket
import re
import struct

from pyasn1.codec.der import decoder

from . import asn1
from . import constants


class KerberosException(Exception):
    pass

def _asn1_decode(data, asn1Spec):
    if isinstance(data, str) or isinstance(data,bytes):
        data, substrate = decoder.decode(data, asn1Spec=asn1Spec)
        if substrate != b'':
            raise KerberosException("asn1 encoding invalid")
    return data

  

class Principal(object):
    """The principal's value can be supplied as:
* a single string
* a sequence containing a sequence of component strings and a realm string
* a sequence whose first n-1 elemeents are component strings and whose last
  component is the realm

If the value contains no realm, then default_realm will be used."""
    def __init__(self, value=None, default_realm=None, type=None):
        self.type = constants.PrincipalNameType.NT_UNKNOWN
        self.components = []
        self.realm = None

        if value is None:
            return

        try:                 
            if isinstance(value, unicode):
                value = value.encode('utf-8')
        except NameError:    
            if isinstance(value, bytes):
                value = value.decode('utf-8')

        if isinstance(value, Principal):
            self.type = value.type
            self.components = value.components[:]
            self.realm = value.realm
        elif isinstance(value, str):
            m = re.match(r'((?:[^\\]|\\.)+?)(@((?:[^\\@]|\\.)+))?$', value)
            if not m:
                raise KerberosException("invalid principal syntax")

            def unquote_component(comp):
                return re.sub(r'\\(.)', r'\1', comp)

            if m.group(2) is not None:
                self.realm = unquote_component(m.group(3))
            else:
                self.realm = default_realm

            self.components = [
                unquote_component(qc)
                for qc in re.findall(r'(?:[^\\/]|\\.)+', m.group(1))]
        elif len(value) == 2:
            self.components = value[0]
            self.realm = value[-1]
            if isinstance(self.components, str):
                self.components = [self.components]
        elif len(value) >= 2:
            self.components = value[0:-1]
            self.realm = value[-1]
        else:
            raise KerberosException("invalid principal value")

        if type is not None:
            self.type = type

    def __eq__(self, other):
        if isinstance (other, str):
            other = Principal (other)

        return (self.type == constants.PrincipalNameType.NT_UNKNOWN.value or
                other.type == constants.PrincipalNameType.NT_UNKNOWN.value or
                self.type == other.type) and all (map (lambda a, b: a == b, self.components, other.components)) and \
               self.realm == other.realm

    def __str__(self):
        def quote_component(comp):
            return re.sub(r'([\\/@])', r'\\\1', comp)

        ret = "/".join([quote_component(c) for c in self.components])
        if self.realm is not None:
            ret += "@" + self.realm

        return ret

    def __repr__(self):
        return "Principal((" + repr(self.components) + ", " + \
               repr(self.realm) + "), t=" + str(self.type) + ")"

    def from_asn1(self, data, realm_component, name_component):
        name = data.getComponentByName(name_component)
        self.type = constants.PrincipalNameType(
            name.getComponentByName('name-type')).value
        self.components = [
            str(c) for c in name.getComponentByName('name-string')]
        self.realm = str(data.getComponentByName(realm_component))
        return self

    def components_to_asn1(self, name):
        name.setComponentByName('name-type', int(self.type))
        strings = name.setComponentByName('name-string'
                                          ).getComponentByName('name-string')
        for i, c in enumerate(self.components):
            strings.setComponentByPosition(i, c)

        return name

class Address(object):
    DIRECTIONAL_AP_REQ_SENDER = struct.pack('!I', 0)
    DIRECTIONAL_AP_REQ_RECIPIENT = struct.pack('!I', 1)

    def __init__(self):
        self.type = None
        self.data = None

    def __str__(self):
        family = self.family

        if family is not None:
            return str((family, self.address))
        else:
            return str((self.type, self.value))

    @property
    def family(self):
        if self.type == constants.AddressType.IPv4.value:
            return socket.AF_INET
        elif self.type == constants.AddressType.IPv4.value:
            return socket.AF_INET6
        else:
            return None

    @property
    def address(self):
        if self.type == constants.AddressType.IPv4.value:
            return socket.inet_pton(self.family, self.data)
        elif self.type == constants.AddressType.IPv4.value:
            return socket.inet_pton(self.family, self.data)
        else:
            return None

    def encode(self):
          
        pass

class EncryptedData(object):
    def __init__(self):
        self.etype = None
        self.kvno = None
        self.ciphertext = None

    def from_asn1(self, data):
        data = _asn1_decode(data, asn1.EncryptedData())
        self.etype = constants.EncryptionTypes(data.getComponentByName('etype')).value
        kvno = data.getComponentByName('kvno')
        if (kvno is None) or (kvno.hasValue() is False):
            self.kvno = False
        else:
            self.kvno = kvno
        self.ciphertext = str(data.getComponentByName('cipher'))
        return self

    def to_asn1(self, component):
        component.setComponentByName('etype', int(self.etype))
        if self.kvno:
            component.setComponentByName('kvno', self.kvno)
        component.setComponentByName('cipher', self.ciphertext)
        return component

class Ticket(object):
    def __init__(self):
          
          
        self.tkt_vno = None
        self.service_principal = None
        self.encrypted_part = None

    def from_asn1(self, data):
        data = _asn1_decode(data, asn1.Ticket())
        self.tkt_vno = int(data.getComponentByName('tkt-vno'))
        self.service_principal = Principal()
        self.service_principal.from_asn1(data, 'realm', 'sname')
        self.encrypted_part = EncryptedData()
        self.encrypted_part.from_asn1(data.getComponentByName('enc-part'))
        return self

    def to_asn1(self, component):
        component.setComponentByName('tkt-vno', 5)
        component.setComponentByName('realm', self.service_principal.realm)
        asn1.seq_set(component, 'sname',
                     self.service_principal.components_to_asn1)
        asn1.seq_set(component, 'enc-part', self.encrypted_part.to_asn1)
        return component

    def __str__(self):
        return "<Ticket for %s vno %s>" % (str(self.service_principal), str(self.encrypted_part.kvno)) 

class KerberosTime(object):
    INDEFINITE = datetime.datetime(1970, 1, 1, 0, 0, 0)

    @staticmethod
    def to_asn1(dt):
          
          

        return "%04d%02d%02d%02d%02d%02dZ" % (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

    @staticmethod
    def from_asn1(data):
        data = str(data)
        year = int(data[0:4])
        month = int(data[4:6])
        day = int(data[6:8])
        hour = int(data[8:10])
        minute = int(data[10:12])
        second = int(data[12:14])
        if data[14] != 'Z':
            raise KerberosException("timezone in KerberosTime is not Z")
        return datetime.datetime(year, month, day, hour, minute, second)

if __name__ == '__main__':
      
    print(Principal("marc"))
    print(Principal(("marc", None)))
    print(Principal((("marc",), None)))
    print(Principal("marc@ATHENA.MIT.EDU"))
    print(Principal("marc", default_realm="ATHENA.MIT.EDU"))
    print(Principal("marc@ATHENA.MIT.EDU", default_realm="EXAMPLE.COM"))
    print(Principal(("marc", "ATHENA.MIT.EDU")))
    print(Principal((("marc"), "ATHENA.MIT.EDU")))
    print(Principal("marc/root"))
    print(Principal(("marc", "root", "ATHENA.MIT.EDU")))
    print(Principal((("marc", "root"), "ATHENA.MIT.EDU")))
    print(Principal("marc\\/root"))
