from __future__ import absolute_import
from __future__ import print_function
import re
import binascii

from random import randrange
from struct import pack, unpack

EMPTY_UUID = b'\x00'*16


def generate():
      
    top = (1<<31)-1
    return pack("IIII", randrange(top), randrange(top), randrange(top), randrange(top))


def bin_to_string(uuid):
    uuid1, uuid2, uuid3 = unpack('<LHH', uuid[:8])
    uuid4, uuid5, uuid6 = unpack('>HHL', uuid[8:16])
    return '%08X-%04X-%04X-%04X-%04X%08X' % (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6)


def string_to_bin(uuid):
      
    if '-' not in uuid:
        return binascii.unhexlify(uuid)

      
      
    matches = re.match(r"([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})",
                       uuid)
    (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = [int(x, 16) for x in matches.groups()]
    uuid = pack('<LHH', uuid1, uuid2, uuid3)
    uuid += pack('>HHL', uuid4, uuid5, uuid6)
    return uuid


def stringver_to_bin(s):
    (maj, min) = s.split('.')
    return pack('<H', int(maj)) + pack('<H', int(min))


def uuidtup_to_bin(tup):
    if len(tup) != 2:
        return
    return string_to_bin(tup[0]) + stringver_to_bin(tup[1])


def bin_to_uuidtup(bin):
    assert len(bin) == 20
    uuidstr = bin_to_string(bin[:16])
    maj, min = unpack("<HH", bin[16:])
    return uuidstr, "%d.%d" % (maj, min)


def string_to_uuidtup(s):
    """
    if version is not found in the input string "1.0"  is returned
    example:
              "00000000-0000-0000-0000-000000000000 3.0" returns ('00000000-0000-0000-0000-000000000000','3.0')
              "10000000-2000-3000-4000-500000000000 version 3.0" returns ('00000000-0000-0000-0000-000000000000','3.0')
              "10000000-2000-3000-4000-500000000000 v 3.0" returns ('00000000-0000-0000-0000-000000000000','3.0')
              "10000000-2000-3000-4000-500000000000" returns ('00000000-0000-0000-0000-000000000000','1.0')

    :param s: string
    :return: tuple (uuid,version)
    """
    g = re.search(r"([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}).*?([0-9]{1,5}\.[0-9]{1,5})",
                  s + " 1.0")
    if g: 
        (u, v) = g.groups()
        return u, v
    return


def uuidtup_to_string(tup):
    uuid, (maj, min) = tup
    return "%s v%d.%d" % (uuid, maj, min)
