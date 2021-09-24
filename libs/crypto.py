

from __future__ import division
from __future__ import print_function
from libs import LOG
try:
    from Cryptodome.Cipher import DES, AES
except Exception:
    LOG.error("Warning: You don't have any crypto installed. You need pycryptodomex")
    LOG.error("See https://pypi.org/project/pycryptodomex/")
from struct import pack, unpack
from libs.structure import Structure
import hmac, hashlib
from six import b

def Generate_Subkey(K):

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

    AES_128 = AES.new(K, AES.MODE_ECB)

    L = AES_128.encrypt(bytes(bytearray(16)))

    LHigh = unpack('>Q',L[:8])[0]
    LLow  = unpack('>Q',L[8:])[0]

    K1High = ((LHigh << 1) | ( LLow >> 63 )) & 0xFFFFFFFFFFFFFFFF
    K1Low  = (LLow << 1) & 0xFFFFFFFFFFFFFFFF

    if (LHigh >> 63):
        K1Low ^= 0x87

    K2High = ((K1High << 1) | (K1Low >> 63)) & 0xFFFFFFFFFFFFFFFF
    K2Low  = ((K1Low << 1)) & 0xFFFFFFFFFFFFFFFF

    if (K1High >> 63):
        K2Low ^= 0x87

    K1 = bytearray(pack('>QQ', K1High, K1Low))
    K2 = bytearray(pack('>QQ', K2High, K2Low))

    return K1, K2

def XOR_128(N1,N2):

    J = bytearray()
    for i in range(len(N1)):
          
        J.append(N1[i] ^ N2[i])
    return J

def PAD(N):
    padLen = 16-len(N)
    return  N + b'\x80' + b'\x00'*(padLen-1)

def AES_CMAC(K, M, length):

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

    const_Bsize = 16
    const_Zero  = bytearray(16)

    AES_128= AES.new(K, AES.MODE_ECB)
    M      = bytearray(M[:length])
    K1, K2 = Generate_Subkey(K)
    n      = len(M)//const_Bsize

    if n == 0:
        n = 1
        flag = False
    else:
        if (length % const_Bsize) == 0:
            flag = True
        else:
            n += 1
            flag = False

    M_n = M[(n-1)*const_Bsize:]
    if flag is True:
        M_last = XOR_128(M_n,K1)
    else:
        M_last = XOR_128(PAD(M_n),K2)

    X = const_Zero
    for i in range(n-1):
        M_i = M[(i)*const_Bsize:][:16]
        Y   = XOR_128(X, M_i)
        X   = bytearray(AES_128.encrypt(bytes(Y)))
    Y = XOR_128(M_last, X)
    T = AES_128.encrypt(bytes(Y))

    return T

def AES_CMAC_PRF_128(VK, M, VKlen, Mlen):
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
    if VKlen == 16:
        K = VK
    else:
        K = AES_CMAC(bytes(bytearray(16)), VK, VKlen)

    PRV = AES_CMAC(K, M, Mlen)

    return PRV

def KDF_CounterMode(KI, Label, Context, L):
  
  
  
  
  
  
  
  
  
  
  
  
  
  
    h = 256
    r = 32

    n = L // h

    if n == 0:
        n = 1

    if n > (pow(2,r)-1):
        raise Exception("Error computing KDF_CounterMode")

    result = b''
    K      = b''

    for i in range(1,n+1):
       input = pack('>L', i) + Label + b'\x00' + Context + pack('>L',L)
       K = hmac.new(KI, input, hashlib.sha256).digest()
       result = result + K

    return result[:(L//8)]

  
class LSA_SECRET_XP(Structure):
    structure = (
        ('Length','<L=0'),
        ('Version','<L=0'),
        ('_Secret','_-Secret', 'self["Length"]'),
        ('Secret', ':'),
    )


def transformKey(InputKey):
      
    OutputKey = []
    OutputKey.append( chr(ord(InputKey[0:1]) >> 0x01) )
    OutputKey.append( chr(((ord(InputKey[0:1])&0x01)<<6) | (ord(InputKey[1:2])>>2)) )
    OutputKey.append( chr(((ord(InputKey[1:2])&0x03)<<5) | (ord(InputKey[2:3])>>3)) )
    OutputKey.append( chr(((ord(InputKey[2:3])&0x07)<<4) | (ord(InputKey[3:4])>>4)) )
    OutputKey.append( chr(((ord(InputKey[3:4])&0x0F)<<3) | (ord(InputKey[4:5])>>5)) )
    OutputKey.append( chr(((ord(InputKey[4:5])&0x1F)<<2) | (ord(InputKey[5:6])>>6)) )
    OutputKey.append( chr(((ord(InputKey[5:6])&0x3F)<<1) | (ord(InputKey[6:7])>>7)) )
    OutputKey.append( chr(ord(InputKey[6:7]) & 0x7F) )

    for i in range(8):
        OutputKey[i] = chr((ord(OutputKey[i]) << 1) & 0xfe)

    return b("".join(OutputKey))

def decryptSecret(key, value):
      
    plainText = b''
    key0 = key
    for i in range(0, len(value), 8):
        cipherText = value[:8]
        tmpStrKey = key0[:7]
        tmpKey = transformKey(tmpStrKey)
        Crypt1 = DES.new(tmpKey, DES.MODE_ECB)
        plainText += Crypt1.decrypt(cipherText)
        key0 = key0[7:]
        value = value[8:]
          
        if len(key0) < 7:
            key0 = key[len(key0):]

    secret = LSA_SECRET_XP(plainText)
    return (secret['Secret'])

def encryptSecret(key, value):
      
    cipherText = b''
    key0 = key
    value0 = pack('<LL', len(value), 1) + value
    for i in range(0, len(value0), 8):
        if len(value0) < 8:
            value0 = value0 + b'\x00'*(8-len(value0))
        plainText = value0[:8]
        tmpStrKey = key0[:7]
        print(type(tmpStrKey))
        print(tmpStrKey)
        tmpKey = transformKey(tmpStrKey)
        Crypt1 = DES.new(tmpKey, DES.MODE_ECB)
        cipherText += Crypt1.encrypt(plainText)
        key0 = key0[7:]
        value0 = value0[8:]
          
        if len(key0) < 7:
            key0 = key[len(key0):]

    return cipherText

def SamDecryptNTLMHash(encryptedHash, key):
      
    Block1 = encryptedHash[:8]
    Block2 = encryptedHash[8:]

    Key1 = key[:7]
    Key1 = transformKey(Key1)
    Key2 = key[7:14]
    Key2 = transformKey(Key2)

    Crypt1 = DES.new(Key1, DES.MODE_ECB)
    Crypt2 = DES.new(Key2, DES.MODE_ECB)

    plain1 = Crypt1.decrypt(Block1)
    plain2 = Crypt2.decrypt(Block2)

    return plain1 + plain2

def SamEncryptNTLMHash(encryptedHash, key):
      
    Block1 = encryptedHash[:8]
    Block2 = encryptedHash[8:]

    Key1 = key[:7]
    Key1 = transformKey(Key1)
    Key2 = key[7:14]
    Key2 = transformKey(Key2)

    Crypt1 = DES.new(Key1, DES.MODE_ECB)
    Crypt2 = DES.new(Key2, DES.MODE_ECB)

    plain1 = Crypt1.encrypt(Block1)
    plain2 = Crypt2.encrypt(Block2)

    return plain1 + plain2
