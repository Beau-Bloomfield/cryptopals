from Crypto.Cipher import AES
from hashlib import sha1
from random import randint
from math import log as ln
from random import choices

BLOCKSIZE = 16
DEFAULT_g = 2
DEFAULT_p = int('ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
                'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
                '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
                '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
                '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
                'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
                'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
                'fffffffffffff', base = 16)
MAX_BYTES = 1 + int( ln(DEFAULT_p) / ln(2) ) // 8

def Pad(x):
    x = list(x)
    assert all( byte in range(256) for byte in x )
    pad = BLOCKSIZE - len(x) % BLOCKSIZE
    x += [pad]*pad
    assert len(x) % BLOCKSIZE == 0
    return bytes(x)

def Unpad(x):
    assert len(x) % BLOCKSIZE == 0
    assert all( byte in range(256) for byte in x )
    last = x[-1]
    assert list(x[-last:]) == [last]*last
    return bytes(x[:-last])

class DiffieHelmanCorrespondent(object):
    def __init__(self, p = DEFAULT_p, g = DEFAULT_g, privkey = None):
        self.g = g
        self.p = p
        self.__privkey__ = privkey if privkey is not None else randint(0, self.p-1)
        self.__pubkey__ = pow(self.g, self.__privkey__, self.p)
        
    def GetPubkey(self, key_format = int):
        assert key_format in {int, bytes}
        return self.__pubkey__ if key_format is int else self.__pubkey__.to_bytes(byteorder='big', length=BLOCKSIZE)
    
    def GenerateSessionKey(self, other_pubkey):
        assert type(other_pubkey) is int
        assert other_pubkey != self.GetPubkey(int)
        assert other_pubkey in range(1+self.p)
        self.__session_key__ = s = pow(other_pubkey, self.__privkey__, self.p)
        s_digest = sha1(s.to_bytes(byteorder='big', length=MAX_BYTES)).digest()
        self.__aes_key__ = s_digest[:BLOCKSIZE]
        
    def Encrypt(self, message):
        try:
            key = self.__aes_key__
        except Exception as e:
            print(e)
        iv = bytes(choices(range(256), k = BLOCKSIZE))
        cipher = AES.new(key, AES.MODE_CBC, iv = iv)
        plaintext = Pad(message)
        ciphertext = cipher.encrypt(plaintext)
        return ciphertext + iv
    
    def Decrypt(self, ciphertext):
        try:
            key = self.__aes_key__
        except Exception as e:
            print(e)
        ciphertext, iv = ciphertext[:-BLOCKSIZE], ciphertext[-BLOCKSIZE:]
        cipher = AES.new(key, AES.MODE_CBC, iv = iv)
        plaintext = cipher.decrypt(ciphertext)
        message = Unpad(plaintext)
        return message