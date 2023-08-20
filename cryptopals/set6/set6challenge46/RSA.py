# Ok so first of all the instructions here (https://cryptopals.com/sets/5/challenges/39) leave a lot out
# And the exercise doesn't work if you follow the instructions specifically... they leave out a lot about the totient function
# I followed Wikipedia instead (https://en.m.wikipedia.org/wiki/RSA_(cryptosystem))

BIT_STRENGTH = 1024

from Crypto.Util.number import getPrime
Prime = ( lambda x = BIT_STRENGTH: getPrime(x) )

# Using implementations from https://github.com/ricpacca/cryptopals/blob/master/S5C39.py

def GCD(a, b):
    """Computes the greatest common divisor between a and b using the Euclidean algorithm."""
    while b != 0:
        a, b = b, a % b

    return a


def LCM(a, b):
    """Computes the lowest common multiple between a and b using the GCD method."""
    return a // GCD(a, b) * b


def ModInv(a, n):
    """Computes the multiplicative inverse of a modulo n using the extended Euclidean algorithm."""
    t, r = 0, n
    new_t, new_r = 1, a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n

    return t

assert ModInv(17, 3120) == 2753

# Let e be 3
e = 3

# The requirement regarding GCD is specified in Wikipedia, NOT the challenge itself

def GeneratePrimes(e = e):
    while True:
        p, q = Prime(), Prime()
        n = p*q
        et = LCM(p-1, q-1) % n

        if 2 < e < et and GCD(e, et) == 1:
            return p, q, et

p, q, et = GeneratePrimes()

class RSAServer(object):
    def __init__(self, e = 3):
        self.e = e
        p, q, et = GeneratePrimes(e)
        self.p = p
        self.q = q
        self.d = ModInv(e, et)
        self.n = p*q
        
    def GetPubkey(self):
        return dict(e = self.e, n = self.n)
    
    def DecryptBytes(self, c):
        m = pow(c, self.d, self.n)
        return m.to_bytes(byteorder='big', length = 2*BIT_STRENGTH//8).replace(b'\0', b'')
    
    def DecryptInt(self, c):
        m = pow(c, self.d, self.n)
        return m
    
    Decrypt = DecryptBytes

class RSAClient(object):
    def __init__(self, e, n):
        self.e = e
        self.n = n
        
    def Encrypt(self, message):
        m = message if type(message) is int else int.from_bytes(message, byteorder = 'big')
        assert m < self.n
        return pow(m, self.e, self.n)