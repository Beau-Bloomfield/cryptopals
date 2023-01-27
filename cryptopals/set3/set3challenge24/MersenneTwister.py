# This is just all the stuff from the last exercise

class MersenneTwister(object):
    # First start with constants
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    f = 1812433253
    
    mt = [0] * n

    index = n+1
    lower_mask: int = (1 << r) - 1
    upper_mask: int = (~lower_mask) & sum( 0b1 << shift for shift in range(w) )
    
    def __init__(self, seed: int):
        mt = self.mt # just so I don't have to write self a bunch of times

        self.index = self.n
        mt[0] = seed
        for i in range(1, self.n):
            mt[i] = sum( 0b1 << shift for shift in range(self.w) ) & ( self.f * ( mt[i-1] ^ ( mt[i-1] >> (self.w-2) )) + 1 )
            
    def __twist__(self):
        mt = self.mt
        for i in range(self.n):
            x = ( mt[i] & self.upper_mask ) | ( mt[ (i+1) % self.n ] & self.lower_mask )
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.a
            mt[i] = mt[ (i+self.m) % self.n ] ^ xA
        self.index = 0
        
    def __call__(self):
        mt = self.mt
        
        if self.index >= self.n:
            if self.index > self.n:
                assert False, "Generator was never seeded"
            else:
                self.__twist__()
        
        y  =  mt[self.index]
        y  = Temper2(y)
        self.index += 1
    
        return y & sum( 0b1 << shift for shift in range(self.w) )
    
def Temper2(y: int):
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    
    y = SimpleTemper(y, bitshift = u,  mask = d)
    y = SimpleTemper(y, bitshift = -s, mask = b)
    y = SimpleTemper(y, bitshift = -t, mask = c)
    y = SimpleTemper(y, bitshift = l,  mask = ~0)
    
    return y

BITSHIFT = 7
MAXBITS = 32
MASK = 0x9D2C5680

def SimpleTemper(y: int, maxbits = MAXBITS, bitshift = BITSHIFT, mask = MASK):
    assert y < ( 0b1<<maxbits)
    assert bitshift < maxbits
    if bitshift > 0:
        y ^= ( y >> bitshift ) & mask
    elif bitshift < 0:
        y ^= ( y << -bitshift ) & mask
    else:
        assert False
    return y