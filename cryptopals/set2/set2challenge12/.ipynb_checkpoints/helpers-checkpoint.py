from Crypto.Cipher import AES

def Chunkerize(x, chunksize, strict = True):
    x = list(x)
    assert len(x) % chunksize == 0 if strict else True
    for n in range( len(x) // chunksize ):
        yield x[ n*chunksize : (n+1)*chunksize ]
        
def PadPlaintext(plaintext: bytes, blocksize = 16):
    npad = blocksize - len(plaintext) % blocksize
    return plaintext + bytes([npad]) * ( npad % blocksize )

def XOR(X: bytes, Y: bytes) -> bytes:
    assert type(X) is bytes and type(Y) is bytes and len(X) == len(Y)
    return bytes([ x^y for x, y in zip(X, Y) ])

def EncryptCBC(plaintext, key, initialization):
    BLOCKSIZE = 16
    plaintext = PadPlaintext(plaintext, BLOCKSIZE)
    assert type(initialization) is bytes and len(initialization) == BLOCKSIZE
    ECBcipher = AES.new(key, AES.MODE_ECB)
    
    plain_blocks = [ bytes(block) for block in Chunkerize(plaintext, BLOCKSIZE) ]
    cipher_blocks = [None] * len(plain_blocks)
    
    for n in range(len(plain_blocks)):
        if n == 0:
            plain_block = XOR(plain_blocks[n], initialization)
            cipher_blocks[n] = ECBcipher.encrypt(plain_block)
        else:
            plain_block = XOR(plain_blocks[n], cipher_blocks[n-1])
            cipher_blocks[n] = ECBcipher.encrypt(plain_block)
    
    return b''.join(cipher_blocks)

def DecryptCBC(ciphertext, key, initialization):
    BLOCKSIZE = 16
    assert len(ciphertext) % BLOCKSIZE == 0
    assert type(initialization) is bytes and len(initialization) == BLOCKSIZE
    ECBcipher = AES.new(key, AES.MODE_ECB)
    
    cipher_blocks = [ bytes(block) for block in Chunkerize(ciphertext, BLOCKSIZE) ]
    plain_blocks = [None] * len(cipher_blocks)
    
    for n in range(len(plain_blocks)):
        if n == 0:
            plain_block = ECBcipher.decrypt(cipher_blocks[n])
            plain_blocks[n] = XOR(plain_block, initialization)
        else:
            plain_block = ECBcipher.decrypt(cipher_blocks[n])
            plain_blocks[n] = XOR(plain_block, cipher_blocks[n-1])
            
    plaintext = b''.join(plain_blocks)
    last = plaintext[-1]
    
    if all( char == last for char in plaintext[-last:] ):
        return plaintext[:-last]
    else:
        return plaintext
    
def EncryptECB(plaintext, key):
    BLOCKSIZE = 16
    plaintext = PadPlaintext(plaintext, BLOCKSIZE)
    ECBcipher = AES.new(key, AES.MODE_ECB)
    blocks = [ bytes(block) for block in Chunkerize(plaintext, BLOCKSIZE) ]
    return b''.join( ECBcipher.encrypt(block) for block in blocks )

def DecryptECB(ciphertext, key):
    ECBcipher = AES.new(key, AES.MODE_ECB)
    return ECBcipher.decrypt(ciphertext)