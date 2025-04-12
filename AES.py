import os
from Crypto.Cipher import AES

key_size = 16

def xor(bstring, key):
    if len(key) < len(bstring):
        scaledKey = (key * (len(bstring)//len(key) + 1))[:len(bstring)]
        return bytes(a ^ b for a, b in zip(bstring, scaledKey))
    else:
        return bytes(a ^ b for a, b in zip(bstring, key))
    
# just reuse padding oracle attack here
# chose not to use ECB mode because it
# key is 128 bits of all 1's
def AES_encrypt(plaintext):
    
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.encrypt(plaintext)

