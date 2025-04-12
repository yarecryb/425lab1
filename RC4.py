# key is 40 bits of all 1's

def xor(bstring, key):
    if len(key) < len(bstring):
        scaledKey = (key * (len(bstring)//len(key) + 1))[:len(bstring)]
        return bytes(a ^ b for a, b in zip(bstring, scaledKey))
    else:
        return bytes(a ^ b for a, b in zip(bstring, key))
    
key = bytes(bytes.fromhex('ff') * 5)

# Psuedo code from https://en.wikipedia.org/wiki/RC4
def ksa(key: bytes):
    keylength = len(key)
    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        S[i], S[j] = S[j], S[i]

    return S

def prga(S, length):
    i = 0
    j = 0
    keystream = []

    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)

    return keystream

def decrypt_unknown_plaintext(unknown_cipher):
    known_plaintext = b"this is the known plaintext for this"
    length = len(known_plaintext)

    S = ksa(key)

    keystream = prga(S.copy(), length)
    ciphertext = xor(known_plaintext, keystream)

    plaintext = xor(xor(known_plaintext, unknown_cipher), ciphertext)
    print(plaintext)

def main():
    plaintext = b"this is the wireless security lab"
    length = len(plaintext)

    S = ksa(key)

    keystream = prga(S.copy(), length)

    # XOR plaintext bytes with keysteam bytes
    ciphertext = xor(plaintext, keystream)
    decrypt_unknown_plaintext(ciphertext)
    
    print("Plaintext :", plaintext)
    print("Ciphertext:", bytes.fromhex(ciphertext.hex()))


if __name__ == '__main__':
    main()