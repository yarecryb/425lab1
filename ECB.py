
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def ecb(plaintext):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""
    index = 0
    block = b""

    while(index+16 < len(block)):
        block = plaintext[index:16]
        ciphertext += cipher.encrypt(block)
        index += 16

    if(len(block)%16 > 0):
        #last block is incomplete, pad it out
        bytes_to_pad = 16 - len(plaintext)
        for i in range(bytes_to_pad):
            plaintext += bytes([bytes_to_pad])
    else:
        #message length is a multiple of 16
        for i in range(16):
            plaintext += bytes([16])

    #encrypt the final block, which is either a padded block or just the number 16 16 times.
    ciphertext += cipher.encrypt(plaintext[index:])
    return cipher, ciphertext

if __name__ == '__main__':
    plaintext = b"this message repthis message repthis message repthis message repthis message rep"
    cipher, ciphertext = ecb(plaintext)
    print(ciphertext)

    decrypted = cipher.decrypt(ciphertext)
    print(decrypted)

    ciphertext_modified = bytearray(ciphertext)
    ciphertext_modified[0] = 0
    ciphertext_modified[1] = 1
    ciphertext_modified[2] = 1
    decrypted_modified_ciphertext = cipher.decrypt(ciphertext_modified)
    print(decrypted_modified_ciphertext)