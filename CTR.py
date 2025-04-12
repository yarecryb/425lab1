from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def ctr(plaintext):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(plaintext)
    return key, nonce, ciphertext 

if __name__ == '__main__':
    plaintext = b"this message repthis message repthis message repthis message repthis message rep"
    key, nonce, ciphertext = ctr(plaintext)
    print(ciphertext)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)
    print("printing decrypted")
    print(decrypted)

    ciphertext_modified = bytearray(ciphertext)
    ciphertext_modified[0] = 0
    ciphertext_modified[1] = 1
    ciphertext_modified[2] = 1
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted_modified_ciphertext = cipher.decrypt(ciphertext_modified)
    print(decrypted_modified_ciphertext)