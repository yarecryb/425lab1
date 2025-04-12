from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def xor(bstring, key):
    if len(key) < len(bstring):
        scaledKey = (key * (len(bstring)//len(key) + 1))[:len(bstring)]
        return bytes(a ^ b for a, b in zip(bstring, scaledKey))
    else:
        return bytes(a ^ b for a, b in zip(bstring, key))
    

key = bytes(bytes.fromhex('ff') * 16)

iv = get_random_bytes(16)
plaintext_secret = b"this is a secret message"

def get_ciphertext():
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext_secret, AES.block_size)
    return iv + cipher.encrypt(padded)

def is_valid_padding(ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = cipher.decrypt(ciphertext)
        unpad(decrypted, 16)
        return True
    except ValueError:
        return False

def guess_byte(c, bytes_left, c_pad, pointer):
    b = b'\x00'
    while True:
        i = int.from_bytes(b)
        i += 1
        b = i.to_bytes(1)
        new_second_to_last = (b'\x00' * bytes_left) + b + c_pad
        new_c = c[0:len(c) - pointer] + new_second_to_last + c[len(c) - (pointer - 16):len(c) - (pointer - 32)]
        if is_valid_padding(new_c):
            return b

def main():
    ciphertext = get_ciphertext()
    print("Ciphertext:", ciphertext)

    ciphertext_in_bytes = ciphertext

    # Decrypted plaintext
    p = b''
    d = b''

    # Start with the second-to-last block (pointer to start of the previous block)
    pointer = 32

    while pointer <= len(ciphertext_in_bytes):
        bytes_left = 15
        pad = b'\x01'
        c_pad = b''
        prev_block = ciphertext_in_bytes[len(ciphertext_in_bytes) - pointer:]

        for _ in range(16):
            b = guess_byte(ciphertext_in_bytes, bytes_left, c_pad, pointer)

            dCurrent = xor(pad, b)
            pCurrent = xor(dCurrent, prev_block[bytes_left].to_bytes(1))
            p = pCurrent + p
            d = dCurrent + d

            # Update pad value
            i = int.from_bytes(pad)
            i += 1
            pad = i.to_bytes(1)

            c_pad = b''
            bytes_left -= 1
            for j in range(0, 16 - bytes_left - 1):
                dByte = d[j].to_bytes(1)
                dnext = xor(pad, dByte)
                c_pad += dnext

        pointer += 16

    print("\nRecovered (raw):", p)
    try:
        unpadded = unpad(p, 16)
        print("Recovered (unpadded):", unpadded.decode('utf-8'))
    except Exception as e:
        print("Failed to unpad or decode:", e)


if __name__ == "__main__":
    main()