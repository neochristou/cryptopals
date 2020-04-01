#!/usr/bin/python3
from set1.set1_sol import * 
import random
import string

def pkcs7_pad(text_bytes: bytes, size: int) -> bytes:
    if not isinstance(text_bytes, bytes) or not isinstance(size, int):
        raise TypeError
    padding_size = size - (len(text_bytes) % size)
    if padding_size == 0:
        return text_bytes
    padding_bytes = (padding_size * chr(padding_size)).encode()
    return text_bytes + padding_bytes

def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    if not isinstance(plaintext, bytes) or not isinstance(key, bytes):
        raise TypeError
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if not isinstance(plaintext, bytes) or not isinstance(key, bytes) or not isinstance(iv, bytes):
        raise TypeError
    ciphertext = b''
    prev_cipher_block = iv
    excess = len(plaintext) % 16
    for i in range(0, len(plaintext) - excess, 16):
        plain_block = plaintext[i:i+16]
        xored_block = xor_bytes(prev_cipher_block, plain_block)
        cipher_block = encrypt_aes_ecb(xored_block, key)
        ciphertext += cipher_block
        prev_cipher_block = cipher_block
    if excess != 0:
        plain_block = plaintext[-excess:]
        plain_block = pkcs7_pad(plain_block, 16)
        xored_block = xor_bytes(prev_cipher_block, plain_block)
        cipher_block = encrypt_aes_ecb(xored_block, key)
        ciphertext += cipher_block
    return ciphertext

def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if not isinstance(ciphertext, bytes) or not isinstance(key, bytes) or not isinstance(iv, bytes):
        raise TypeError
    plaintext = b''
    prev_cipher_block = iv 
    for i in range(0, len(ciphertext), 16):
        cipher_block = ciphertext[i:i+16]
        dec_block = decrypt_aes_ecb(cipher_block, key)
        plain_block = xor_bytes(dec_block, prev_cipher_block)
        prev_cipher_block = cipher_block
        plaintext += plain_block
    return plaintext

def generate_random_bytes(size: int) -> bytes:
    if not isinstance(size, int):
        raise TypeError
    rand = bytearray(random.getrandbits(8) for _ in range(size)) 
    return bytes(rand)

def encryption_oracle(plaintext: bytes) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError
    key = generate_random_bytes(16)
    pre_pad_size = random.randint(5,10)
    pre_pad = generate_random_bytes(pre_pad_size)
    pad_size = random.randint(5,10)
    pad = generate_random_bytes(pad_size)
    rand = random.randint(0,1)
    plaintext = pre_pad + plaintext + pad
    plaintext = pkcs7_pad(plaintext, 16)
    ciphertext = b''
    if rand == 0:
        ciphertext = encrypt_aes_cbc(plaintext, key, generate_random_bytes(16))
    else:
        ciphertext = encrypt_aes_ecb(plaintext, key)
    return ciphertext

def detect_mode(ciphertext_base64: bytes) -> str:
    if not isinstance(ciphertext_base64, bytes):
        raise TypeError
    ciphertext = base64.b64decode(ciphertext_base64)
    if detect_aes_ecb(ciphertext):
        return 'ECB'
    else:
        return 'CBC'

def ecb_oracle(plaintext: bytes, key: bytes) -> bytes:
    if not isinstance(plaintext, bytes) or not isinstance(key, bytes):
        raise TypeError
    unknown_str = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    plaintext = plaintext + unknown_str
    plaintext =  pkcs7_pad(plaintext, 16)
    ciphertext = b''
    ciphertext = encrypt_aes_ecb(plaintext, key)
    return ciphertext

def detect_block_size(key: bytes) -> int:
    if not isinstance(key, bytes):
        raise TypeError
    plaintext = b'A'
    first_hit = False
    first_hit_len = 0
    ciphertext = ecb_oracle(plaintext, key)
    prev_cipher_len = len(ciphertext)
    while not first_hit:
        first_hit_len += 1
        ciphertext = ecb_oracle(plaintext, key)
        cipher_len = len(ciphertext)
        if cipher_len > prev_cipher_len:
            first_hit = True
        prev_cipher_len = cipher_len
        plaintext += b'A'
    while True:
        ciphertext = ecb_oracle(plaintext, key)
        cipher_len = len(ciphertext)
        if cipher_len > prev_cipher_len:
            return len(plaintext) - first_hit_len
        else:
            prev_cipher_len = cipher_len
            plaintext += b'A'

def ecb_decrypt_byte_at_a_time(key: bytes) -> bytes:
    if not isinstance(key, bytes):
        raise TypeError
    block_size = detect_block_size(key)
    ciphertext = ecb_oracle(b'A' * 50, key)
    ciphertext = codecs.encode(ciphertext, 'base64').decode('utf-8')
    mode = detect_mode(bytes(ciphertext, 'utf-8'))
    if mode != 'ECB':
        raise Exception('Can only decrypt ECB mode')
    encrypted_secret = ecb_oracle(b'', key)
    encrypted_secret_len = len(encrypted_secret)
    total_blocks = encrypted_secret_len // block_size # Find out how many block the encrypted secret is by itself
    decrypted_text = b''
    target_position = (total_blocks - 1) * block_size # We will be decrypting the block where our input ends
    pre_appended_input = target_position * b'A' + b'A' * (block_size - 1) # Append A's and decrease each time we reveal a character 
    for curr_block in range(total_blocks):
        decrypted_block = b''
        for i in range(block_size):
            target = ecb_oracle(pre_appended_input, key)[target_position:target_position+ 16] # The block we want to match
            for c in string.printable:
                plaintext_pad = (target_position - (curr_block * 16)) * b'A' + b'A' * (block_size - 1 - i) + decrypted_text + decrypted_block + bytes(c, 'utf-8') # Same as target, except last character (brute force it)
                output_block = ecb_oracle(plaintext_pad, key)[target_position:target_position+ 16]
                if target == output_block: # Check if output matches target until we get the correct character
                    decrypted_block += bytes(c, 'utf-8')
                    break
            pre_appended_input = pre_appended_input[:-1]
        decrypted_text += decrypted_block
    return decrypted_text
    
if __name__ == '__main__':
    # Challenge 12
    key = generate_random_bytes(16)
    decrypted = ecb_decrypt_byte_at_a_time(key)
    print(decrypted.decode('utf-8'))

    # Challenge 11
    # plaintext = b'A' * 50
    # ciphertext = encryption_oracle(plaintext) 
    # ciphertext = codecs.encode(ciphertext, 'base64').decode('utf-8')
    # mode = detect_mode(bytes(ciphertext, 'utf-8'))
    # print(mode)

    # Challenge 10
    # enc_file = open('set2/10.txt', 'r')
    # enc_text = bytearray(enc_file.read(), 'utf-8')
    # ciphertext = codecs.decode(enc_text, 'base64')
    # key = b'YELLOW SUBMARINE'
    # iv = b'\x00' * 16
    # plaintext = decrypt_aes_cbc(ciphertext, key, iv) 
    # print(plaintext.decode('utf-8'))

    # Check cbc encryption
    # dec_file = open('set2/decrypted.txt', 'r')
    # plaintext = bytes(dec_file.read(), 'utf-8')
    # key = b'YELLOW SUBMARINE'
    # iv = b'\x00' * 16
    # ciphertext = encrypt_aes_cbc(plaintext, key, iv)
    # ciphertext = codecs.encode(ciphertext, 'base64').decode('utf-8')
    # print(ciphertext)

    # Check ecb encryption
    # dec_file = open('set2/lyrics.txt', 'r')
    # plaintext = bytes(dec_file.read(), 'utf-8')
    # key = b'YELLOW SUBMARINE'
    # ciphertext = encrypt_aes_ecb(plaintext[:len(plaintext)- len(plaintext) % 8], key) 
    # ciphertext = codecs.encode(ciphertext, 'base64').decode('utf-8')
    # print(ciphertext)

    # Challenge 9 
    # padded_bytes = pkcs7_pad(b'YELLOW SUBMARINE', 20)
    # print(padded_bytes)
