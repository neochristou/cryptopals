#!/usr/bin/python3
from set1.set1_sol import * 
import random

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

# def generate_random_key():
#     key = bytearray(random.getrandbits(8) for _ in range(16)) 
#     return 

if __name__ == '__main__':
    # Challenge 11
    # key = generate_random_key()

    # Challenge 10
    enc_file = open('set2/10.txt', 'r')
    enc_text = bytearray(enc_file.read(), 'utf-8')
    ciphertext = codecs.decode(enc_text, 'base64')
    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * 16
    plaintext = decrypt_aes_cbc(ciphertext, key, iv) 
    print(plaintext.decode('utf-8'))

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
