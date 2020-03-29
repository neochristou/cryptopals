#!/usr/bin/python3
from set1.set1_sol import * 

def pkcs7_pad(text_bytes, size):
    padding_size = size - (len(text_bytes) % size)
    if padding_size == 0:
        return text_bytes
    padding_bytes = (padding_size * chr(padding_size)).encode()
    return text_bytes + padding_bytes

def encrypt_aes_ecb(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def decrypt_aes_cbc(ciphertext, key, iv):
    plaintext = b""
    prev_cipher_block = iv 
    for i in range(0, len(ciphertext), 16):
        cipher_block = ciphertext[i:i+16]
        dec_block = decrypt_aes_ecb(cipher_block, key)
        plain_block = xor_bytes(dec_block, prev_cipher_block)
        prev_cipher_block = cipher_block
        plaintext += plain_block
    return plaintext

if __name__ == '__main__':
    # Challenge 10
    enc_file = open('set2/10.txt', 'r')
    enc_text = bytearray(enc_file.read(), 'utf-8')
    ciphertext = codecs.decode(enc_text, 'base64')
    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * 16
    plaintext = decrypt_aes_cbc(ciphertext, key, iv) 
    print(plaintext.decode('utf-8'))

    # Check ecb encryption
    # dec_file = open('set2/lyrics.txt', 'r')
    # plaintext = bytearray(dec_file.read(), 'utf-8')
    # key = b'YELLOW SUBMARINE'
    # ciphertext = encrypt_aes_ecb(plaintext[:len(plaintext)- len(plaintext) % 8], key) 
    # ciphertext = codecs.encode(ciphertext, 'base64')
    # print(ciphertext)

    # Challenge 9 
    # padded_bytes = pkcs7_pad(b'YELLOW SUBMARINE', 20)
    # print(padded_bytes)
