#!/usr/bin/python3
from set1.set1_sol import * 
from set2.set2_sol import * 
import random, string, struct
from typing import Callable

key = generate_random_bytes(16)
strings_to_encrypt = [b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc='
b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93' ]

def encrypt_random_string_cbc() -> bytes:
    iv = generate_random_bytes(16)
    rand_pos = random.randint(0, len(strings_to_encrypt) - 1)
    string = strings_to_encrypt[rand_pos]
    string = base64.b64decode(string)
    string = pkcs7_pad(string, 16)
    encrypted = encrypt_aes_cbc(string, key, iv)
    return encrypted, iv

def decrypt_and_validate_padding(ciphertext: bytes, iv: bytes) -> bool:
    if not isinstance(ciphertext, bytes) or not isinstance(iv, bytes):
        raise TypeError
    plaintext = decrypt_aes_cbc(ciphertext, key, iv)
    try: 
        pkcs7_pad_validate(plaintext)
    except Exception:
        return False
    return True

def decrypt_block_padding_oracle(first_block: bytes, second_block: bytes, iv: bytes) -> bytes:
    if not isinstance(first_block, bytes) or not isinstance(second_block, bytes) or not isinstance(iv, bytes):
        raise TypeError
    block_size = 16
    decrypted_block = [0] * block_size
    for pos in range(block_size):
        correct_pad_byte = pos + 1
        fake_block = bytearray(first_block)
        original_byte = first_block[block_size - pos - 1]
        for i in range(pos):
            fake_block[block_size - i - 1] ^= decrypted_block[block_size - i - 1]
            fake_block[block_size - i - 1] ^= correct_pad_byte
        for byte in range(256):
            fake_block[block_size - pos - 1] = byte
            valid = decrypt_and_validate_padding(bytes(fake_block) + second_block, iv)
            if valid:
                target = byte ^ correct_pad_byte ^ original_byte
                decrypted_block[block_size - pos - 1] = target
                break
    return bytes(decrypted_block)
    
def attack_padding_oracle_cbc(ciphertext: bytes, iv: bytes) -> bytes:
    if not isinstance(ciphertext, bytes) or not isinstance(iv, bytes):
        raise TypeError
    decrypted = b''
    block_size = 16
    blocks = len(ciphertext) // block_size
    for i in range(0, blocks - 1, 1):
        first_block = ciphertext[i * block_size: (i+1) * block_size]
        second_block = ciphertext[(i+1) * block_size: (i+2) * block_size]
        decrypted += decrypt_block_padding_oracle(first_block, second_block, iv)
    return decrypted

def decrypt_aes_ctr(ciphertext: bytes, key: bytes, nonce: bytes):
    if not isinstance(ciphertext, bytes) or not isinstance(key, bytes) or not isinstance(nonce,bytes):
        raise TypeError
    counter = 0
    block_size = 16
    decrypted = b''
    blocks = len(ciphertext) // block_size
    for i in range(blocks):
        to_decrypt = ciphertext[i * block_size: (i+1) * block_size]
        keystream_block = encrypt_aes_ecb(nonce + struct.pack('<Q', counter), key)
        counter += 1
        decrypted += xor_bytes(to_decrypt, keystream_block)
    excess = len(ciphertext) - blocks * block_size
    to_decrypt = ciphertext[-excess:]
    keystream_block = encrypt_aes_ecb(nonce + struct.pack('<Q', counter), key)
    decrypted += xor_bytes(to_decrypt, keystream_block[:excess])
    return decrypted

def encrypt_aes_ctr(plaintext: bytes, key: bytes, nonce: bytes):
    if not isinstance(plaintext, bytes) or not isinstance(key, bytes) or not isinstance(nonce,bytes):
        raise TypeError
    counter = 0
    block_size = 16
    encrypted = b''
    blocks = len(plaintext) // block_size
    for i in range(blocks):
        to_encrypt = plaintext[i * block_size: (i+1) * block_size]
        keystream_block = encrypt_aes_ecb(nonce + struct.pack('<Q', counter), key)
        counter += 1
        encrypted += xor_bytes(to_encrypt, keystream_block)
    excess = len(plaintext) - blocks * block_size
    to_encrypt = plaintext[-excess:]
    keystream_block = encrypt_aes_ecb(nonce + struct.pack('<Q', counter), key)
    encrypted += xor_bytes(to_encrypt, keystream_block[:excess])
    return encrypted

if __name__ == '__main__':
    # Challenge 18
    key = b'YELLOW SUBMARINE'
    encrypted = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    decrypted = decrypt_aes_ctr(encrypted, key, b'\x00' * 8)
    print(decrypted)
    encrypted = encrypt_aes_ctr(decrypted, key, b'\x00' * 8)
    encrypted = base64.b64encode(encrypted)
    print(encrypted)

    # Challenge 17
    # encrypted, iv = encrypt_random_string_cbc()
    # decrypted = attack_padding_oracle_cbc(encrypted, iv)
    # print(decrypted)
    # decrypted = decrypt_aes_cbc(encrypted, key, iv)
    # print(decrypted)

