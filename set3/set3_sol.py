#!/usr/bin/python3
from set1.set1_sol import * 
from set2.set2_sol import * 
from set3.mt19937 import MT19937
import random, string, struct, operator
from typing import Callable
from spellchecker import SpellChecker
from numpy import random

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

plaintexts19 = [
b'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
b'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
b'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
b'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
b'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
b'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
b'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
b'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
b'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
b'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
b'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
b'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
b'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
b'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
b'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
b'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
b'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
b'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
b'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
b'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
b'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
b'U2hlIHJvZGUgdG8gaGFycmllcnM/',
b'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
b'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
b'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
b'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
b'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
b'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
b'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
b'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
b'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
b'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
b'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
b'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
b'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
b'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
b'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
b'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
b'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=' ]

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
    if (excess > 0):
        to_encrypt = plaintext[-excess:]
        keystream_block = encrypt_aes_ecb(nonce + struct.pack('<Q', counter), key)
        encrypted += xor_bytes(to_encrypt, keystream_block[:excess])
    return encrypted

def encrypt_same_nonce_ctr(plaintexts: list) -> list:
    if not isinstance(plaintexts, list):
        raise TypeError
    nonce = b'\x00' * 8
    ciphertexts = []
    for plaintext in plaintexts:
        plaintext = base64.b64decode(plaintext)
        ciphertext = encrypt_aes_ctr(plaintext, key, nonce)
        ciphertexts.append(ciphertext)
    return ciphertexts

def decrypt_same_nonce_ctr(ciphertexts: list) -> list:
    if not isinstance(ciphertexts, list):
        raise TypeError
    max_len = len(max(ciphertexts, key=len))
    score_list = [0] * max_len
    for i in range(max_len): 
        scores = {}
        for j in range(256):
            scores[j] = 0
        score_list[i] = scores
    best = [0] * max_len
    plaintexts = [b''] * len(ciphertexts)
    for ciphertext in ciphertexts:
        for pos, c in enumerate(ciphertext):
            for i in range(256):
                cand = chr(c ^ i)
                if cand.upper() in letterFrequency: 
                    score_list[pos][i] += letterFrequency.get(cand.upper())
    for i, score in enumerate(score_list):
        best[i] = max(score.items(), key=operator.itemgetter(1))[0]
    for i, ct in enumerate(ciphertexts):
        for pos, c in enumerate(ct):
            decrypted_char = chr((c ^ best[pos])).lower()
            if decrypted_char < hex(0xc0):
                decrypted_char = '\x20'
            plaintexts[i] += bytes(decrypted_char, 'utf-8')
    # spellchecker = SpellChecker()
    # for i, plaintext in enumerate(plaintexts):
    #     plaintext = plaintext.decode('utf-8')
    #     spellchecked_pt = ''
    #     for word in plaintext.split(' '):
    #         new_word = word
    #         if len(word) > 1:
    #             new_word = spellchecker.correction(word) + ' '
    #         spellchecked_pt += new_word
    #     plaintexts[i] = bytes(spellchecked_pt, 'utf-8')
    return plaintexts

if __name__ == '__main__':
    # Challenge 21
    rand = MT19937(123)
    npr = random.RandomState(123)
    for i in range(10):
        if rand.extract_number() != npr.randint(2**32):
            raise Exception('Wrong generated random number')

    # Challenge 20
    # pt_file = open('set3/20.txt', 'r') 
    # plaintexts = pt_file.read().splitlines()
    # ciphertexts = encrypt_same_nonce_ctr(plaintexts)
    # plaintexts = decrypt_same_nonce_ctr(ciphertexts)
    # for plaintext in plaintexts:
    #     print(plaintext)

    # Challenge 19
    # ciphertexts = encrypt_same_nonce_ctr(plaintexts19)
    # plaintexts = decrypt_same_nonce_ctr(ciphertexts)
    # for plaintext in plaintexts:
    #     print(plaintext)

    # Challenge 18
    # key = b'YELLOW SUBMARINE'
    # encrypted = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    # decrypted = decrypt_aes_ctr(encrypted, key, b'\x00' * 8)
    # print(decrypted)
    # encrypted = encrypt_aes_ctr(decrypted, key, b'\x00' * 8)
    # encrypted = base64.b64encode(encrypted)
    # print(encrypted)

    # Challenge 17
    # encrypted, iv = encrypt_random_string_cbc()
    # decrypted = attack_padding_oracle_cbc(encrypted, iv)
    # print(decrypted)
    # decrypted = decrypt_aes_cbc(encrypted, key, iv)
    # print(decrypted)

