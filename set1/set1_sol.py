#!/usr/bin/python3
import codecs
import base64
import string
import enchant
from Crypto.Cipher import AES

letterFrequency = {'E' : 12.0,
'T' : 9.10,
'A' : 8.12,
'O' : 7.68,
'I' : 7.31,
'N' : 6.95,
'S' : 6.28,
'R' : 6.02,
'H' : 5.92,
'D' : 4.32,
'L' : 3.98,
'U' : 2.88,
'C' : 2.71,
'M' : 2.61,
'F' : 2.30,
'Y' : 2.11,
'W' : 2.09,
'G' : 2.03,
'P' : 1.82,
'B' : 1.49,
'V' : 1.11,
'K' : 0.69,
'X' : 0.17,
'Q' : 0.11,
'J' : 0.10,
'Z' : 0.07 }

def hex_to_base64(hexstring: str) -> str:
    if not isinstance(hexstring, str):
        raise TypeError
    return codecs.encode(codecs.decode(hexstring, 'hex'), 'base64').decode()

def base64_to_hex(base64string):
    return base64.b64decode(base64string).hex()

def xor_bytes(bytes1: bytes, bytes2: bytes) -> bytes:
    if not isinstance(bytes1, bytes) or not isinstance(bytes2, bytes):
        raise TypeError
    if len(bytes1) != len(bytes2):
        raise Exception('Chunks must have the same length')
    xored = bytearray(bytes1)
    for i, b in enumerate(bytes2):
        xored[i] ^= b
    return xored 

def xor_hex(hexstring1, hexstring2):
    if len(hexstring1) != len(hexstring2):
        raise Exception('Strings must have the same length')
    hex1 = int(hexstring1, 16)
    hex2 = int(hexstring2, 16)
    return '{:x}'.format(hex1 ^ hex2)

def single_byte_xor(ciphertext: bytes, threshold: int, get_key = False) -> bytes:
    if not isinstance(ciphertext, bytes) or not isinstance(threshold, int):
        raise TypeError
    dictionary = enchant.Dict("en_US")
    string_scores = {}
    for i in range(256):
        xored_bytes = b''
        for byte in ciphertext:
            xored_bytes += bytes([byte ^ i])
        try:
            xored_str = xored_bytes.decode('utf-8')
            score = 0
            sentences = xored_str.split()
            for word in sentences:
                for c in word:
                    if c.upper() in letterFrequency:
                        score += letterFrequency.get(c.upper())
                    else:
                        score -= 5
                if word.isprintable() and dictionary.check(word) and len(word) > 1:
                    score += 10
            if score > threshold:
                string_scores[xored_str] = score
        except (UnicodeDecodeError, AttributeError):
            pass
    sorted_scores = sorted(string_scores, key=string_scores.get, reverse=True)
    if get_key:
        return ord(sorted_scores[0][0]) ^ ciphertext[0]
    final_list = ""
    final_list = '\n'.join(("[score: " + str(string_scores[sentence]) + "] " + sentence) for sentence in sorted_scores)
    return final_list

def find_xored_single_byte(lines: list, threshold: int) -> bytes:
    if not isinstance(lines, list) or not isinstance(threshold, int):
        raise TypeError
    all_sentences = ""
    for line in lines:
        line_sentences = single_byte_xor(bytes.fromhex(line), threshold)
        if len(line_sentences) > 0:
            all_sentences += line_sentences 
    return all_sentences

def encrypt_repeating_xor(plaintext: bytes, key: bytes):
    if not isinstance(plaintext, bytes) or not isinstance(key, bytes):
        raise TypeError
    length = len(plaintext)
    repeats = length // len(key)
    excess = length % len(key)
    keystream = key * repeats + key[:excess]
    ciphertext = b''
    plaintext_bytes = bytearray(plaintext)
    keystream_bytes = bytearray(keystream)
    for i in range(length):
        ciphertext += bytes([plaintext_bytes[i] ^ keystream_bytes[i]])
    return ciphertext

def decrypt_repeating_xor(ciphertext_bytes: bytes, log_info=False):
    if not isinstance(ciphertext_bytes, bytes):
        raise TypeError
    ciphertext = bytearray(ciphertext_bytes)
    min_dist = 100
    min_keysize = 100
    for keysize in range(2,40,1):
        samples = list()
        distances = 0
        blocks = len(ciphertext) // keysize
        for i in range(0, keysize * blocks, keysize):
            samples.append(ciphertext[i:i+keysize])
        for i in range(1,blocks - 1,1):
            distances += hamming(samples[0], samples[i])
        avg_dist = (distances/ blocks)/keysize
        if avg_dist < min_dist:
            min_dist = avg_dist
            min_keysize = keysize
    if log_info:
        print("Key size:", min_keysize, " [ score:" ,avg_dist, "]")
    blocks = {}
    for i in range(min_keysize):
        blocks[i] = []
    excess = len(ciphertext) % min_keysize
    for i in range(0,len(ciphertext) - excess, min_keysize):
        for j in range(min_keysize):
            blocks[j].append(ciphertext[i+j])
    for i in range(0, excess):
        blocks[i].append(ciphertext[-excess + i])
    key = []
    for i in range(min_keysize):
        block_str = ''.join(chr(c) for c in blocks[i])
        block_bytes = bytes(block_str, 'utf-8')
        key.append(single_byte_xor(block_bytes, 100, True))
    if log_info:
        key_text = ""
        for c in key:
            key_text += chr(c)
        print("Key: ", key_text)
    plaintext = ""
    for i in range(0,len(ciphertext) - excess, min_keysize):
        for j in range(min_keysize):
            plaintext += chr(ciphertext[i+j] ^ key[j])
    for i in range(0, excess):
            plaintext += chr(ciphertext[-excess + i] ^ key[i])
    return plaintext 

def hamming(str1: bytes, str2: bytes):
    if len(str1) != len(str2):
        raise Exception('Strings must have the same length')
    binary1 = ''.join(format(c, '08b') for c in str1)
    binary2 = ''.join(format(c, '08b') for c in str2)
    dist = 0
    for c1, c2 in zip(binary1, binary2):
        dist += (c1!=c2)
    return dist

def decrypt_aes_ecb(ciphertext: bytes, key: bytes):
    if not isinstance(ciphertext, bytes) or not isinstance(key, bytes):
        raise TypeError
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def detect_aes_ecb(ciphertext_bytes: bytes) -> bool:
    if not isinstance(ciphertext_bytes, bytes):
        raise TypeError
    ciphertext = ciphertext_bytes.decode('utf-8')
    block_list = []
    block_dict = {}
    for i in range(0, len(ciphertext), 32):
        block = ciphertext[i:i+32]
        block_list.append(block)
        block_dict[block] = None
    if len(block_list) == len(block_dict):
        return False
    else:
        return True

if __name__ == '__main__':
    # Challenge 8
    enc_file = open('set1/8.txt', 'r')
    lines = enc_file.read().splitlines()
    for line in lines:
        if (detect_aes_ecb(bytes(line,'utf-8'))):
            print("Detected AES ECB: ", line)

    # Challenge 7
    # enc_file = open('set1/7.txt', 'r')
    # enc_text = bytes(enc_file.read(), 'utf-8')
    # ciphertext = bytes(codecs.decode(enc_text, 'base64'))
    # key = b'YELLOW SUBMARINE'
    # plaintext = decrypt_aes_ecb(ciphertext, key).decode('utf-8')
    # print(plaintext)

    # Challenge 6
    # enc_file = open('set1/6.txt', 'r')
    # enc_text = enc_file.read()
    # enc_hex = base64_to_hex(enc_text)
    # enc_bytes = bytes.fromhex(enc_hex)
    # plaintext = decrypt_repeating_xor(enc_bytes, log_info=True)
    # print(plaintext)

    # Challenge 5
    # plaintext = b"Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
    # key = b"ICE"
    # encrypted = encrypt_repeating_xor(plaintext, key)
    # print(encrypted.hex())

    # Challenge 4
    # enc_file = open('set1/4.txt', 'r')
    # lines = enc_file.read().splitlines()
    # ct = []
    # for line in lines:
    #     ct.append(bytes.fromhex(line))
    # output = find_xored_single_byte(lines, 100)
    # print(str(output))

    # Challenge 3
    # ct = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    # output = single_byte_xor(ct, 100)
    # print(output)

    # Challenge 2
    # input1 = bytes.fromhex('686974207468652062756c6c277320657965')
    # input2 = bytes.fromhex('1c0111001f010100061a024b53535009181c')
    # output = xor_bytes(input1, input2)
    # print(output.hex())

    # Challenge 1
    # input_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d' 
    # print(hex_to_base64(input_str))

    
