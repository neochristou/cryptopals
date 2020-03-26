#!/usr/bin/python3
import codecs
import base64
import string
import enchant

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

def hex_to_base64(hexstring):
    return codecs.encode(codecs.decode(hexstring, 'hex'), 'base64').decode()

def base64_to_hex(base64string):
    return base64.b64decode(base64string).hex()

def xor_hex(hexstring1, hexstring2):
    if len(hexstring1) != len(hexstring2):
        raise Exception('Strings must have the same length')
    hex1 = int(hexstring1, 16)
    hex2 = int(hexstring2, 16)
    return '{:x}'.format(hex1 ^ hex2)

def single_byte_xor(hexstring, threshold):
    dictionary = enchant.Dict("en_US")
    hexnum = bytes.fromhex(hexstring)
    string_scores = {}
    for i in range(256):
        xored_bytes = b''
        for byte in hexnum:
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
    final_list = ""
    final_list = '\n'.join(("[score: " + str(string_scores[sentence]) + "] " + sentence) for sentence in sorted(string_scores, key=string_scores.get, reverse=True))
    return final_list

def find_xored_single_byte(lines, threshold):
    all_sentences = ""
    for line in lines:
        line_sentences = single_byte_xor(line, threshold)
        if len(line_sentences) > 0:
            all_sentences += line_sentences 
    return all_sentences

def encrypt_repeating_xor(plaintext, key):
    length = len(plaintext)
    repeats = length // len(key)
    excess = length % len(key)
    keystream = key * repeats + key[:excess]
    ciphertext = b''
    plaintext_bytes = bytearray(plaintext, 'utf-8')
    keystream_bytes = bytearray(keystream, 'utf-8')
    for i in range(length):
        ciphertext += bytes([plaintext_bytes[i] ^ keystream_bytes[i]])
    return ciphertext.hex()

def decrypt_repeating_xor(ciphertext_hex):
    ciphertext = bytearray.fromhex(ciphertext_hex).decode('utf-8')
    min_dist = 100
    min_keysize = 100
    for keysize in range(2,40,1):
        samples = list()
        distances = 0
        for i in range(0, 4 * keysize, keysize):
            samples.append(ciphertext[i:i+keysize])
        for i in range(1,4,1):
            distances += hamming(samples[0], samples[i])
        avg_dist = (distances/3)/keysize
        if avg_dist < min_dist:
            min_dist = avg_dist
            min_keysize = keysize
    #TODO



def hamming(str1, str2):
    if len(str1) != len(str2):
        raise Exception('Strings must have the same length')
    binary1 = ''.join(format(ord(c), '08b') for c in str1)
    binary2 = ''.join(format(ord(c), '08b') for c in str2)
    dist = 0
    for c1, c2 in zip(binary1, binary2):
        dist += (c1!=c2)
    return dist

if __name__ == '__main__':
    # Challenge 6
    # enc_file = open('6.txt', 'r')
    # enc_text = enc_file.read()
    # enc_hex = base64_to_hex(enc_text)
    # decrypt_repeating_xor(enc_hex)

    # Challenge 5
    # plaintext = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
    # key = "ICE"
    # encrypted = encrypt_repeating_xor(plaintext, key)
    # print(encrypted)

    # Challenge 4
    enc_file = open('4.txt', 'r')
    lines = enc_file.read().splitlines()
    print(find_xored_single_byte(lines, 100))

    # Challenge 3
    # print(single_byte_xor('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736', 100))

    # Challenge 2
    # input1 = '686974207468652062756c6c277320657965'
    # input2 = '1c0111001f010100061a024b53535009181c'
    # print(xor_hex(input1, input2))

    # Challenge 1
    # input_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d' 
    # print(hex_to_base64(input_str))

    
