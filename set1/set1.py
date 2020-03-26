#!/usr/bin/python3
import codecs
import binascii
import string
import enchant

def hex_to_base64(hexstring):
    return codecs.encode(codecs.decode(hexstring, 'hex'), 'base64').decode()

def xor_hex(hexstring1, hexstring2):
    if len(hexstring1) != len(hexstring2):
        raise Exception('Strings must have the same length')
    hex1 = int(hexstring1, 16)
    hex2 = int(hexstring2, 16)
    return '{:x}'.format(hex1 ^ hex2)

def single_byte_xor(hexstring):
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
                if word.isprintable() and dictionary.check(word) and len(word) > 1:
                    score += 1
            if score > 1:
                string_scores[xored_str] = score
        except (UnicodeDecodeError, AttributeError):
            pass
    final_list = ""
    final_list = '\n'.join(("[score: " + str(string_scores[sentence]) + "] " + sentence) for sentence in sorted(string_scores, key=string_scores.get, reverse=True))
    return final_list

def find_xored_single_byte(lines):
    all_sentences = ""
    for line in lines:
        line_sentences = single_byte_xor(line)
        if len(line_sentences) > 0:
            all_sentences += line_sentences 
    return all_sentences

if __name__ == '__main__':
    # Challenge 4
    enc_file = open('4.txt', 'r')
    lines = enc_file.read().splitlines()
    print(find_xored_single_byte(lines))

    # Challenge 3
    # print(single_byte_xor('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))

    # Challenge 2
    # input1 = '686974207468652062756c6c277320657965'
    # input2 = '1c0111001f010100061a024b53535009181c'
    # print(xor_hex(input1, input2))

    # Challenge 1
    # input_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d' 
    # print(hex_to_base64(input_str))

    
