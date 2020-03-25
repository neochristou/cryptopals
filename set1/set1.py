#!/usr/bin/python3
import codecs
import binascii

def hex_to_base64(hexstring):
    return codecs.encode(codecs.decode(hexstring, 'hex'), 'base64').decode()

def xor_hex(str1, str2):
    if len(str1) != len(str2):
        raise Exception('Strings must have the same length')
    hex1 = int(str1, 16)
    hex2 = int(str2, 16)
    return '{:x}'.format(hex1 ^ hex2)

if __name__ == '__main__':
    # input_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d' 
    # print(hex_to_base64(input_str))
    # input1 = '686974207468652062756c6c277320657965'
    # input2 = '1c0111001f010100061a024b53535009181c'
    # print(xor_hex(input1, input2))
    
