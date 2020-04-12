#!/usr/bin/python3
from set1.set1_sol import * 
import random
import string
from typing import Callable

def pkcs7_pad(text_bytes: bytes, size: int) -> bytes:
    if not isinstance(text_bytes, bytes) or not isinstance(size, int):
        raise TypeError
    padding_size = size - (len(text_bytes) % size)
    padding_bytes = (padding_size * chr(padding_size)).encode()
    return text_bytes + padding_bytes

def pkcs7_pad_validate(text: bytes) -> bytes:
    if not isinstance(text, bytes):
        raise TypeError
    block_size = 16
    padding_byte = text[-1]
    if padding_byte > block_size or padding_byte == 0:
        raise Exception('Incorrect PKCS7 padding')
    for _ in range(padding_byte):
        if text[-1] != padding_byte:
            raise Exception('Incorrect PKCS7 padding')
        text = text[:-1]
    return text

def encrypt_aes_ecb(plaintext: bytes, key: bytes) -> bytes:
    if not isinstance(plaintext, bytes) or not isinstance(key, bytes):
        raise TypeError
    if len(plaintext) % 16 != 0:
        raise Exception('Data must be 16-byte aligned')
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

def ecb_oracle(plaintext: bytes, key: bytes, prefix: bytes = b'') -> bytes:
    if not isinstance(plaintext, bytes) or not isinstance(key, bytes):
        raise TypeError
    unknown_str = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    plaintext = prefix + plaintext + unknown_str
    plaintext =  pkcs7_pad(plaintext, 16)
    ciphertext = b''
    ciphertext = encrypt_aes_ecb(plaintext, key)
    return ciphertext

def detect_block_size(key: bytes, encryption_function: Callable) -> int:
    if not isinstance(key, bytes) or not isinstance(encryption_function, Callable):
        raise TypeError
    plaintext = b'A'
    first_hit = False
    first_hit_len = 0
    ciphertext = encryption_function(plaintext, key)
    prev_cipher_len = len(ciphertext)
    while not first_hit:
        first_hit_len += 1
        ciphertext = encryption_function(plaintext, key)
        cipher_len = len(ciphertext)
        if cipher_len > prev_cipher_len:
            first_hit = True
        prev_cipher_len = cipher_len
        plaintext += b'A'
    while True:
        ciphertext = encryption_function(plaintext, key)
        cipher_len = len(ciphertext)
        if cipher_len > prev_cipher_len:
            return len(plaintext) - first_hit_len
        else:
            prev_cipher_len = cipher_len
            plaintext += b'A'

def ecb_decrypt_byte_at_a_time(key: bytes, encryption_function: Callable, prefix: bytes = b'') -> bytes:
    if not isinstance(key, bytes) or not isinstance(encryption_function, Callable) or not isinstance(prefix, bytes):
        raise TypeError
    block_size = detect_block_size(key, encryption_function)
    ciphertext = encryption_function(b'A' * 50, key, prefix)
    ciphertext = codecs.encode(ciphertext, 'base64').decode('utf-8')
    mode = detect_mode(bytes(ciphertext, 'utf-8'))
    if mode != 'ECB':
        raise Exception('Can only decrypt ECB mode')
    if prefix == b'':
        prepend = b''
        plaintext_start = 0
    else:
        # If the encryption adds a prefix, find where the actual input starts by brute-forcing the size of the prefix
        indicator = encrypt_aes_ecb(b'B' * block_size, key).decode('latin1') # Block full of B's
        prepend = b'B'
        indicator_pos = -1
        # Keep encrypting until we find a block full of B's
        while indicator_pos == -1:
            encrypted_text = encryption_function(prepend, key, prefix) 
            indicator_pos = encrypted_text.decode('latin-1').find(indicator)
            prepend += b'B'
        # Now we know the size of the random prefix, so from now on prepad the correct number of B's on the input in order to align the blocks and just ignore the first blocks up until the prefix (which contain the prefix + the B's)
        prepend = prepend[:-1-block_size]
        plaintext_start = indicator_pos
    encrypted_secret_len = len(encryption_function(prepend, key, prefix).decode('latin-1')[plaintext_start:])
    total_blocks = encrypted_secret_len // block_size # Find out how many block the encrypted secret is by itself
    decrypted_text = b''
    target_position = (total_blocks - 1) * block_size # We will be decrypting the block where our input ends
    pre_appended_input = prepend + target_position * b'A' + b'A' * (block_size - 1) # Append A's and decrease each time we reveal a character 
    for curr_block in range(total_blocks):
        decrypted_block = b''
        for i in range(block_size):
            encrypted_text = encryption_function(pre_appended_input, key, prefix)[plaintext_start:]

            target = encrypted_text[target_position:target_position+ 16] # The block we want to match
            for c in string.printable:
                plaintext_pad = prepend + (target_position - (curr_block * 16)) * b'A' + b'A' * (block_size - 1 - i) + decrypted_text + decrypted_block + bytes(c, 'utf-8') # Same as target, except last character (brute force it)
                output = encryption_function(plaintext_pad, key, prefix)[plaintext_start:]
                output_block = output[target_position:target_position+ 16]
                if target == output_block: # Check if output matches target until we get the correct character
                    decrypted_block += bytes(c, 'utf-8')
                    break
            pre_appended_input = pre_appended_input[:-1]
        decrypted_text += decrypted_block
    return decrypted_text

def encode_cookie(query: bytes) -> dict:
    if not isinstance(query, bytes):
        raise TypeError
    query_str = query.decode('utf-8')
    params = query_str.split('&')
    data = {}
    for param in params:
        split = param.split('=')
        data[split[0]] = split[1]
    return data 

def profile_for(email: bytes) -> bytes:
    if not isinstance(email, bytes):
        raise TypeError
    badchars = ['&', '=']
    email_str = email.decode('utf-8')
    for c in badchars:
        if c in email_str:
            email_str = email_str[:email_str.index(c)]
    email = bytes(email_str, 'utf-8')
    return b'uid=10&role=user&email=' + email

def encrypt_profile(profile: bytes, key: bytes) -> bytes:
    if not isinstance(profile, bytes) or not isinstance (key, bytes):
        raise TypeError
    profile = pkcs7_pad(profile, 16)
    return encrypt_aes_ecb(profile, key)

def decrypt_profile(enc_profile: bytes, key: bytes) -> dict:
    if not isinstance(enc_profile, bytes) or not isinstance (key, bytes):
        raise TypeError
    decr = decrypt_aes_ecb(enc_profile, key).decode('utf-8')
    pad = ord(decr[-1:])
    if pad > 0 and pad < 16:
        decr = decr[:-pad]
    return encode_cookie(bytes(decr, 'utf-8'))

def create_admin_account(key: bytes) -> bytes:
    if not isinstance (key, bytes):
        raise TypeError
    block_size = detect_block_size(key, encrypt_profile)
    target_bytes = b'&role=admin' # The bytes we want to attach on the text
    email_suffix = b'@testemail.com'
    email_prefix = b'a'
    profile = profile_for(email_prefix + email_suffix)
    email_prefix += b'a' * (2 * block_size - (len(profile) % block_size)) # Create an extra block where we control the whole plaintext block
    profile = profile_for(email_prefix + email_suffix) # Create a fake profile to get the blocks of the ciphertext
    encrypted_fake_profile = encrypt_profile(profile, key)[:-block_size] # Throw away the last block
    attach = encrypt_aes_ecb(pkcs7_pad(email_suffix + target_bytes, block_size), key) # Create a new last block by encrypting the bytes we want to attach, along with the last part of the email
    encrypted_fake_profile += attach # Attach the last modified encrypted block
    return encrypted_fake_profile

def encrypt_userdata(userdata: bytes, key:bytes, iv: bytes) -> bytes:
    if not isinstance(userdata, bytes) or not isinstance(key, bytes) or not isinstance(iv, bytes):
        raise TypeError
    prepend = "comment1=cooking%20MCs;userdata="
    append = ";comment2=%20like%20a%20pound%20of%20bacon"
    badchars = [';', '=']
    userdata = userdata.decode('utf-8')
    for c in badchars:
        if c in userdata:
            userdata = userdata[:userdata.index(c)]
    data = pkcs7_pad(bytes(prepend + userdata + append, 'utf-8'), 16)
    return encrypt_aes_cbc(data, key, iv)

def decrypt_userdata(encrypted: bytes, key: bytes, iv: bytes) -> bool:
    if not isinstance(encrypted, bytes) or not isinstance(key, bytes) or not isinstance(iv, bytes):
        raise TypeError
    decr = decrypt_aes_cbc(encrypted, key, iv)
    decrypted_data = pkcs7_pad_validate(decr).decode('latin-1')
    data = decrypted_data.split(';')
    for param in data:
        if 'admin' in param:
            split = param.split('=')
            if split[1] == 'true':
                return True
    return False

def cbc_bit_flip(ciphertext: bytes, target: bytes):
    if not isinstance(ciphertext, bytes) or not isinstance(target, bytes):
        raise TypeError
    prepend = "comment1=cooking%20MCs;userdata="
    block_size = 16
    target = pkcs7_pad(target, block_size) # Pad target bytes so we can xor it (didn't need to do it with pkcs7)
    target = xor_bytes(bytes(prepend[block_size:2 * block_size], 'utf-8'), target) # Xor target bytes with the starting bytes of the second block. This way, when we this change gets propagated to the second block, the two xors will cancel each other out and the plaintext will contain our target bytes
    target_len = len(target)
    xored = xor_bytes(target, ciphertext[:target_len]) # Xor our crafted block with the first block of the ciphertext. It will mess up the first block of plaintext, but the second block will contain the target bytes
    ciphertext = xored + ciphertext[target_len:] # Replace the first ciphertext block with the crafted block
    return ciphertext

if __name__ == '__main__':
    # Challenge 16
    key = generate_random_bytes(16)
    iv = generate_random_bytes(16)
    userdata = b"test;admin=true"
    encrypted = encrypt_userdata(userdata, key, iv) 
    modified = cbc_bit_flip(encrypted, b';admin=true;')
    decrypted_modified = decrypt_userdata(modified, key, iv)
    print(decrypted_modified)

    # Challenge 15
    # unpadded = pkcs7_pad_validate(b"ICE ICE BABY\x04\x04\x04\x04")
    # print(unpadded)
    # unpadded = pkcs7_pad_validate(b"ICE ICE BABYAAAA\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11")
    # print(unpadded)
    # unpadded = pkcs7_pad_validate(b"ICE ICE BABY\x05\x05\x05\x05")
    # print(unpadded)
    # unpadded = pkcs7_pad_validate(b"ICE ICE BABY\x01\x02\x03\x04")
    # print(unpadded)

    # Challenge 14
    key = generate_random_bytes(16)
    prefix_len = random.randint(5,30)
    prefix = generate_random_bytes(prefix_len)
    decrypted = ecb_decrypt_byte_at_a_time(key, ecb_oracle, prefix)
    print(decrypted.decode('utf-8'))

    # Challenge 13
    # key = generate_random_bytes(16)
    # admin_acc = create_admin_account(key)
    # admin_acc_decrypted = decrypt_profile(admin_acc, key)
    # print(admin_acc_decrypted)

    # Test profile functions
    # profile = profile_for(b'test@test.com&role=admin')
    # print(profile)
    # enc_profile = encrypt_profile(profile, key)
    # print(enc_profile)
    # decr_profile = decrypt_profile(enc_profile, key)
    # print(decr_profile)

    # Challenge 12
    # key = generate_random_bytes(16)
    # decrypted = ecb_decrypt_byte_at_a_time(key, ecb_oracle)
    # print(decrypted.decode('utf-8'))

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
    # padded_bytes = pkcs7_pad(b'YELLOW SUBMARINE', 16)
    # encrypt_aes_cbc(padded_bytes, generate_random_bytes(16), generate_random_bytes(16))
