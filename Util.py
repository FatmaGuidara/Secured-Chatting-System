import hashlib
import pycrunch
from des import DesKey
import random
import string
from Crypto.Cipher import AES
import rsa
import rsa.randnum
import elgamal
import math

# message_encoded = None

# 1- Codage et décodage d'un message
# a- Codage
def _coder(message):
    print("Voulez choisir encoding :")
    encodings = ['utf_32', 'utf_32_be', 'utf_32_le', 'utf_16', 'utf_16_be', 'utf_16_le', 'utf_8', 'utf_8_sig']
    index = 1
    for encoding in encodings:
        print(f'{index} {encoding}')
        index += 1
    my_encoding = input('Encoding > ')
    global message_encoded
    
    return message.encode(my_encoding).hex()

# b- Décodage
def _decoder(message_encoded):
    print("Voulez choisir decoding :")
    encodings = ['utf_32', 'utf_32_be', 'utf_32_le', 'utf_16', 'utf_16_be', 'utf_16_le', 'utf_8', 'utf_8_sig']
    index = 1
    for encoding in encodings:
        print(f'{index} {encoding}')
        index += 1
    my_encoding = input('Decoding > ')
    return bytes.fromhex(message_encoded).decode(my_encoding)

# 2- Hachage d'un message
# a- Md5
def _md5(message):
    message += "\n"
    result = hashlib.md5(message.encode())
    return (result.hexdigest())

# b- SHA1
def _sha1(message):
    message += "\n"
    hash_obj = hashlib.sha1(message.encode())
    return(hash_obj.hexdigest())

# c- SHA256
def _sha256(message):
    message += "\n"
    hashed = hashlib.sha256(message.encode()).hexdigest()
    return (hashed)

# Generer un dictionnaire
def _generer_dictionnaire():
    return None

# 3 - Craquage d'un message haché
# a- Md5
def _md5_dict_cracker(hash):
    f = open("insat.dic", "r")
    for line in f:
        if(hashlib.md5(line.encode()).hexdigest() == hash):
            print(f"=> Cracked >> {line} ")
            return 0
    print("Sorry we couldn't find your email")
# b- SHA1
def _sha1_dict_cracker(hash):
    f = open("insat.dic", "r")
    for line in f:
        if(hashlib.sha1(line.encode()).hexdigest() == hash):
            print(f"=> Cracked >> {line} ")
            return 0
    print("Sorry we couldn't find your email")
# c- SHA256
def _sha256_dict_cracker(hash):
    f = open("insat.dic", "r")
    for line in f:
        if(hashlib.sha256(line.encode()).hexdigest() == hash):
            print(f"=> Cracked >> {line} ")
            return 0
    print("Sorry we couldn't find your email")

# 4 - Chiffrement et déchiffrement symétrique d'un message
# a- DES
def _generate_DES_Key():
    S = 8
    ran = ''.join(random.choices(string.ascii_uppercase + string.digits, k = S))
    return ran

def _des_encrypt(key, message):
    
    key0 = DesKey(key.encode())
    return key0.encrypt(message.encode(), padding=True)

def _des_decrypt(key, message):
    key0 = DesKey(key.encode())
   
    return key0.decrypt(bytes.fromhex(message), padding=True).decode()

# b- AES256
def _generate_AES_Key():
    S = 16
    ran = ''.join(random.choices(string.ascii_uppercase + string.digits, k = S))
    return ran

def _aes_encrypt(key, message):
    cipher = AES.new(key.encode(), AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext, nonce, tag

def _aes_decrypt(key, message, nonce, tag):
    cipher = AES.new(key.encode(), AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(message)
    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        print("Key incorrect or message corrupted")

# 5- Chiffrement et déchiffrement asymétrique d'un message
# a- RSA
def _generate_keys_rsa():
    (pubkey, privkey) = rsa.newkeys(512)
    return pubkey, privkey

def _encrypt_rsa(pubkey, message):
    return rsa.encrypt(message.encode(), pubkey)

def _decrypt_rsa(privkey, message):
    return rsa.decrypt(message, privkey)

def _rsa_encrypt_big_files(pubkey):
    block_key = rsa.randnum.read_random_bits(128)
    return rsa.encrypt(block_key, pubkey)

# b- Elgamal
def _generate_ElGamal_keys():
    return elgamal.generate_keys()

def _encrypt_elgamal(pubkey, message):
    return elgamal.encrypt(pubkey, message)

def _decrypt_elgamal(privkey, message):
    return elgamal.decrypt(privkey, message)


# MAIN
# message = "hello"
# encoded_message = _coder(message)
# print(encoded_message)
# print(_decoder())

# a = input()
# b = input()
# c = input()
#
# print(_md5(a))
# print(_sha1(b))
# print(_sha256(c))
#
# a = input()
# b = input()
# c = input()
#
# _md5_dict_cracker(a)
# _sha1_dict_cracker(b)
# _sha256_dict_cracker(c)
# key = _generate_DES_Key()
# print(_des_encrypt(key, message).hex())
# encrypted = _des_encrypt(key, message)
# print(_des_decrypt(key, encrypted))

# -----------------AES
# key = _generate_AES_Key()
# _aes_encrypt(key, message)
# ciphertext, nonce, tag = _aes_encrypt(key, message)
# print(ciphertext.hex())
# plaintext = _aes_decrypt(key, ciphertext, nonce, tag)
# print(plaintext)

# -----------------RSA
# pubkey, privkey = _generate_keys_rsa();
# print(pubkey)
# encoded_rsa = _encrypt_rsa(pubkey, message)
# print(encoded_rsa.hex())
# decoded_rsa = rsa.decrypt(encoded_rsa, privkey)
# print(decoded_rsa)

# -----------------El Gamal
# elgamal_keys = _generate_ElGamal_keys()
# cipher = _encrypt_elgamal(elgamal_keys.get('publicKey'), message)
# print(cipher)
# plaintext = _decrypt_elgamal(elgamal_keys.get('privateKey'), cipher)
# print(plaintext)

