import os
import auth
import Util
import rsa
import rsa.randnum

db = auth.DBConnection()
curseur = db.cursor()
print('------------ PROJET SECURITE ------------')
print('connected:')
print('Please type the number of the desired choice:')
print('1. Menu')
rep = input('> ')

if (rep == '1'):
    print('---- MENU:')
    print("1 - Codage et décodage d'un message")
    print("2 - Hachage d'un message")
    print("3 - Craquage d'un message haché")
    print("4 - Chiffrement et déchiffrement symétrique d'un message")
    print("5 - Chiffrement et déchiffrement asymétrique d'un message")
    print("6 - ChatRoom")

    rep2 = input('> ')

    # 1- Codage et décodage d'un message
    if(rep2 == '1'):
        print("1 - to encode")
        print("2 - to decode")
        # a - Codage
        rep11 = input('> ')
        if (rep11 == '1'):
            message = input('Please enter the message to encode > ')
            encoded_message = Util._coder(message)
            print(f'The encoded message is -> {encoded_message}')
        else:
        # b - Décodage
            encoded_message = input('Please enter the message to encode > ')
            decoded_message = Util._decoder(encoded_message)
            print(f"the decoded message -> {decoded_message}")

    # 2 - Hachage d'un message
    elif (rep2 =='2'):
        email = input('Please enter your email > ')
        print('1. Hashing with MD5')
        print('2. Hashing with SHA1')
        print('3. Hashing with SHA256')

        rep22 = input('algo > ')

        # a - Md5
        if (rep22 == '1'):
            print(f'Hashed Email with MD5 -> {Util._md5(email)}')
        # b - SHA1
        if (rep22 == '2'):
            print(f'Hashed Email with SHA1 -> {Util._sha1(email)}')
        # c - SHA256
        if (rep22 == '3'):
            print(f'Hashed Email with SHA256 -> {Util._sha256(email)}')
        else:
            print('please write a valid choice')

    # 3 - Craquage d'un message haché
    elif (rep2 == '3'):
        hash = input('Enter the hash to crack > ')
        print('1. Hashing with MD5')
        print('2. Hashing with SHA1')
        print('3. Hashing with SHA256')

        rep23 = input('algo > ')
        if(rep23 == '1'):
            # a - Md5
            Util._md5_dict_cracker(hash)
        elif (rep23 == '2'):
            # b - SHA1
            Util._sha1_dict_cracker(hash)
        elif (rep23 == '3'):
            # c - SHA256
            Util._sha256_dict_cracker(hash)
        else:
            print('please write a valid choice')
    # 4 - Chiffrement et déchiffrement symétrique d'un message
    elif (rep2 == '4'):
        print('1. DES')
        print('2. AES256')

        rep24 = input('> ')

        # a - DES
        if(rep24 == '1'):
            print(' you have chosen DES Would you like to')
            print('1. generate key')
            print('2. encrypt with key')
            print('3. decrypt with key')
            rep241 = input('> ')
            if (rep241 == '1'):
                key = Util._generate_DES_Key()
                print(f'KEY => {key}')
            if (rep241 == '2'):
                key = input('your key > ')
                message = input('your message > ')
                print(f'Encrypted message with DES -> {Util._des_encrypt(key, message).hex()}')
            if(rep241 == '3'):
                key = input("your key >")
                message = input("the message you want to decrypt >")
                print(f'Decrypted message with DES -> {Util._des_decrypt(key, message)}')
                
        # b - AES256
        elif (rep24 == '2'):
            
            message = input('Please enter the message to encrypt with AES256 > ')
            key = Util._generate_AES_Key()
            print('*. Consult Key')

            rep241 = input('> ')
            ciphertext, nonce, tag = Util._aes_encrypt(key, message)
            if (rep241 == "*"):
                print(f'KEY => {key}')
                print(f'NONCE => {nonce}')
                print(f'tag => {tag}')
                

            
            print(f'Encrypted message with AES256 -> {ciphertext.hex()}')
            plaintext = Util._aes_decrypt(key, ciphertext, nonce, tag)
            print(f'Encrypted message with AES256 -> {plaintext}')
        else:
            print('please write a valid choice')

    elif (rep2 == '5'):
        print('1. RSA')
        print('2. ElGamal')

        rep25 = input('> ')

        # a - RSA
        if(rep25 == '1'):
            message = input('Please enter the message to encrypt with RSA > ')
            pubkey, privkey = Util._generate_keys_rsa();
            print(pubkey)
            encrypted_rsa = Util._encrypt_rsa(pubkey, message)
            print(f'Encrypted message with RSA -> {encrypted_rsa.hex()}')
            decrypted_rsa = rsa.decrypt(encrypted_rsa, privkey)
            print(f'Decrpted message with RSA -> {decrypted_rsa}')
            
        # b - Elgamal
        elif(rep25 == '2'):
            message = input('Please enter the message to encrypt with ElGamal > ')
            elgamal_keys = Util._generate_ElGamal_keys()
            print(f"g = {elgamal_keys.get('publicKey').g}")
            print(f"p = {elgamal_keys.get('publicKey').p}")
            print(f"y = {elgamal_keys.get('publicKey').h}")
            cipher = Util._encrypt_elgamal(elgamal_keys.get('publicKey'), message)
            print(f'Encrypted message with ElGamal -> {cipher}')
            plaintext = Util._decrypt_elgamal(elgamal_keys.get('privateKey'), cipher)
            print(f'Encrypted message with ElGamal -> {plaintext}')
        else:
            print('please write a valid choice')
    elif (rep2 == '6'):
        os.system("python chatroom_client.py")
    else:
        print('please write a valid choice')
    
else:
    print('please write a valid choice')

os.system("python menu.py")
