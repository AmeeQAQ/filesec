from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import cryptography.exceptions
import os
import argparse

def encryption(file, passwd):
    if os.path.isfile(file):
        f = open(file, "rb")
        fread = f.read()
        f.close()
        # Random 128-bit salt for password-based encryption
        salt = os.urandom(16)
        # Password derivation by PBKDF2
        kdf = PBKDF2HMAC(hashes.SHA256(),32,salt,480000)
        key = kdf.derive(passwd.encode())
        # Random 128-bit initialization vector for CBC
        iv = os.urandom(16)
        # Cipher using AES in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        # File padding to fit 128-bit blocks
        padder = padding.PKCS7(128).padder()
        padded_file = padder.update(fread) + padder.finalize()
        # encryption
        ciphered_content = encryptor.update(padded_file) + encryptor.finalize()
        f = open(file, 'wb')
        f.write(ciphered_content)
        f.close()
        # Password "database"
        f = open('passwd.txt', 'a')
        f.write(file + '::' + key.hex() + '::' + salt.hex() + '::' + iv.hex())
        f.close()
    else:
        print("file not found")

def decryption(file, passwd):
    f = open(file, "rb")
    fread = f.read()
    f.close()
    f = open('passwd.txt', 'r')
    secrets = f.read()
    entry = secrets.split('::')
    if entry[0] == file:
        kdf = PBKDF2HMAC (hashes.SHA256(),32,bytes.fromhex(entry[2]),480000)
        try:
            kdf.verify(passwd.encode(), bytes.fromhex(entry[1]))
        except cryptography.exceptions.InvalidKey:
            print('The entered password is not correct')
            raise
        cipher = Cipher(algorithms.AES(bytes.fromhex(entry[1])), modes.CBC(bytes.fromhex(entry[3])))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        deciphered_content = decryptor.update(fread) + decryptor.finalize()
        unpadded_file = unpadder.update(deciphered_content) + unpadder.finalize()
        f = open(file, 'wb')
        f.write(unpadded_file)
        f.close()
    
def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", 
                        help="file to be encrypted. Use the absolute route if the file is not in the same directory as the script", required=True)
    parser.add_argument("-m", "--mode", 
                        help="0 to encrypt, 1 to decrypt", required=True, type=int)
    return parser

def main():
    args = parser().parse_args()
    if (args.mode == 0):
        passwd = input('Enter your encrypting password: ')
        if passwd:
            encryption(args.file, passwd)
        else:
            print('Enter a valid password')
    elif (args.mode == 1):
        passwd = input('Enter your file password: ')
        decryption(args.file, passwd)
    else:
        print("Mode not supported")
    

if __name__ == '__main__' : 
    main()