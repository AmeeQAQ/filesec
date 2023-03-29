from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import hashlib
import argparse

def encryption(file):
    f = open(file, "rb")
    fread = f.read()
    f.close()
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_file = padder.update(fread) + padder.finalize()
    ciphered_content = encryptor.update(padded_file) + encryptor.finalize()
    f = open(file, 'wb')
    f.write(ciphered_content)
    os.rename(file, file + ".enc")
    print("key: " + key.hex() + ", iv: " + iv.hex())

def decryption(file, key, iv):
    f = open(file, "rb")
    fread = f.read()
    f.close()
    cipher = Cipher(algorithms.AES(bytes.fromhex(key)), modes.CBC(bytes.fromhex(iv)))
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    deciphered_content = decryptor.update(fread) + decryptor.finalize()
    unpadded_file = unpadder.update(deciphered_content) + unpadder.finalize()
    f = open(file, 'wb')
    f.write(unpadded_file)
    os.rename(file, file.replace('.enc', ''))
    
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
        encryption(args.file)
    elif (args.mode == 1):
        key = input()
        iv = input()
        decryption(args.file, key, iv)
    else:
        print("Mode not supported")
    

if __name__ == '__main__' : 
    main()