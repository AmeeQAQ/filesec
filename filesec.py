from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import hashlib
import argparse

def encryption(file):
    f = open(file, "rb")
    fread = f.read()
    print(fread)
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
    
def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", 
                        help="file to be encrypted. Use the absolute route if the file is not in the same directory as the script", required=True)
    parser.add_argument("-m", "--mode", 
                        help="0 to encrypt, 1 to decrypt", required=False)
    return parser

def main():
    args = parser().parse_args()
    encryption(args.file)

if __name__ == '__main__' : 
    main()