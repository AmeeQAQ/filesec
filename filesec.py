from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
import cryptography.exceptions
import os
import argparse

def keygen(passwd):
    # Randomly generated key to encrypt files
    k1 = os.urandom(16)
    # Salt is the spice of life
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(hashes.SHA256(),32,salt,480000)
    # k2 derived from password to encrypt k1
    k2 = kdf.derive(passwd.encode())
    # Initialization Vector for AES256
    iv = os.urandom(16)
    # Encrypting k1
    cipher = Cipher(algorithms.AES256(k2), modes.CBC(iv))
    k1_encrypted = cipher.encryptor().update(k1) + cipher.encryptor().finalize()
    # Hash k2 for storing
    digest = hashes.Hash(hashes.SHA256())
    k2_hashed = digest.update(k2) + digest.finalize()
    # Generate plaintext file for storage
    f = open('keys.txt', 'w')
    f.write(k1_encrypted.hex() + '::' + iv.hex() + '::' + k2_hashed.hex() + '::' + salt.hex())

def filecrypt(file, passwd):
    # Check if file exist
    if os.path.isfile(file):
        # Read contents of file
        f = open(file, "rb")
        fread = f.read()
        f.close()
        # Initialization Vector for encryption
        iv = os.urandom(16)
        # Cryptguard Cipher
        cryptguard = Cipher(algorithms.AES(key), modes.CBC(iv))
        # Padder
        padder = padding.PKCS7(128).padder()
        padded_content = padder.update(fread) + padder.finalize()
        # Into the crypt
        tomb = cryptguard.encryptor().update(padded_content) + cryptguard.encryptor().finalize()
        f = open(file, 'wb')
        f.write(tomb)
        f.close()
        # Write tombstone
        f = open('tomb.txt', 'w')
        f.write(file + '::' + iv.hex())
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
            filecrypt(args.file, passwd)
        else:
            print('Enter a valid password')
    elif (args.mode == 1):
        passwd = input('Enter your file password: ')
        decryption(args.file, passwd)
    else:
        print("Mode not supported")
    

if __name__ == '__main__' : 
    main()