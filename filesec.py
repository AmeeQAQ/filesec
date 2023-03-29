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
    k2 = kdf.derive(passwd)
    # Initialization Vector for AES256
    iv = os.urandom(16)
    # Encrypting k1
    cryptguard = Cipher(algorithms.AES(k2), modes.CBC(iv))
    k1_encrypted = cryptguard.encryptor().update(k1) + cryptguard.encryptor().finalize()
    # Hash k2 for storing
    digest = hashes.Hash(hashes.SHA256())
    digest.update(k2) 
    k2_hashed = digest.finalize()
    # Generate plaintext file for storage
    f = open('keys.txt', 'w')
    f.write(k1_encrypted.hex() + '::' + iv.hex() + '::' + k2_hashed.hex() + '::' + salt.hex())

# Authentication function to check if password is correct
def auth(passwd, keys):
    kdf = PBKDF2HMAC(hashes.SHA256(),32,bytes.fromhex(keys[3]),480000)
    k2auth = kdf.derive(passwd)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(k2auth)
    hashkey = digest.finalize()
    return hashkey.hex() == keys[2]

# Decryption function for k1
def dk1(passwd, salt, ck1, iv):
    kdf = PBKDF2HMAC(hashes.SHA256(),32,salt,480000)
    k2 = kdf.derive(passwd)
    cryptguard = Cipher(algorithms.AES(k2),modes.CBC(iv))
    k1 = cryptguard.decryptor().update(ck1) + cryptguard.decryptor().finalize()
    return k1

# The (en)Crypt
def filecrypt(file, passwd):
    # Check if file exist
    if os.path.isfile(file):
        # Check passwd against hashed k2
        f = open('keys.txt', 'r')
        keyring = f.read()
        f.close()
        keys = keyring.split('::')
        if auth(passwd, keys):
            # Decrypt k1
            k1 = dk1(passwd, bytes.fromhex(keys[3]), bytes.fromhex(keys[0]), bytes.fromhex(keys[1]))
            # Read contents of file
            f = open(file, "rb")
            fread = f.read()
            f.close()
            # Initialization Vector for encryption
            iv = os.urandom(16)
            # Call the Cryptguard
            cryptguard = Cipher(algorithms.AES(k1), modes.CBC(iv))
            # Padder
            padder = padding.PKCS7(128).padder()
            bury = padder.update(fread) + padder.finalize()
            # Into the Crypt
            tomb = cryptguard.encryptor().update(bury) + cryptguard.encryptor().finalize()
            f = open(file, 'wb')
            f.write(tomb)
            f.close()
            # Write tombstone
            f = open('tomb.txt', 'w')
            f.write(file + '::' + iv.hex())
        else:
            print("Password mismatch")
    else:
        print("File not found")

# The (de)Crypt
def filedecrypt(file, passwd):
    # Check if file exist
    if os.path.isfile(file):
        f = open('keys.txt', 'r')
        keyring = f.read()
        f.close()
        keys = keyring.split('::')
        # Password auth
        if auth(passwd, keys):
            # Decrypt k1
            k1 = dk1(passwd, bytes.fromhex(keys[3]), bytes.fromhex(keys[0]), bytes.fromhex(keys[1]))
            # Read tombstone
            f = open('tomb.txt', 'r')
            inscription = f.read()
            f.close()
            filecrypted = inscription.split('::')
            # Call the Cryptguard
            cryptguard = Cipher(algorithms.AES(k1), modes.CBC(bytes.fromhex(filecrypted[1])))
            unpadder = padding.PKCS7(128).unpadder()
            f = open(file, 'rb')
            corpse = f.read()
            f.close()
            unearthed = cryptguard.decryptor().update(corpse) + cryptguard.decryptor().finalize()
            revived = unpadder.update(unearthed) + unpadder.finalize()
            f = open(file, 'wb')
            f.write(revived)
            f.close()
        else:
            print('Password mismatch')
    else:
        print('File not found')

def changepass(newpasswd, k1):
    # Salt is the spice of life
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(hashes.SHA256(),32,salt,480000)
    # k2 derived from password to encrypt k1
    k2 = kdf.derive(newpasswd)
    # Initialization Vector for AES
    iv = os.urandom(16)
    # Encrypting k1
    cipher = Cipher(algorithms.AES(k2), modes.CBC(iv))
    k1_encrypted = cipher.encryptor().update(k1) + cipher.encryptor().finalize()
    # Hash k2 for storing
    digest = hashes.Hash(hashes.SHA256())
    digest.update(k2) 
    k2_hashed = digest.finalize()
    # Generate plaintext file for storage
    f = open('keys.txt', 'w')
    f.write(k1_encrypted.hex() + '::' + iv.hex() + '::' + k2_hashed.hex() + '::' + salt.hex())
    
def parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", 
                        help="0 to encrypt, 1 to decrypt, 2 to establish a new password", required=False, type=int)
    parser.add_argument("-f", "--file", 
                        help="file to be encrypted. Use the absolute route if the file is not in the same directory as the script", required=False)
    return parser

def main():
    args = parser().parse_args()
    passwd = input('Enter encrypt password: ')
    match args.mode:
        case 0:
            filecrypt(args.file, passwd.encode())

        case 1:
            filedecrypt(args.file, passwd.encode())

        case 2:
            f = open('keys.txt', 'r')
            keyring = f.read()
            f.close()
            keys = keyring.split('::')
            if auth(passwd.encode(), keys):
                newpasswd = input('Enter a new password: ')
                newconf = input ('Repeat new password: ')
                if newpasswd == newconf:
                    k1 = dk1(passwd.encode(), bytes.fromhex(keys[3]), bytes.fromhex(keys[0]), bytes.fromhex(keys[1]))
                    changepass(newpasswd.encode(), k1)
                else:
                    print("Incorrect password")
            else:
                print('Password mismatch')
    

if __name__ == '__main__' : 
    main()