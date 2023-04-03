from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from dotenv import load_dotenv
import cryptography.exceptions
import os
import argparse

# keygen function to generate user keys derived from an introduced password.
# Store 'keys.txt' somewhere safe and use a .env file to refer to it.
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
    # Derive a key from the introduced password
    kdf = PBKDF2HMAC(hashes.SHA256(),32,bytes.fromhex(keys[3]),480000)
    k2auth = kdf.derive(passwd)
    # Hash the derived key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(k2auth)
    hashkey = digest.finalize()
    # Check if H(kdf(password)) is equal to keys[2], which is the hashed key derived from the original password
    return hashkey.hex() == keys[2]

# Decryption function for k1
def dk1(passwd, salt, ck1, iv):
    # Derive a key from the introduced password (presumably the correct one checked by 'auth')
    kdf = PBKDF2HMAC(hashes.SHA256(),32,salt,480000)
    k2 = kdf.derive(passwd)
    # Create cipher to decrypt k1 with k2
    cryptguard = Cipher(algorithms.AES(k2),modes.CBC(iv))
    # Decrypt k1
    k1 = cryptguard.decryptor().update(ck1) + cryptguard.decryptor().finalize()
    return k1

# Function to split the key file and retrieve every element of it
def keysplit(keyfile):
    f = open(keyfile, 'r')
    keyring = f.read()
    f.close()
    keys = keyring.split('::')
    return keys

# Cipher function with encryption and decryption modes
def cryptguard(mode, key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    match mode:
        case 0:
            # Padder
            padder = padding.PKCS7(128).padder()
            entomb = padder.update(data) + padder.finalize()
            # Padded plaintext to ciphertext
            close = cipher.encryptor().update(entomb) + cipher.encryptor().finalize()
            return close
        case 1:
            # Ciphertext to padded plaintext
            open = cipher.decryptor().update(data) + cipher.decryptor().finalize()
            # Plaintext
            unpadder = padding.PKCS7(128).unpadder()
            revived = unpadder.update(open) + unpadder.finalize()
            return revived


# The (en)Crypt
def filecrypt(file, passwd, keys):
    # Check if file exist
    if os.path.isfile(file):
        # Password auth
        if auth(passwd, keys):
            # Decrypt k1
            k1 = dk1(passwd, bytes.fromhex(keys[3]), bytes.fromhex(keys[0]), bytes.fromhex(keys[1]))
            # Read contents of file
            f = open(file, "rb")
            corpse = f.read()
            f.close()
            # Initialization Vector for encryption
            iv = os.urandom(16)
            # Call the Cryptguard
            coffin = cryptguard(0, k1, iv, corpse)
            # Into the Crypt
            f = open(file, 'wb')
            f.write(coffin)
            f.close()
            # Write tombstone
            f = open(os.environ['TOMB'])
            f.write(file + '::' + iv.hex())
        else:
            print("Password mismatch")
    else:
        print("File not found")

# The (de)Crypt
def filedecrypt(file, passwd, keys):
    # Check if file exist
    if os.path.isfile(file):
        # Password auth
        if auth(passwd, keys):
            # Decrypt k1
            k1 = dk1(passwd, bytes.fromhex(keys[3]), bytes.fromhex(keys[0]), bytes.fromhex(keys[1]))
            # Read tombstone
            f = open(os.environ['TOMB'], 'r')
            tombstone = f.read()
            f.close()
            inscription = tombstone.split('::')
            # Read contents file
            f = open(file, 'rb')
            corpse = f.read()
            f.close()
            # Call the Cryptguard
            revived = cryptguard(1, k1, bytes.fromhex(inscription[1]), corpse)
            f = open(file, 'wb')
            f.write(revived)
            f.close()
        else:
            print('Password mismatch')
    else:
        print('File not found')

# Function to change user's password
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
    # Hash(k2) for storing
    digest = hashes.Hash(hashes.SHA256())
    digest.update(k2) 
    k2_hashed = digest.finalize()
    # Generate plaintext file for storage
    f = open(os.environ['KEYRING'], 'w')
    f.write(k1_encrypted.hex() + '::' + iv.hex() + '::' + k2_hashed.hex() + '::' + salt.hex())

# Parser for Command-Line arguments
def parser():
    parser = argparse.ArgumentParser()
    # Script mode
    parser.add_argument("-m", "--mode", 
                        help="0 to encrypt, 1 to decrypt, 2 to establish a new password, 3 to generate your key", required=True, type=int)
    # File to be used. Requiered for modes 0 and 1
    parser.add_argument("-f", "--file", 
                        help="file to be encrypted. Use the absolute route if the file is not in the same directory as the script", required=False)
    return parser

def main():
    args = parser().parse_args()

    passwd = input('Enter password: ')
    load_dotenv()
    match args.mode:
        case 0:
            keys = keysplit(os.environ['KEYRING'])
            filecrypt(args.file, passwd.encode(), keys)

        case 1:
            keys = keysplit(os.environ['KEYRING'])
            filedecrypt(args.file, passwd.encode(), keys)

        case 2:
            keys = keysplit(os.environ['KEYRING'])
            # Authenticating user through personal passowrd
            if auth(passwd.encode(), keys):
                newpasswd = input('Enter a new password: ')
                newconf = input ('Repeat new password: ')
                # Password confirmation
                if newpasswd == newconf:
                    # Decryption of k1
                    k1 = dk1(passwd.encode(), bytes.fromhex(keys[3]), bytes.fromhex(keys[0]), bytes.fromhex(keys[1]))
                    # Change password
                    changepass(newpasswd.encode(), k1)
                else:
                    print("Incorrect password")
            else:
                print('Password mismatch')
        
        case 3:
            if os.path.isfile(os.environ['KEYRING']):
                print('Key already exists')
            else:
                keygen(passwd.encode())
    

if __name__ == '__main__' : 
    main()
