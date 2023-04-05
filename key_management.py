from cryptguard import *
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

# Function to split the key file and retrieve every element of it
def keysplit(keyfile):
    f = open(keyfile, 'r')
    keyring = f.read()
    f.close()
    keys = keyring.split('::')
    return keys

# Decryption function for k1
def dk1(passwd, salt, ck1):
    # Derive a key from the introduced password (presumably the correct one checked by 'auth')
    kdf = PBKDF2HMAC(hashes.SHA256(),32,salt,480000)
    k2 = kdf.derive(passwd)
    # Call the cryptguard in mode 1 to decrypt k1
    iv_k1 = ck1[:16]
    k1 = ck1[16:]
    k1 = cryptguard(1, k2, iv_k1, k1)
    return k1

# Authentication function to check if password is correct
def auth(passwd, keys):
    # Derive a key from the introduced password
    kdf = PBKDF2HMAC(hashes.SHA256(),32,bytes.fromhex(keys[2]),480000)
    k2auth = kdf.derive(passwd)
    # Hash the derived key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(k2auth)
    hashkey = digest.finalize()
    # Check if H(kdf(password)) is equal to keys[2], which is the hashed key derived from the original password
    return hashkey.hex() == keys[1]

# keygen function to generate user keys derived from an introduced password.
# Store 'keys.txt' somewhere safe and use a .env file to refer to it.
def keygen(passwd):
    # Randomly generated key to encrypt files
    k1 = os.urandom(16)
    print(k1.hex())
    # Salt is the spice of life
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(hashes.SHA256(),32,salt,480000)
    # k2 derived from password to encrypt k1
    k2 = kdf.derive(passwd)
    # Initialization Vector for AES256
    iv = os.urandom(16)
    # Call the Cryptguard to encrypt k1
    k1_encrypted = cryptguard(0, k2, iv, k1)
    # Prepend IV into the encrypted data
    k1_encrypted = iv + k1_encrypted
    # Hash k2 for storing
    digest = hashes.Hash(hashes.SHA256())
    digest.update(k2) 
    k2_hashed = digest.finalize()
    # Generate plaintext file for storage
    f = open(os.environ['KEYRING'], 'w')
    f.write(k1_encrypted.hex() + '::' + k2_hashed.hex() + '::' + salt.hex())

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
    k1_encrypted = cryptguard(0, k2, iv, k1)
    # Prepend IV into the encrypted data
    k1_encrypted = iv + k1_encrypted
    # Hash(k2) for storing
    digest = hashes.Hash(hashes.SHA256())
    digest.update(k2) 
    k2_hashed = digest.finalize()
    # Generate plaintext file for storage
    f = open(os.environ['KEYRING'], 'r+')
    f.write(k1_encrypted.hex() + '::' + k2_hashed.hex() + '::' + salt.hex())