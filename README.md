# filesec
Little python script to encrypt/decrypt files. Developed as a learning tool for my college studies.  
Uses the [cryptography](https://cryptography.io/en/latest/) python library for basically everything, as well as [argparse](https://docs.python.org/3/library/argparse.html) for command-line arguments.  
  
## How to use it
The script needs at least one parameter, which is `-m`, `--mode`. It has four possible modes:
- 0: encryption. Paired with a file.
- 1: decryption. Paired with a file.
- 2: change of password.
- 3: key generation.  
  
The second parameter is `-f`, `--file`. Used to specify the file's path.

## How it works
The script works with [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) encryption in [CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) mode and two keys:
- k1: generated automatically in mode 3. 128-bit random key used to encrypt all the data.
- k2: key derived from your entered password using [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2). This key will be used to encrypt k1 so we can store it safely and allow us to change our password without having to decrypt everything.
k2 will then be hashed with [SHA-256](https://en.wikipedia.org/wiki/SHA-2) and stored with its [salt](https://en.wikipedia.org/wiki/Salt_(cryptography)).  


So far, all we have is the encrypted k1, AKA k2(k1), H(k2), and some salt.  

In order to encrypt, decrypt or change your password, the script will ask for a password, which will be derived into a key using k2's salt and hashed with SHA-256. This hashcode is compared to the one already stored, and if the comparison fails, the script will simply end.  
Had it not, the next step will be to decrypt k1 using k2. With k1 decrypted, we can proceed to either encrypt or decrypt:
- If we are in mode 0, the script will generate a random 128-bit value that will be used as the initialization vector for CBC, and stored at the head of the encrypted file *(soon)*.
- If we are in mode 1, we just need to retrieve the IV used in the encryption and decrypt using k1.  

It is worth noting two things:
- It is **NECESSARY** to add the required padding **before** encrypting and **after** decrypting. CBC requires the data to be a multiple of the cipher's established block size.
In this case, 128-bit padding must be added (and removed), as the IV is also 128-bits (this is a bit of a note to myself).
- Since we are using two keys, one to encrypt/decrypt and another to authenticate, we can safely change our password even if there's encrypted data with the previous one.
k2 is only used to encrypt/decrypt k1 and will never alter k1 itself. It's like locking a key into a box with another key (which... is actually kind of "encrypted" too).
