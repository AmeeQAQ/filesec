from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


# Cipher function with encryption and decryption modes
def cryptguard(mode, key, iv, data):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    match mode:
        case 0:
            # Padder
            padder = padding.PKCS7(128).padder()
            entomb = padder.update(data) + padder.finalize()
            # Padded plaintext to ciphertext
            ciphertext = cipher.encryptor().update(entomb) + cipher.encryptor().finalize()
            return ciphertext
        case 1:
            # Ciphertext to padded plaintext
            open = cipher.decryptor().update(data) + cipher.decryptor().finalize()
            # Plaintext
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(open) + unpadder.finalize()
            return plaintext