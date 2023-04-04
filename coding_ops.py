from key_management import * 
        
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
            f = open(os.environ['TOMB'], 'r+')
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