from coding_ops import *
from dotenv import load_dotenv
import cryptography.exceptions
import argparse

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
