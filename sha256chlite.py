import hashlib, os

def hashcheck(file, sum):
    f = open(file, "rb")
    digest = hashlib.file_digest(f, "sha256")
    f.close()
    hexdig = digest.hexdigest()
    return hexdig == sum