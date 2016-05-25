# For md5, sha1, sha224, sha256, sha384, sha512 algorithms
import hashlib
import string

# Character lengths of each type of hash
#  md5 - 32
#  sha1 - 40
#  sha224 - 56
#  sha256 - 64
#  sha384 - 96
#  sha512 - 128

# Get the hash from the user
hashed_password = raw_input("Entser the hash: ")

# Remove accidental spaces aroung the input
hashed_password = hashed_password.strip()

# A dictionary of functions where the key is the lendth of the hash
algorithms = {
        32: hashlib.md5,
        40: hashlib.sha1,
        56: hashlib.sha224,
        64: hashlib.sha256,
        96: hashlib.sha384,
        128: hashlib.sha512
    }

# Read all the passwords from the text file and split them by newline
with open("wordlist.txt", "r") as f:
    words = f.read().split("\n")

# Check if the hash is of known length
if len(hashed_password) not in algorithms.keys():
    print "Unknown hash type"
else:
    # A boolean variable identifying if the password was found
    found = False
    
    print "Checking all passwords in the wordlist"
    for password in words:
        if algorithms[len(hashed_password)](password).hexdigest() == hashed_password:
            print "FOUND!"
            print "The password is '%s'" % password
            found = True
            break

    if not found:
        print "The password was not found in the wordlist"
