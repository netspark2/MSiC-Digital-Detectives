# For md5, sha1, sha224, sha256, sha384, sha512 algorithms
import hashlib

# Take user input
password = raw_input("Enter a password: ")

# MD5
print "MD5:\t" + hashlib.md5(password).hexdigest()
# SHA1
print "SHA1:\t" + hashlib.sha1(password).hexdigest()
# SHA224
print "SHA224:\t" + hashlib.sha224(password).hexdigest()
# SHA256
print "SHA256:\t" + hashlib.sha256(password).hexdigest()
# SHA384
print "SHA384:\t" + hashlib.sha384(password).hexdigest()
# SHA512
print "SHA512:\t" + hashlib.sha512(password).hexdigest()


