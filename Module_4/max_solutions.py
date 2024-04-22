from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def md5_hash(message):
    md5hash = hashes.Hash(hashes.MD5())
    md5hash.update(message)
    md5digest = md5hash.finalize()
    return md5digest

def sha1_hash(message):
    sha1hash = hashes.Hash(hashes.SHA1())
    sha1hash.update(message)
    sha1digest = sha1hash.finalize()
    return sha1digest

# EXERCISE 1
"""
Starting from the first live-coding (about MD5 and SHA1), add functionality so that the user can 
enter a string, which the program then computes and displays the MD5 and SHA1 hashes of. Test with strings 
that are similar, such as “Hello” and “H3llo”.
"""
def ex1():
    input_string = input("Enter string: ")
    md5hash = md5_hash(input_string.encode("UTF-8"))
    sha1hash = sha1_hash(input_string.encode("UTF-8"))

    print("MD5 hash: ", md5hash)
    print("SHA-1 hash: ", sha1hash)

# EXERCISE 2
"""
Starting from the first live-coding (about MD5 and SHA1), compute the MD5 and SHA1 hash of a file 
or your choosing. Have the program print the filename as well as the MD5 and SHA1 hashes of it.

(Hint: To open a file in the same directory as the Python script, you can use:

> filepath = os.path.dirname(__file__) + "\\" + filename

where filename is the name of the file.)
"""
def ex2():
    file_dir = os.path.dirname(os.path.realpath(__file__))
    file_name = "shattered-1.pdf"
    file = open(file_dir + "\\" + file_name, "rb")

    byte_value = file.read()
    md5hash = md5_hash(byte_value)
    sha1hash = sha1_hash(byte_value)

    print("File name: ", file_name)
    print("MD5 hash: ", md5hash)
    print("SHA-1 hash: ", sha1hash)

# EXERCISE 3
"""
Continuing from the previous exercise, download the two PDF files from https://shattered.io.
Compute the SHA1 hash of each of the two files, what do you observe? What about the MD5 hashes of them?
"""
def ex3():
    file_dir = os.path.dirname(os.path.realpath(__file__))

    file_name1 = "shattered-1.pdf"
    file_name2 = "shattered-2.pdf"

    file1 = open(file_dir + "\\" + file_name1, "rb")
    file2 = open(file_dir + "\\" + file_name2, "rb")

    byte_value1 = file1.read()
    byte_value2 = file2.read()

    sha1_hash1 = sha1_hash(byte_value1)
    sha1_hash2 = sha1_hash(byte_value2)

    md5_hash1 = md5_hash(byte_value1)
    md5_hash2 = md5_hash(byte_value2)

    print("File name: ", file_name1)
    print("MD5 hash: ", md5_hash1.hex())
    print("SHA-1 hash: ", sha1_hash1.hex())

    print("File name: ", file_name2)
    print("MD5 hash: ", md5_hash2.hex())
    print("SHA-1 hash: ", sha1_hash2.hex())

    print("MD5 Match: ", md5_hash1.hex() == md5_hash2.hex())
    print("SHA-1 Match: ", sha1_hash1.hex() == sha1_hash2.hex())

# EXERCISE 4
"""
This exercise is about requirements of cryptographic hash functions:
"""

"""
(a): Why do we want a hash function to be one-way?

Answer:
We want a hash function to be one-way to ensure that it is computationally infeasible to reverse the process
and retrieve the original input from its hash value. This property is essential for password hashing
and digital signatures, where we want to protect sensitive information. If an attacker could easily
reverse the hash function, it would compromise the security of the system.
"""

"""
(b): Suppose we have a hash function which takes a 128-bit input and gives us a 64-bit output. Must it be the 
case that there is at least one colliding pair of inputs for this hash function?

Answer:
Yes, it must be the case that there is at least one colliding pair of inputs for this hash function.
This is because the output space of a hash function with a fixed output size (64 bits in this case)
is smaller than the input space (128 bits). Due to the pigeonhole principle, where there are more
possible inputs than there are possible outputs, collisions are inevitable. In other words,
there are more potential inputs than there are unique hash values, so multiple inputs can map to the same
hash value, resulting in collisions.
"""

# EXERCISE 5
"""
Consider the following method for generating a tag for a message: Given data, the tag is the 
SHA256 hash of the data. Is this method secure, or are there some problems here?

Answer:
The method of generating a tag for a message by taking the SHA256 hash of the data is generally secure
for many use cases. However, there are some considerations and potential limitations:

Collision Resistance: 
SHA256 is designed to be collision-resistant, meaning it should be computationally infeasible
to find two different inputs that produce the same hash value. This property is crucial for security
because it ensures that an attacker cannot forge a different message with the same hash value as the
original message.

Preimage Resistance:
SHA256 is also designed to be preimage-resistant, meaning it should be computationally infeasible to find
an input that produces a specific hash value. This property helps maintain the confidentiality of the original
message because it prevents an attacker from deducing the original message from its hash value.

Length Extension Attack:
While SHA256 itself is resistant to length extension attacks, the way it is used in practice may introduce
vulnerabilities if not implemented correctly. For example, if the hash value is concatenated with the original
message and then hashed again, it could potentially expose the system to length extension attacks. Therefore,
it's important to use SHA256 in a secure manner, such as using HMAC (Hash-based Message Authentication Code)
for message authentication.

Key Management: 
If the integrity of the message is critical, it's essential to consider key management practices. 
Using a cryptographic hash function like SHA256 for message authentication provides integrity protection, 
but it does not provide authentication or non-repudiation without additional mechanisms such as digital signatures.
"""

# EXERCISE 6
"""
Starting with the live-coding with the MAC, implement a simple Encrypt-then-MAC scheme.
Be sure to use two different keys for the Encryption and MAC respectively. Test your scheme on some plaintexts and
print the resulting ciphertexts and associated MAC tags. Use AES-CTR for encryption and HMAC-SHA256 for the MAC.
"""
def ex6():
    def encrypt_then_mac(message, encryption_key, mac_key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(message) + encryptor.finalize()

        mac = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend)
        mac.update(ciphertext)
        tag = mac.finalize()

        return (ciphertext, iv, tag)

    encryption_key = os.urandom(16)
    mac_key = os.urandom(32)

    message = b'This is a test.'
    ciphertext, iv, tag = encrypt_then_mac(message, encryption_key, mac_key)
    print("Ciphertext:", ciphertext)
    print("IV:", iv)
    print("MAC Tag:", tag.hex())

    return (ciphertext, iv, tag, encryption_key, mac_key)

# EXERCISE 7
"""
This exercise is a continuation of the previous one. Implement a simple Decrypt-then-MAC scheme. 
Test you scheme on some (ciphertext, tag)-pairs that you generated in the previous exercise.
"""
def ex7():
    ciphertext, iv, tag, encryption_key, mac_key = ex6()
    def decrypt_then_mac(ciphertext, iv, tag, encryption_key, mac_key):
        cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

        mac = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        mac.update(ciphertext)
        computed_tag = mac.finalize()

        if computed_tag == tag:
            return decrypted_message
        else:
            return None
        
    decrypted_message = decrypt_then_mac(ciphertext, iv, tag, encryption_key, mac_key)
    if decrypted_message is not None:
        print("Decrypted Message:", decrypted_message)
        return ciphertext, tag
    else:
        print("MAC verification failed. Message integrity compromised.")

def start():
    ex7()

start()