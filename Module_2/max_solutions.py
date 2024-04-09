from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os, base64

# EXERCISE 3
"""
Starting from the AES-ECB live coding example, add functions so that the user can input an 
arbitrary text string. This text string should then be encrypted, and the ciphertext should be printed in the 
console. Be sure to check that your code can decrypt the ciphertext also. (Hint: Note that the code requires 
plaintext and ciphertext to be bytearrays.)
"""
def pad(message):
    padder = padding.PKCS7(128).padder()
    padded_msg = padder.update(message)
    padded_msg += padder.finalize()
    return padded_msg

def unpad(message):
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_msg = unpadder.update(message)
    unpadded_msg += unpadder.finalize()
    return unpadded_msg

def encrypt(message, cipher):
    message = pad(message)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message)
    ciphertext += encryptor.finalize()
    return ciphertext

def decrypt(ciphertext, cipher):
    decryptor = cipher.decryptor()
    decrypted_msg = decryptor.update(ciphertext)
    decrypted_msg += decryptor.finalize()
    decrypted_msg = unpad(decrypted_msg)
    return decrypted_msg

def ex3():
    key = os.urandom(16)
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    input_string = input("Enter string: ")
    ciphertext = encrypt(input_string.encode("UTF-8"), cipher)
    print("Encrypted ciphertext: ", ciphertext)

    plaintext = decrypt(ciphertext, cipher).decode()
    print("Decrypted plaintext: ", plaintext)

    print("Matches: ", input_string == plaintext)

# EXERCISE 4
"""
Modify the code from the previous exercise so that the user can choose whether to provide a key or 
have the program generate a key. Try to encrypt with simple keys such as the all-zeros bitstring
"""
def ex4():
    input_key = input("Input key (Enter a non-numeric value for an auto-generated key.): ")
    try:
        key = int(input_key)
    except ValueError:
        key = os.urandom(16)

    print("Key:", key)
    cipher = Cipher(algorithm=algorithms.AES(key), mode=modes.ECB())
    input_string = input("Enter string: ")
    ciphertext = encrypt(input_string.encode("UTF-8"), cipher)
    print("Encrypted ciphertext: ", ciphertext)

    plaintext = decrypt(ciphertext, cipher).decode()
    print("Decrypted plaintext: ", plaintext)

    print("Matches: ", input_string == plaintext)

# EXERCISE 5
"""
Consider the following key and nonce, here in their Base64 representation:
Key: WXvqxbAEEM08snXbYgu8bg==
Nonce: ZmRqZW1ma3Jtc2thbXNuZA==
Decrypt the following ciphertext (here in Base64) using AES in CTR mode:
M8owlYB5ewJJ2YFcdLdXJu0DHlv4+9iqUpdpJeRyH3SRqg==
(Hint: to convert from Base64 to bytearray, have a look at the Base64 module in Python)
"""
def aes_ctr_encrypt(key, nonce, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def aes_ctr_decrypt(key, nonce, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def ex5():
    key_base64 = "WXvqxbAEEM08snXbYgu8bg=="
    nonce_base64 = "ZmRqZW1ma3Jtc2thbXNuZA=="
    ciphertext_base64 = "M8owlYB5ewJJ2YFcdLdXJu0DHlv4+9iqUpdpJeRyH3SRqg=="

    key = base64.b64decode(key_base64)
    nonce = base64.b64decode(nonce_base64)
    ciphertext = base64.b64decode(ciphertext_base64)

    plaintext = aes_ctr_decrypt(key, nonce, ciphertext)
    print("Decrypted plaintext: ", plaintext.decode("UTF-8"))

    encrypted_ciphertext = aes_ctr_encrypt(key, nonce, plaintext)
    print("Original ciphertext: ", ciphertext)
    print("Newly encrypted ciphertext: ", encrypted_ciphertext)
    print("Matches: ", ciphertext == encrypted_ciphertext)

# EXERCISE 6
"""
In the previous exercise, how many blocks does the ciphertext have. Does the CTR mode use 
padding (why/why not?)

Answer:
The number of blocks is 34. However, CTR mode does not use padding because it transforms AES into a stream cipher
where ciphertext length equals plaintext length, eliminating the need for padding to fit into fixed-size blocks.
"""
def ex6():
    ciphertext_base64 = "M8owlYB5ewJJ2YFcdLdXJu0DHlv4+9iqUpdpJeRyH3SRqg=="
    ciphertext = base64.b64decode(ciphertext_base64)
    num_blocks = len(ciphertext)
    print("Number of blocks in ciphertext:", num_blocks)

# EXERCISE 7
"""
Note that CTR uses both a nonce and counter to encrypt data. However, you were only given the 
key and nonce (and not the counter). What does that mean for the value of the counter?

Answer:
In many cases, the counter starts at 0 or 1, but it ultimately depends on the specific cryptographic implementation or protocol.
In the Python cryptography library, if the counter is not explicitly initialized for the CTR mode, it is initialized to zero by default.
This means that the initial value of the counter is set to zero, and it is incremented automatically for each block of data processed during encryption or decryption.

Meaning, that in our specific scenario where the ciphertext has the block size of 34, the final counter value would be 33.
"""

# EXERCISE 8
"""
In this exercise, we are working with the stream cipher ChaCha20 in Python. See 
https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20 for usage and an example.
"""
def chacha20_encrypt(key, nonce, plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def chacha20_decrypt(key, nonce, ciphertext):
    backend = default_backend()
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

"""
(a): Encrypt the plaintext “Hello world” (without quotes) using the stream cipher ChaCha20. Be sure to generate 
a key and nonce properly. Print the ciphertext in the console, what do you see?
"""
def ex8():
    key = os.urandom(32)  # 256-bit key
    nonce = os.urandom(16)  # 128-bit nonce
    plaintext = b"Hello world"
    ciphertext = chacha20_encrypt(key, nonce, plaintext)
    print("Ciphertext: ", ciphertext.hex())

    """
    (b): Decrypt the ciphertext obtained in part (a), and check that the original plaintext and decrypted ciphertext are 
    equal (why do we want to check this?)
    """
    decrypted_plaintext = chacha20_decrypt(key, nonce, ciphertext)
    print("Decrypted plaintext: ", decrypted_plaintext.decode())

    """
    (c): Change one byte of the ciphertext and decrypt it using the same key and nonce as in part (a). What do you 
    observe?
    """
    modified_ciphertext = ciphertext[:5] + bytes([ciphertext[5] ^ 0x0A]) + ciphertext[6:]
    decrypted_modified_plaintext = chacha20_decrypt(key, nonce, modified_ciphertext)
    print("Decrypted modified plaintext:", decrypted_modified_plaintext.decode())

    """
    (d): Change one byte of the key and decrypt the ciphertext obtained in part (b). What do you see?
    """
    modified_key = key[:5] + bytes([key[5] ^ 0x0A]) + key[6:]
    try:
        decrypted_modified_key_plaintext = chacha20_decrypt(modified_key, nonce, ciphertext)
        print("Decrypted modified key plaintext: ", decrypted_modified_key_plaintext.decode())
    except Exception as e:
        print("Decryption failed due to incorrect key.", e)

def start():
    ex8()

start()