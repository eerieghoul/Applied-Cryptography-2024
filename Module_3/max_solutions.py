from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# EXERCISE 1
"""
This exercise is about Python bytearrays. Solutions are on the Github page.
"""
def ex1():
    """
    (a): Begin by defining an empty bytearray, call it barr1. Also, define a bytes-object with contents “Python 3 
    programming”. Call it barr2.
    """
    barr1 = bytearray()
    barr2 = b"Python 3 programming"

    """
    (b): Copy the contents of barr2 into barr1, except that the “3” should be a “2”. In other words, the resulting 
    bytearray should read: “Python 2 programming” (Hint: Like lists, you can slice bytearrays: for example, use 
    barr1[0:4] to get the first 4 bytes from barr1.)
    """
    barr1 = bytearray(barr2)
    barr1[7] = ord('2')

    """
    (c): Compute the number of bytes in barr1 and barr2. (Hint: this is like computing the number of elements in a 
    list)
    """
    num_bytes_barr1 = len(barr1)
    num_bytes_barr2 = len(barr2)

    """
    (d): What is the value and type of the fifth byte in barr1?
    """
    fifth_byte_value = barr1[4]
    fifth_byte_type = type(fifth_byte_value)

    """
    (e): Use a Python-builtin function to find the ASCII character of the fifth byte in barr1?
    """
    fifth_byte_ascii = chr(fifth_byte_value)

    """
    (f): Use a Python-builtin function to print the hexadecimal representation of the bytearray barr1.
    """
    hex_representation_barr1 = barr1.hex()

    print("Number of bytes in barr1:", num_bytes_barr1)
    print("Number of bytes in barr2:", num_bytes_barr2)
    print("Value of the fifth byte in barr1:", fifth_byte_value)
    print("Type of the fifth byte in barr1:", fifth_byte_type)
    print("ASCII character of the fifth byte in barr1:", fifth_byte_ascii)
    print("Hexadecimal representation of barr1:", hex_representation_barr1)

# EXERCISE 2
"""
Begin by encrypting a string of your own choosing using AES-CTR. Then, change one byte in the 
ciphertext, and try to decrypt this modified ciphertext using the same key as before. Does it work, and if so, what 
is the (modified?) plaintext?

Answer: 
Original plaintext: Hello, this is a test string to encrypt using AES-CTR.
Modified plaintext: Hello& this is a test string to encrypt using AES-CTR.

Also change one byte in the key, can you decrypt using the modified key?

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

key = os.urandom(32) 
nonce = os.urandom(16)

def ex2():
    plaintext = b"Hello, this is a test string to encrypt using AES-CTR."
    ciphertext = aes_ctr_encrypt(key, nonce, plaintext)
    modified_ciphertext = ciphertext[:5] + bytes([ciphertext[5] ^ 0x0A]) + ciphertext[6:]

    try:
        decrypted_modified_plaintext = aes_ctr_decrypt(key, nonce, modified_ciphertext)
        print("Decrypted modified plaintext:", decrypted_modified_plaintext.decode())
    except Exception as e:
        print("Decryption with modified ciphertext using original key and nonce failed:", str(e))

    modified_key = key[:5] + bytes([key[5] ^ 0x0A]) + key[6:]
    try:
        decrypted_modified_key_plaintext = aes_ctr_decrypt(modified_key, nonce, ciphertext)
        print("Decrypted modified key plaintext: ", decrypted_modified_key_plaintext.decode())
    except Exception as e:
        print("Decryption failed due to incorrect key.", e)

# EXERCISE 3
"""
Generate a random ciphertext and decrypt it using the same key and nonce as in the previous 
exercise. Does it work? Why/why not?

Answer:
The decryption fails because the random ciphertext generated in this exercise is not encrypted using the same key and nonce as used in the previous exercise.
In symmetric encryption schemes like AES-CTR, the decryption process requires the exact same key and nonce that were used during encryption.

Since the random ciphertext is generated independently of the key and nonce used in the previous exercise, there is no guarantee that they match.
Therefore, attempting to decrypt the random ciphertext with the original key and nonce will likely result in failure,
as the ciphertext was not encrypted with those specific parameters.
"""
def ex3():
    random_ciphertext = os.urandom(32)
    try:
        decrypted_random_plaintext = aes_ctr_decrypt(key, nonce, random_ciphertext)
        print("Decrypted random plaintext:", decrypted_random_plaintext.decode())
    except Exception as e:
        print("Decryption with random ciphertext using original key and nonce failed:", str(e))

def start():
    ex3()

start()
