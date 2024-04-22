import random

# EXERCISE 1
"""
Consider RSA, where your private key is d = 937 and your public key is (n, e) = (2537, 13). You 
receive the ciphertext c = 2222.
"""

"""
(a): What is the modulus in this setup?

Answer: To find the modulus (n), we use the public key provided, 
which is (n, e) = (2537, 13). Therefore, the modulus (n) is 2537.
"""

"""
(b): Decrypt the ciphertext you received, what do you get?

Answer: To decrypt the ciphertext (c) using the private key (d), 
we use the RSA decryption formula: m = c^d mod n

c = 2222
d = 937
n = 2537

m = 2222^937 mod 2537 = 18
"""

"""
(c): Encrypt the plaintext obtained in part (b). What do you observe?

Answer: To encrypt the plaintext obtained in part (b) using the public key, 
we use the RSA encryption formula: c = m^e mod n

m (plaintext obtained in (b) = 18
e = 13
n = 2537

c = 18^13 mod 2537 = 2222

We observe that the ciphertext obtained after encryption (c) is the same as the original ciphertext provided (a).
This is because the encryption and decryption operations using RSA are inverse operations of each other 
when using the correct keys. Therefore, encrypting the decrypted plaintext yields the original ciphertext.
"""

# EXERCISE 2
"""
This exercise is about malleability of RSA. We use the private key d = 937 and public key (n, e) = 
(2537, 13). Note that these are the same as in the previous exercise.
"""

"""
(a): Choose two different plaintexts (i.e. integers) that you want to encrypt. Encrypt these using the given RSA 
parameters.

Answer: We'll choose two different plaintexts (integers) and encrypt them using the given RSA parameters.

m1 = 5
m2 = 8
public key (n, e) = (2537, 13)

c1 = m1^e mod n
c1 = 5^13 mod 2537
c1 = 205

c2 = m2^e mod n
c2 = 8^13 mod 2537
c2 = 156
"""

"""
(b): Multiply the two ciphertexts and then decrypt the result of the multiplication. What do you observe in the 
decryption of the recovered plaintext with respect to the two plaintexts in part (a)?

Answer: Let's calculate the encryption of the plaintexts and then perform the multiplication and decryption using
the formula m = c^d mod n

private key (d) = 937
c = m1 * m2 = 205 * 156 = 31980
m = c^d mod n = 31980^937 mod 2537 = 40

Observation: When we decrypt the result of the multiplication, we obtain a value (approximately 40) that is different from both plaintexts 
(5 and 8, respectively).

This observation demonstrates the malleability of RSA encryption, where an attacker can manipulate ciphertexts 
by performing mathematical operations on them, resulting in a related plaintext when decrypted. 

The resulting plaintext obtained after decryption corresponds to the product of the original plaintexts. 
This demonstrates the malleability of RSA encryption in this specific scenario. 

An attacker, by manipulating ciphertexts (in this case, by multiplying them), 
can influence the resulting plaintext upon decryption.
"""

# EXERCISE 3
"""
In this exercise, you are to encrypt and decrypt a message using RSA in the Cryptography library. 
Start by downloading today’s RSA starter-code from GitHub.
"""

"""
(a): Run the code which generates RSA keys and saves them in separate PEM files. You should now have two 
PEM files, one for the private key and one for the public key. Use the parameter 65537 as public exponent, and 
a key size of 2048 when generating the keys.
"""

"""
(b): Encrypt a message of you own choice using RSA, using the code you downloaded. Use the public key for 
encrypting your message.
"""

"""
(c): Decrypt the message you encrypted in the previous part. Which key do you need to use?

Answer: The corresponding private key obtained in part (a) to decrypt the message encrypted in part (b). 
"""

"""
(d): Encrypt the file Dice.png using RSA. Does it work? If not, what is the problem?

Answer: Encryption failed, likely due to the size of Dice.png.
"""

"""
(e): Check what is the largest number of bytes you can encrypt using RSA with the specified parameters. (Hint: 
it is sufficient to test with random plaintexts)

Answer: In RSA encryption, the maximum size of the plaintext that can be encrypted is determined by the size 
of the key and the padding scheme used. With a 2048-bit key size, the maximum plaintext size that can be 
encrypted depends on the padding scheme, typically OAEP (Optimal Asymmetric Encryption Padding).

For RSA with OAEP padding, the maximum plaintext size that can be encrypted is calculated as:
Max plaintext size = (Key size / 8 - 2) * (Hash Size - 2)

With OAEP padding using a typical hash function like SHA-256 (32 bytes hash size),
the maximum plaintext size would be 2048 / 8 - 2 * 32 - 2 = 190 bytes.
"""

"""
(f): Based on the above, do you think that RSA is suitable for encrypting large files? If not, suggest an 
alternative approach.

Answer: Instead of using RSA directly for encrypting large files, a common approach is to use a hybrid encryption scheme, 
where RSA is used for encrypting a symmetric encryption key, and symmetric encryption (such as AES) is used to encrypt the actual file data. 
This approach combines the security benefits of asymmetric and symmetric encryption while mitigating the limitations of RSA for handling large amounts of data.
"""

# EXERCISE 4
"""
Write a Python program which implements the anonymous Diffie-Hellman key exchange. Use p=23 
and g=5 as parameters. For this part, it is sufficient to test the key exchange in the same script.
"""
prime = 23 # modulus
generator = 5 # base

def generate_private_key(prime):
        return random.randint(2, prime - 1)

def calculate_public_key(generator, private_key, prime):
    return pow(generator, private_key, prime)

def calculate_shared_secret(own_private_key, other_public_key, prime):
    return pow(other_public_key, own_private_key, prime)

def ex4():
    def diffie_hellman(prime, generator):
        # Alice's side
        a_private = generate_private_key(prime)
        a_public = calculate_public_key(generator, a_private, prime)
    
        # Bob's Side
        b_private = generate_private_key(prime)
        b_public = calculate_public_key(generator, b_private, prime)

        a_shared_secret = calculate_shared_secret(a_private, b_public, prime)
        print("Alice's shared secret: ", a_shared_secret)

        b_shared_secret = calculate_shared_secret(b_private, a_public, prime)
        print("Bob's shared secret: ", b_shared_secret)

        if (a_shared_secret == b_shared_secret):
            return a_shared_secret
        else: return False

    shared_secret = diffie_hellman(prime, generator)
    print("Shared secret: ", shared_secret)
    
# EXERCISE 5
"""
Continuing with Diffie-Hellman, using the same parameters as in the previous exercise, write a 
Python program that implements a Man-in-the-Middle attack (see the slides for hints)
"""
def ex5():
    def man_in_the_middle(prime, generator):
        # Alice's Side
        a_private_key = generate_private_key(prime)
        a_public_key = calculate_public_key(generator, a_private_key, prime)

        # Bob's Side
        b_private_key = generate_private_key(prime)
        b_public_key = calculate_public_key(generator, b_private_key, prime)

        # Attacker's Side
        c_private_key = generate_private_key(prime)
        c_public_key = calculate_public_key(generator, c_private_key, prime)

        d_private_key = generate_private_key(prime)
        d_public_key = calculate_public_key(generator, d_private_key, prime)
    
        # Man-in-the-Middle Interception
        # Attacker intercepts Bob's public key and sends it to Alice
        b_public_key_intercepted = c_public_key

        # Attacker intercepts Alice's public key and sends it to Bob
        a_public_key_intercepted = d_public_key
        
        # Fradulent Shared Secrets
        # Attacker computes shared secret with Bob's intercepted public key
        shared_secret_cb = calculate_shared_secret(c_private_key, b_public_key_intercepted, prime)
        print("Shared Secret: ", shared_secret_cb)

        # Attacker computes shared secret with Alice's intercepted public key
        shared_secret_da = calculate_shared_secret(d_private_key, a_public_key_intercepted, prime)
        print("Shared Secret: ", shared_secret_da)

    man_in_the_middle(prime, generator)

# EXERCISE 6
"""
Why are nonces used in the handshake in TLS?

Answer: To ensure the freshness of cryptographic material and to prevent replay attacks. 
Each party generates a nonce and includes it in its handshake messages. 
Nonces help ensure that each handshake session is unique, even if the same parties establish multiple connections.
"""

# EXERCISE 7
"""
Suppose Alice and Bob communicate over TLS. How can Alice be sure that she is in fact 
communicating with Bob?

Answer: Alice can verify Bob's identity through the use of certificates. 
During the TLS handshake, Bob presents his digital certificate, which includes his public key 
and identity information, signed by a trusted Certificate Authority (CA). Alice can verify the certificate's 
authenticity using the CA's public key, ensuring that she is indeed communicating with the entity claiming to be Bob.
"""

# EXERCISE 8
"""
How does TLS prevent MITM attacks?

Answer: TLS prevents MITM (Man-in-the-Middle) attacks through various mechanisms, including:

Certificate validation: TLS ensures the authenticity of communication endpoints by verifying 
digital certificates presented during the handshake.

Encryption: TLS encrypts communication between endpoints, making it difficult for an attacker to intercept
 and modify data.

Key exchange: TLS uses secure key exchange protocols like Diffie-Hellman to establish 
shared secret keys between endpoints, preventing eavesdropping and tampering.
"""

# EXERCISE 9
"""
Suppose Bob initiates a TCP connection with Eve who is pretending to be Alice. During the 
handshake, Eve sends Alice’s certificate to Bob. In what step of the handshake algorithm will Bob discover that 
he’s not communicating with Alice?

Answer: Bob will likely discover that he's not communicating with Alice during the certificate verification
step of the handshake algorithm. If the certificate presented by Eve (pretending to be Alice) 
is invalid or not trusted, Bob's TLS implementation will fail the certificate validation process, 
indicating that the entity claiming to be Alice is not authentic.
"""

# EXERCISE 10
"""
What is the purpose of the Preshared Master Secret?

Answer: The Preshared Master Secret (PMS) is used in TLS to derive session keys for symmetric 
encryption and integrity protection. It is derived from pre-shared secrets exchanged between the 
client and server during the handshake process. The PMS ensures that session keys are unique to each 
TLS session and are not predictable by attackers.
"""

# EXERCISE 11
"""
Why is the symmetric encryption key used when Alice sends data to Bob different from the 
symmetric encryption key used when Bob sends data to Alice?

Answer: This approach, known as Forward Secrecy or Perfect Forward Secrecy (PFS),
ensures that compromising one session's symmetric encryption key does not compromise the confidentiality
of past or future sessions. Each session negotiates and uses a unique symmetric encryption key,
 providing stronger security guarantees against long-term key compromise.
"""

# EXERCISE 12 
"""
What is the purpose of using a MAC in TLS?

Answer: To provide integrity protection for transmitted data. The MAC ensures that the data received 
by the recipient has not been tampered with during transmission. 
It is computed using a shared secret key and included in each TLS record alongside the encrypted data.
"""

# EXERCISE 13
"""
Suppose Alice and Bob are communicating over an TLS session. Suppose an attacker, who does 
not have any of the shared keys, inserts a bogus TCP segment into a packet stream with correct TCP 
checksum and sequence numbers (and correct IP addresses and port numbers). Will SSL at the receiving side 
accept the bogus packet and pass the payload to the receiving application? Why or why not?

Answer: No, SSL/TLS at the receiving side will not accept the bogus packet and pass the payload to 
the receiving application. Even if the TCP segment has correct checksums and sequence numbers, 
SSL/TLS verifies the integrity of the payload using the MAC, which is computed using shared secret keys 
negotiated during the handshake. Since the attacker does not possess these keys, the MAC verification will fail,
 and the SSL/TLS layer will reject the packet.
"""

def start():
    ex5()

start()