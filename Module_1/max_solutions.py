import os

## EXERCISE 1
"""
Write a Python program which takes a string as input, and prints the individual byte values of the 
string.
"""
def ex1():
    input_string = input("Enter string: ")
    bytes_data = input_string.encode('UTF-8')
    for byte in bytes_data:
        print(byte)

## EXERCISE 2
"""
Write a Python program which takes a positive integer as input and prints the binary and 
hexadecimal representation of this integer.
"""
def ex2():
    input_pos_int = int(input("Enter positive integer: "))
    if (input_pos_int > 0):
        int_bin = bin(input_pos_int)
        int_hex = hex(input_pos_int)
    print(input_pos_int, int_bin, int_hex)
    
## EXERCISE 3
"""
Write a Python program which takes a text string as input and saves it as UTF-8 encoded variable. 
Test if it works when using Danish letters such as æ, ø, å.
"""
def ex3():
    input_string = input("Enter string: ")
    input_string_encoded = input_string.encode('UTF-8')
    print(input_string, input_string_encoded)

## EXERCISE 4
"""
Repeat the previous exercise but encode the string in ASCII instead of UTF-8. Does it work? Why or 
why not?

Answer: ASCII alternative does not support special characters (e.g.: ø, æ, å), as it is beyond its range.
"""
def ex4():
    input_string = input("Enter string: ")
    input_string_encoded = input_string.encode('ASCII')
    print(input_string, input_string_encoded)

## EXERCISE 5
"""
Write a Python program that opens a PNG file in binary mode and prints the first 8 bytes of the file 
(its signature). Compare with https://en.wikipedia.org/wiki/Portable_Network_Graphics#File_header
"""
def ex5():
    image_dir = os.path.dirname(os.path.realpath(__file__))
    file = open(image_dir + "\\dice.png", "rb")
    firstbytes = file.read(8)
    wikibytes = bytes([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
    i = 0

    for byte in firstbytes:
        print(hex(byte), hex(wikibytes[i]))
        i += 1

## EXERCISE 6
"""
 Let plaintext = 0b1100 and key = 0b1001. (Note: in Python, you can define an integer by using e.g. x 
= 0b1111 (which will create a variable called x with the value 15). Also note that XOR is only defined between 
two integers.
"""
def ex6():
    plaintext = 0b1100
    key = 0b1001

    """
    (a): Compute the XOR of plaintext and key, call this the ciphertext.
    """
    ciphertext = plaintext ^ key
    print(ciphertext)

    """
    (b): Compute the XOR of ciphertext and the key. What do you observe?

    Answer: The ciphertext is decoded back to the plaintext.
    """
    ck_xor = ciphertext ^ key
    print(ck_xor)

    """
    (c): Change one bit of the ciphertext, and compute the XOR of it and the key. What happens to the plaintext? 
    (Note: This property is called malleability.)

    Answer: The plaintext changes, meaning a potential attacker can make controlled changes to the ciphertext,
    and in turn modify the plaintext without necessarily having access to the encryption key,
    rendering malleability an undesired property that should be taken into consideration when designing a cryptographic protocol.
    """
    ciphertext = 0b100 # original bit value: 0b101
    ck_xor = ciphertext ^ key
    print(ck_xor, plaintext)

## EXERCISE 7
"""
On paper and in Python, compute the following remainders (note that the remainder must always be 
positive):

On paper:  
"""
def ex7():
    """
    (a): 5 mod 21
    """
    a = 5 % 21
    print(a)

    """
    (b): 17 mod 11
    """
    b = 17 % 11
    print(b)

    """
    (c): -27 mod 23
    """
    c = -27 % 23
    print(c)

## EXERCISE 8
"""
Why is the OTP not used for communication over the Internet?

Answer: 
The One-Time Pad (OTP) is a theoretically perfect encryption technique when implemented correctly.
It provides unconditional security, meaning that if properly implemented, it is impossible for an attacker to gain any information
about the plaintext from the ciphertext, regardless of computational resources.

However, despite its theoretical perfection, OTP is impractical for many real-world scenarios,
particularly for communication over the Internet, due to several limitations:

Key Management: Each key in OTP must be at least as long as the message being encrypted, and the key must be truly random
and only used once. Generating and securely exchanging such large, random keys for every message exchange
is extremely impractical, especially for large volumes of data.

Key Distribution: Securely distributing the keys to both the sender and the receiver is a significant challenge.
If the keys are compromised during distribution, the security of the entire communication is compromised.

Key Storage: Since the keys need to be as long as the message and must be kept secret, storing and managing
such large keys securely is difficult.

Key Reuse: Reusing keys in OTP compromises its security. If a key is used more than once,
patterns may emerge in the ciphertext that could potentially be exploited by attackers.

Computational Overhead: Encrypting and decrypting messages using OTP can be computationally intensive,
especially for large messages. Additionally, both the sender and receiver need to perform the same encryption
and decryption process, which requires computational resources.

Communication Channel Constraints: OTP assumes a perfect communication channel where the ciphertext is transmitted without
error. In real-world scenarios, communication channels may introduce errors or loss of data,
which can corrupt the ciphertext and make decryption impossible.
"""

## EXERCISE 9
"""
Implement a fixed-XOR function using the instructions here: 
https://cryptopals.com/sets/1/challenges/2

Instructions:

Fixed XOR
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
"""
def ex9():
    string = "1c0111001f010100061a024b53535009181c"
    key = "686974207468652062756c6c277320657965"
    intended_result = "746865206b696420646f6e277420706c6179"

    decoded_string = int(string, 16)
    decoded_key = int(key, 16)

    result = decoded_string ^ decoded_key
    result_hex = format(result, 'x')

    print("Result:", result, result_hex)
    print("Intended result:", intended_result)
    print("Matched:", result_hex == intended_result)

## EXERCISE 10
"""
Consider the following Python code for simple random number generation:

import random, time
current = time.time()
random.seed(current)
r1 = random.randrange(0, 65534)
random.seed(current)
r2 = random.randrange(0, 65534)
print(r1)
print(r2)

Does this code produce consecutive random numbers? If not, suggest an improvement.

Answer: The code above does not produce consecutive random numbers, because it is reseeding the generator BEFORE
generating each random number. This resets the generator's internal state, meaning the sequence of numbers will not be
consecutive.

Solution below, where the random numbers are generated from the same sequence, rendering them consecutive:
"""
def ex10():
    import random, time
    current = time.time()
    random.seed(current)

    r1 = random.randrange(0, 65534)
    r2 = random.randrange(0, 65534)

    print(r1, r2)

## EXERCISE 11
"""
Study which random number generators are available in the standard library of a programming 
language of your choice? Are cryptographically secure options available?

Answer:

In Python's standard library, the random module provides several functions for generating random numbers. These functions are based on the Mersenne Twister pseudo-random number generator algorithm.

Here are some of the main functions provided by the random module:

random.random(): Generates a random floating-point number in the range [0.0, 1.0).
random.randint(a, b): Generates a random integer in the range [a, b] (inclusive).
random.randrange(start, stop[, step]): Generates a random integer from the range start (inclusive) to stop (exclusive) with an optional step size.
random.choice(seq): Returns a random element from the non-empty sequence seq.
random.shuffle(seq): Shuffles the elements of the sequence seq in place.
random.sample(population, k): Returns a k-length list of unique elements chosen from the population sequence.

While these functions are suitable for many applications, they are not suitable for cryptographic purposes as they are not cryptographically secure. For cryptographic purposes, Python's secrets module should be used instead,
which provides functions for generating cryptographically secure random numbers.

Here are some functions provided by the secrets module:

secrets.randbelow(n): Returns a random integer in the range [0, n) using a cryptographically secure random number generator.
secrets.randbits(k): Returns a random integer with k random bits using a cryptographically secure random number generator.
secrets.choice(seq): Returns a random element from the non-empty sequence seq using a cryptographically secure random number generator.
secrets.token_bytes(n): Returns n random bytes using a cryptographically secure random number generator.
secrets.token_hex(nbytes=None): Returns a random hexadecimal string containing nbytes of random bytes, or nbytes//2 characters if nbytes is not specified, using a cryptographically secure random number generator.
secrets.token_urlsafe(nbytes=None): Returns a random URL-safe string containing nbytes of random bytes, or nbytes//3 * 4 characters if nbytes is not specified, using a cryptographically secure random number generator.
These functions in the secrets module are specifically designed to be suitable for cryptographic purposes and should be used when security is a concern.
"""

## EXERCISE 12
"""
What are the advantages and disadvantages of using an RNG instead of an PRNG?

Answer:
Advantages of RNGs (Random Number Generators):
True Randomness: RNGs generate random numbers based on truly unpredictable physical processes, such as radioactive decay or atmospheric noise.
This ensures that the generated numbers are truly random and not deterministic like those from PRNGs.

Unpredictability: RNGs produce numbers that are unpredictable, making them suitable for cryptographic applications where unpredictability is essential.

Statistical Properties: RNGs typically have good statistical properties, such as uniform distribution and independence between successive random numbers.

Security: RNGs are considered more secure than PRNGs for cryptographic purposes because they are not susceptible to predictability based on initial seed values or internal state.

Disadvantages of RNGs:
Hardware Requirements: RNGs often require specialized hardware to generate random numbers from physical processes, which can be expensive and less practical for general-purpose computing.

Speed: Generating truly random numbers can be slower than generating pseudo-random numbers using algorithms, especially when relying on physical processes with inherent limitations in speed.

Limited Availability: True RNGs may not be readily available on all platforms, limiting their widespread use compared to PRNGs, which are typically built into programming languages and libraries.

Bias and Non-Uniformity: Some sources of randomness may introduce biases or non-uniformity in the generated random numbers, affecting their statistical properties.


Advantages of PRNGs (Pseudo-Random Number Generators):
Speed: PRNGs are generally much faster than RNGs because they use deterministic algorithms to generate random-like sequences.

Determinism: PRNGs produce deterministic sequences of numbers based on a seed value, making them suitable for simulations, testing, and other applications where repeatability is desired.

Portability: PRNGs are built into most programming languages and libraries, making them readily available and easy to use across different platforms and environments.

Control: PRNGs allow for greater control over the generated sequences, such as specifying seed values or using different algorithms for different requirements.

Disadvantages of PRNGs:
Predictability: PRNGs are deterministic, meaning that given the same initial seed value, they will produce the same sequence of numbers. This predictability can be exploited by attackers in cryptographic applications.

Periodicity: PRNGs have a finite period after which the sequence of numbers repeats. If the period is short or the sequence becomes predictable, it can lead to security vulnerabilities.

Seed Sensitivity: PRNGs are sensitive to the seed value used to initialize them. If the seed is not carefully chosen, it can lead to correlated sequences or security vulnerabilities.

Statistical Properties: While good PRNGs strive to produce sequences with good statistical properties, they may exhibit biases or correlations that can affect their suitability for certain applications, especially in cryptography.

In summary, the choice between using an RNG and a PRNG depends on the specific requirements of the application, including factors such as speed, security, predictability,
and availability of hardware resources. RNGs are preferred for cryptographic applications, where true randomness and unpredictability are critical,
while PRNGs are more suitable for applications where speed, repeatability, and control are prioritized
"""
## EXERCISE 13
"""
Implement a naive random number generator for generating numbers in the range 0 to 191, as 
follows: Start by generating a random 8-bit value and interpreting it as an integer. Then reduce this integer 
modulo 192. Generate many integers in this way and check the probability distribution of the resulting numbers.
"""
def naive_random_number():
    import random
    random_number = random.randrange(0, 256)
    result = random_number % 192
    return result

def check_probability_distribution(num_samples):
    frequency = [0] * 192
    for _ in range(num_samples):
        number = naive_random_number()
        frequency[number] += 1

    probabilities = [count / num_samples for count in frequency]
    return probabilities

def ex13():
    num_samples = 1000
    probabilities = check_probability_distribution(num_samples)

    for number, probability in enumerate(probabilities):
        print(f"Number: {number}, Probability: {probability}")
    
## EXERCISE 14
"""
Read the webpage https://inversegravity.net/2019/password-entropy/ about entropy of passwords. 
What is the main takeaway of this article?

Answer:
Password Entropy: Password entropy is a measure of the unpredictability of characters in a string. It is based on the number of characters (the character set) and the length of the password.
A password with high entropy is theoretically harder to brute force.

Entropy Calculation: Entropy is calculated using the formula H = log2(N^L), where H is the entropy, N is the character set or number of possible symbols, and L is the length of the password.
The higher the entropy, the stronger the password.

Character Sets and Entropy: Different character sets have different entropy per symbol. For example, a password composed of Arabic numerals (0-9) has an entropy of approximately 3.322 bits per symbol,
while a password composed of all ASCII printable characters has an entropy of approximately 6.570 bits per symbol.

Human-generated Passwords: People tend to create passwords with lower entropy than randomly generated passwords. Common human behaviors, such as using common words, patterns, or predictable variations,
reduce the effective strength of passwords.

Password Guidelines: The article provides guidelines for creating strong passwords, including using password managers to generate random passwords, using a minimum password length of 12 or more characters,
and avoiding common patterns or easily guessable information.

Overall, the article emphasizes the importance of understanding password entropy and following best practices to create strong and secure passwords that are resistant to brute force attacks.

"""
## EXERCISE 15
"""
Implement a single-byte XOR cipher using the instructions here: 
https://cryptopals.com/sets/1/challenges/3

Instructions:

Single-byte XOR cipher
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
"""

def single_byte_xor_cipher(hex_string):
    ciphertext = bytes.fromhex(hex_string)
    max_score = 0
    best_key = None
    plaintext = None

    for key in range(256):
        decrypted = bytes([byte ^ key for byte in ciphertext])

        score = sum(chr(byte).lower() in 'etaoin shrdlu' for byte in decrypted)

        if score > max_score:
            max_score = score
            best_key = key
            plaintext = decrypted
    print(plaintext)
    return best_key, plaintext.decode()

def ex15():
    hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

    key, decrypted_message = single_byte_xor_cipher(hex_string)
    print("Key:", key)
    print("Decrypted message:", decrypted_message)
    
## EXERCISE 16 [WIP - Encountering a decoder error (lingering whitespaces...?)]
"""
Brute-force single-byte XOR cipher using the instructions here: 
https://cryptopals.com/sets/1/challenges/4

Instructions:

Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)

The file: https://cryptopals.com/static/challenge-data/4.txt
"""
def detect_single_byte_xor(strings):
    best_score = 0
    best_plaintext = None
    best_key = None

    for hex_string in strings:
        key, plaintext = single_byte_xor_cipher(hex_string) # method reused from exercise 15
        score = sum(chr(byte).lower() in 'etaoin shrdlu' for byte in plaintext.encode())
        if score > best_score:
            best_score = score
            best_plaintext = plaintext
            best_key = key
    
    return best_key, best_plaintext

def ex16():
    file_dir = os.path.dirname(os.path.realpath(__file__))
    file = open(file_dir + "\\4.txt", "r")
    strings = [line for line in file]

    key, plaintext = detect_single_byte_xor(strings)
    print("Key:", key)
    print("Plaintext:", plaintext)

## EXERCISE 17
"""
Implement repeating-key XOR using the instructions here: 
https://cryptopals.com/sets/1/challenges/5

Instructions:

Implement repeating-key XOR
Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
"""
def repeating_key_xor(plaintext, key):
    encrypted_bytes = bytearray()
    key_length = len(key)
    for i, byte in enumerate(plaintext):
        encrypted_byte = byte ^ key[i % key_length]
        encrypted_bytes.append(encrypted_byte)
    return encrypted_bytes.hex()

def ex17():
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"
    encrypted_text = repeating_key_xor(plaintext.encode(), key.encode())
    ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    print(encrypted_text)
    print(ciphertext)
    print(encrypted_text == ciphertext)

def start():
    ex17()

start()