"""
Module 5, Exercise 4: Diffie-Hellman Key Exchange

"""
from cryptography.hazmat.primitives.asymmetric import rsa
import random

# Generate private key
def generate_private_key(prime): # exponent
    return random.randint(2, prime - 1)

# Calculate public key
def calculate_public_key(generator, private_key, prime):
    return pow(generator, private_key, prime)

def calculate_shared_secret(own_private_key, other_public_key, prime):
    return pow(own_private_key, other_public_key, prime)

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

prime = 23 # modulus
generator = 5 # base
shared_secret = diffie_hellman(prime, generator)
print("Shared secret: ", shared_secret)