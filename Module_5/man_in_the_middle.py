import random

prime = 23
generator = 5

# Generate private key
def generate_private_key(prime):
    return random.randint(2, prime - 1)

# Calculate public key
def calculate_public_key(generator, private_key, prime):
    return pow(generator, private_key, prime)

def calculate_shared_secret(own_private_key, other_public_key, prime):
    return pow(own_private_key, other_public_key, prime)

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

    b_public_key_intercepted = c_public_key
    a_public_key_intercepted = d_public_key

    # Fradulent Shared Secrets
    shared_secret_cb = calculate_shared_secret(c_private_key, b_public_key_intercepted, prime)
    print("Shared Secret: ", shared_secret_cb)

    shared_secret_da = calculate_shared_secret(d_private_key, a_public_key_intercepted, prime)
    print("Shared Secret: ", shared_secret_da)

man_in_the_middle(prime, generator)