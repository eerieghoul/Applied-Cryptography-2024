import socket

# EXERCISE 1
"""
In this exercise, you are to implement a rudimentary chat client. This is to be done using socket 
programming. Start by downloading the client and server scripts from the course Github page.
"""
def ex1():
    def server():
        HOST = '127.0.0.1' # Localhost
        PORT = 9999 # Choose port above 1024

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((HOST, PORT))
            sock.listen()
            conn, addr = sock.accept()
            with conn:
                print("Connection received from:", addr)
                while True:
                    # Receives data from server
                    r_data = conn.recv(1024)
                    print("Received data:", r_data)

                    # Enters data and sends it to client
                    s_data = input("Enter data to send: ").encode('UTF-8')
                    conn.sendall(s_data)
    
    def client():
        HOST = '127.0.0.1' # Localhost
        PORT = 9999 # Choose port above 1024

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            while True:
                # Enters data and sends it to server
                s_data = input("Enter data to send:").encode('UTF-8')
                sock.sendall(s_data)

                # Receives data from server
                r_data = sock.recv(1024)
                print("Received data:", r_data)

# EXERCISE 2
"""
Modify the chat client so that messages exchanged are encrypted before they are sent. For this, use 
the AES-CTR mode (see previous lecture on Github for example code). Assume here that both client and server 
have the same key and nonce (note that these must be in bytes format).
"""
def ex2():
    def server():
        HOST = '127.0.0.1' # Localhost
        PORT = 9999 # Choose port above 1024

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((HOST, PORT))
            sock.listen()
            conn, addr = sock.accept()
            with conn:
                print("Connection received from:", addr)
                while True:
                    # Receives data from server
                    r_data = conn.recv(1024)
                    print("Received data:", r_data)

                    # Enters data and sends it to client
                    s_data = input("Enter data to send: ").encode('UTF-8')
                    conn.sendall(s_data)
    
    def client():
        HOST = '127.0.0.1' # Localhost
        PORT = 9999 # Choose port above 1024

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            while True:
                # Enters data and sends it to server
                s_data = input("Enter data to send:").encode('UTF-8')
                sock.sendall(s_data)

                # Receives data from server
                r_data = sock.recv(1024)
                print("Received data:", r_data)
    
    client()
    server()

# EXERCISE 3
"""
Modify the chat client so that a shared secret is established before encrypted communication is 
done. The shared secret should be established using the anonymous Diffie-Hellman key exchange (see the 
slides). For the Diffie-Hellman parameters, use g=5 and p=23.

Hint 1: Note that server and client must generate their own secret values. What are the allowed values of those?

Hint 2: When sending the common value from client to server (or vice-versa), not that you can only send bytes 
through a socket connection. So, you need some way to convert the integers from the Diffie-Hellman 
computation into bytes.

Hint 3: When deriving a key from the common value, start by using a hash function for the derivation. Note that 
the purpose of doing this is to get a key for the AES-CTR encryption. It is however better to use another 
cryptographic method for key derivation. Can you see which?
"""

def start():
    ex2()

start()