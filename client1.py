# print("Im the first client")
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from sympy import randprime
import random
import socket 
import hashlib
import time
PORT = 1535
IP = '127.0.0.1'
SPLITTER = "#"
LAST_VALUE = -1
NUMBER_NODES = 3
MILISECOND = 0.1
MIN_PRIME = 2
BUFFER_SIZE = 1024

index = 2

def diffie_hellman(client_soc):
    prime_str, generator_str  = client_soc.recv(BUFFER_SIZE).decode().split(",")
    prime = int(prime_str)
    generator = int(generator_str)
    
    private_num = random.randint(MIN_PRIME - 1, prime - 1)
    temp_key = pow(generator, private_num, prime)

    other_key = client_soc.recv(BUFFER_SIZE).decode()
    other_key = int(other_key)
    time.sleep(MILISECOND)
    client_soc.sendall(str(temp_key).encode())
    shared_key = pow(other_key, private_num, prime)
    return shared_key


    

def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with AES, return plaintext."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def node1(key: bytes, iv: bytes, ciphertext: bytes):
    global index
    index = index - 1
    cipher = aes_decrypt(key, iv, ciphertext)
    print("cipher after node1: ", cipher.hex())
    return cipher

def node2(key: bytes, iv: bytes, ciphertext: bytes):
    global index
    index = index - 1
    cipher = aes_decrypt(key, iv, ciphertext)
    print("cipher after node2: ", cipher.hex())
    return cipher

def node3(key: bytes, iv: bytes, ciphertext: bytes):
    global index
    index = index - 1
    cipher = aes_decrypt(key, iv, ciphertext)
    print("cipher after node3: ", cipher.hex())
    return cipher

def main():
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    

    # Connecting to the other client
    client2_address = (IP, PORT)
    sock.connect(client2_address)

    #SEND MESSAGE TO CLIENT2
    msg = "first client says hello!!!"
    sock.sendall(msg.encode())
    #GET MESSAGE  FROM CLIENT2 
    client2_msg = sock.recv(BUFFER_SIZE)
    client2_msg = client2_msg.decode()
    print(client2_msg)

    key_list = [diffie_hellman(sock) for _ in range(NUMBER_NODES)]
    aes_key_list = []

    for dh_key in key_list:
        # Convert int -> bytes 
        key_bytes = str(dh_key).encode()
        aes_key = hashlib.sha256(key_bytes).digest()
        aes_key_list.append(aes_key)

    client2_msg = sock.recv(BUFFER_SIZE).decode()
    parts = client2_msg.split(SPLITTER)

    iv_list = [bytes.fromhex(iv_hex) for iv_hex in parts[:LAST_VALUE]]
    ct_str = parts[LAST_VALUE]
    
    cipher = node1(aes_key_list[index], iv_list[index], bytes.fromhex(ct_str))    
    cipher = node2(aes_key_list[index], iv_list[index], cipher)    
    cipher = node3(aes_key_list[index], iv_list[index], cipher)

    print ("message is: ", cipher.decode())
    sock.close()





if __name__ == "__main__":
    main()