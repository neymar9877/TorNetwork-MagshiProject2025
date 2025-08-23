#print("Im the second client")
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib
import random
from sympy import randprime
import socket
import time
PORT = 1535
IP = '127.0.0.1'
SPLITTER = "#"
NUMBER_NODES = 3
MILISECOND = 0.1
IV_SIZE = 16
MAX_PRIME = 10000
MIN_PRIME = 2
BUFFER_SIZE = 1024

def diffie_hellman(sock):
    prime = randprime(MIN_PRIME, MAX_PRIME)
    generator = 2
    param_str = f"{prime},{generator}".encode()
    time.sleep(MILISECOND)
    sock.sendall(param_str)
    private_num = random.randint(MIN_PRIME - 1, prime - 1)
    temp_key = pow(generator, private_num, prime)
    time.sleep(MILISECOND)
    sock.sendall(str(temp_key).encode())
    
    other_key = sock.recv(BUFFER_SIZE).decode()
    other_key = int(other_key)

    shared_key = pow(other_key, private_num, prime)
    return shared_key

def aes_encrypt(key: bytes, plaintext: bytes):
    """Encrypt plaintext with AES, return (iv, ciphertext)."""
    iv = os.urandom(IV_SIZE)  # random IV for each message
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext

    #  spliter .............. (cipherText)
    # IV1 555 IV2 555 IV3 555 4753824735692845793845

def create_cipher(sock: socket, message: str):
    iv_list = [None] * NUMBER_NODES # default values
    ct = message.encode()
    for i in range (NUMBER_NODES):        
        aes_key = diffie_hellman(sock)        
        aes_key = hashlib.sha256(str(aes_key).encode()).digest() # convert int -> bytes
        iv_list[i], ct = aes_encrypt(aes_key, ct)
        ct_str = ct.hex()
    cipherText = SPLITTER.join([iv.hex() for iv in iv_list]) + SPLITTER + ct_str
    print("cipherText after 3 layers: ", ct_str)
    print("cipherText after 3 layers with the iv: ", cipherText)
    return cipherText


def main():
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    

    # Connecting to the other client
    address = ('', PORT)
    sock.bind(address)


    # Listen for incoming connections
    sock.listen(1)

    # Create a new conversation socket
    client_soc, client_address = sock.accept()

    # GET MESSAGE FROM CLIENT1
    client_msg = client_soc.recv(BUFFER_SIZE)
    client_msg = client_msg.decode()
    print(client_msg)

    #SEND MESSAGE TO CLIENT1
    msg = "second client says hello!!!"
    client_soc.sendall(msg.encode())
    
    msg = input("enter a message: ")
    cipherText = create_cipher(client_soc, msg)
    client_soc.sendall(cipherText.encode())


    sock.close()
    client_soc.close()









if __name__ == "__main__":
    main()