#print("Im the second client")
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib
import random
from sympy import randprime
import socket
PORT = 1535
IP = '127.0.0.1'

def diffie_hellman(sock):
    prime = randprime(0, 10000)
    generator = 2
    param_str = f"{prime},{generator}".encode()
    sock.sendall(param_str)

    private_num = random.randint(2, prime - 1)
    temp_key = pow(generator, private_num, prime)
    sock.sendall(str(temp_key).encode())
    
    other_key = sock.recv(1024).decode()
    other_key = int(other_key)

    shared_key = pow(other_key, private_num, prime)
    return shared_key

def aes_encrypt(key: bytes, plaintext: bytes):
    """Encrypt plaintext with AES, return (iv, ciphertext)."""
    iv = os.urandom(16)  # random IV for each message
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext

    #  spliter .............. (cipherText)
    # IV1 555 IV2 555 IV3 555 4753824735692845793845

def create_cipher(sock: socket, message: str):
    iv_list = [None] * 3 # default values
    ct = message.encode()
    for i in range (3):
        print("!")
        aes_key = diffie_hellman(sock)
        print("!!")
        aes_key = hashlib.sha256(str(aes_key).encode()).digest() # convert int -> bytes
        iv_list[i], ct = aes_encrypt(aes_key, ct)
        ct_str = ct.hex()
    cipherText = "555".join([iv.hex() for iv in iv_list]) + "555" + ct_str
    print("cipherText after 3 layers: ", ct_str)
    print("cipherText after 3 layers with the iv: ", cipherText)


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
    client_msg = client_soc.recv(1024)
    client_msg = client_msg.decode()
    print(client_msg)

    #SEND MESSAGE TO CLIENT1
    msg = "second client says hello!!!"
    client_soc.sendall(msg.encode())
    aes_key = diffie_hellman(client_soc)
    aes_key = hashlib.sha256(str(aes_key).encode()).digest() # convert int -> bytes
    iv, ct = aes_encrypt(aes_key, b"hello peer")
    iv_str = iv.hex()
    ct_str = ct.hex()

    msg = iv_str + "," + ct_str
    print("encrypted msg before sending: " , ct_str)
    # client_soc.sendall(cipherText.encode())
    client_soc.sendall(msg.encode())


    print("now we checking\n\n")
    create_cipher(client_soc, "hello world!")

    sock.close()
    client_soc.close()









if __name__ == "__main__":
    main()