# print("Im the first client")
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from sympy import randprime
import random
import socket 
import hashlib
PORT = 1535
IP = '127.0.0.1'

def diffie_hellman(client_soc):
    prime_str, generator_str  = client_soc.recv(1024).decode().split(",")
    prime = int(prime_str)
    generator = int(generator_str)
    
    private_num = random.randint(2, prime - 1)
    temp_key = pow(generator, private_num, prime)

    other_key = client_soc.recv(1024).decode()
    other_key = int(other_key)

    client_soc.sendall(str(temp_key).encode())
    shared_key = pow(other_key, private_num, prime)
    return shared_key


    

def aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with AES, return plaintext."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

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
    client2_msg = sock.recv(1024)
    client2_msg = client2_msg.decode()
    print(client2_msg)

    aes_key = diffie_hellman(sock)
    aes_key = hashlib.sha256(str(aes_key).encode()).digest() # convert int -> bytes

    client2_msg = sock.recv(1024)
    client2_msg = client2_msg.decode()
    iv_str, ct_str = client2_msg.split(',')
    iv = bytes.fromhex(iv_str)
    ct = bytes.fromhex(ct_str)


    plain_text = aes_decrypt(aes_key, iv, ct)
    print("encrypted msg after recive: ", ct_str)
    print("decrypted msg after recive: ", plain_text)

    key_list = [diffie_hellman(sock) for _ in range(3)]

    sock.close()





if __name__ == "__main__":
    main()