# print("Im the first client")
from cryptography.hazmat.primitives.asymmetric import dh
from sympy import randprime
import random
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

    diffie_hellman(sock)


    sock.close()





if __name__ == "__main__":
    main()