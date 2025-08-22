#print("Im the second client")
from cryptography.hazmat.primitives.asymmetric import dh
import random
import socket
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
    diffie_hellman(client_soc)


    sock.close()








if __name__ == "__main__":
    main()