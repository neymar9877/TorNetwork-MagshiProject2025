# print("Im the first client")
from cryptography.hazmat.primitives.asymmetric import dh
import socket 
PORT = 1535
IP = '127.0.0.1'

def diffie_hellman(sock):
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    param_numbers = parameters.parameter_numbers
    param_str = f"{param_numbers.p},{param_numbers.g}".encode()
    sock.sendall(param_str)
    print("client 1 finished diffie")
    

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