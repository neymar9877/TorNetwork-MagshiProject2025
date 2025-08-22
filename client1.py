#print("Im the first client")

import socket
PORT = 1535
IP = '127.0.0.1'

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


    sock.close()





if __name__ == "__main__":
    main()