#print("Im the second client")

import socket
PORT = 1535
IP = '127.0.0.1'

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


    sock.close()








if __name__ == "__main__":
    main()