import socket
import sys
import hashlib

'''

TCP Server with MD5 Hash Response
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: October 2024

Purpose:
    Demonstrates TCP socket programming by creating a server that receives
    messages, calculates MD5 hashes, and sends confirmations back to clients.

Security Application:
    - Network communication protocols
    - Server-side socket programming
    - Message integrity verification
    - Hash-based authentication concepts

Usage:
    python3 tcp_server.py
    (Start this before running tcp_client.py)

Requirements:
    - Python 3.x
    - No external libraries required

Output:
    Listens on port 5555, receives messages, returns MD5 hashes
    
Note:
    Server runs until receiving 'exit' command or manual termination

'''


print("Server Starting up...\n")



try:

    serverSocket = socket.socket()  # Create socket for listening

    localHost = socket.gethostname()  # Get local host address

    localPort = 5555  # Specify a local port 



    serverSocket.bind((localHost, localPort))  # Bind socket to localHost

    serverSocket.listen(1)  # Listen for connections



    print('Waiting for connection request...\n')

    conn, client = serverSocket.accept()  



    print("Connection received from client: ", client, "\n")



    while True:

        buffer = conn.recv(2048)  

        if not buffer:

            break

        

        print(buffer)  



        

        md5Obj = hashlib.md5()

        md5Obj.update(buffer)  

        digest = md5Obj.hexdigest()

        digestBytes = bytes(digest.encode('utf8'))



        

        response = b"Received message. MD5: " + digestBytes

        print(response)

        conn.sendall(response)        



        if b'exit' in buffer.lower():

            print("Server terminated by user")

            break



    conn.close()



except Exception as err:

    sys.exit(str(err))



