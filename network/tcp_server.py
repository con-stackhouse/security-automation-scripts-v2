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
    messages, calculates MD5 checksums, and sends them back to clients.

Security Application:
    - Network communication protocols
    - Server-side socket programming
    - Checksum exchange demonstration

Usage:
    python3 tcp_server.py
    (Start this before running tcp_client.py)

Requirements:
    - Python 3.x
    - No external libraries required

Output:
    Listens on port 5555, receives messages, returns MD5 checksums

Note:
    Server runs until receiving 'exit' command or manual termination.
    The MD5 digest returned here is a simple checksum, not a security
    control. A bare, unkeyed hash provides no message authentication
    or tamper protection: anyone who can modify the message in
    transit can recompute a matching MD5 digest. Real message
    authentication requires a keyed MAC (e.g. HMAC-SHA256) or a
    signature scheme.

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



