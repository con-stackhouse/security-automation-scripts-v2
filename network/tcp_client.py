import socket
import sys

'''

TCP Client with Message Transmission
Author: Connor Stackhouse
Course: Cyber Operations Engineering - University of Arizona
Date: October 2024

Purpose:
    Demonstrates TCP socket programming by creating a client that sends
    messages to a server and receives MD5 checksum responses.

Security Application:
    - Network communication protocols
    - Client-server architecture
    - Checksum exchange demonstration
    - Socket programming fundamentals

Usage:
    python3 tcp_client.py
    (Requires tcp_server.py running first on port 5555)

Requirements:
    - Python 3.x
    - No external libraries required

Output:
    Sends messages and receives MD5 checksum responses from server

Note:
    The MD5 digest exchanged here is a simple checksum, not a
    security control. A bare, unkeyed hash provides no message
    authentication or tamper protection: anyone who can modify the
    message in transit can recompute a matching MD5 digest. Real
    message authentication requires a keyed MAC (e.g. HMAC-SHA256)
    or a signature scheme.

'''


print("Client Application")

print("Establish a connection to a server")

print("Available on the same host using PORT 5555")



PORT = 5555    # Port Number of Server

    

try:

    # Create a Socket

    clientSocket = socket.socket()

    

    # Get local host address

    localHost = socket.gethostname()

    

    print("\nAttempt connection to: ", localHost, PORT)

    

    clientSocket.connect((localHost, PORT))

    

    

    print("Socket Connected ...")

    print("Sending message to Server\n")

    

    messages = [

        "Hello World",

        "Basketball",

        "Arizona",

        "MD5 Hash",

        "Sending Messages",

        "TCP Client",

        "Server Response",

        "United States",

        "Check the Hash",

        "Goodbye!"

    ]

    

    for eachMessage in messages:

        clientSocket.sendall(bytes(str(eachMessage).encode('utf-8')))

        

        

        buffer = clientSocket.recv(2048)

        print("Raw buffer: " + str(buffer))

        print("Decoded message: " + buffer.decode('utf-8'))

    

    clientSocket.close()  # Close the socket

    

except Exception as err:

    sys.exit(err)



