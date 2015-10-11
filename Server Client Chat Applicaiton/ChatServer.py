__author__ = 'vishalrao'
import socket
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-sp", help="give the server port", default=None, type=int)
args = parser.parse_args()
# print "sp:" + args.sp

# Checking if the server if is given
if args.sp is None:
    print "error, server ip not mentioned, this is a required field. Use the option -h to see usage"
    exit(0)

# loopback ip
host = '127.0.0.1'

# port given by the user
port = int(args.sp)

# creating a list for the clients of the server
clients = []

# creating the socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# binding the socket to the host and port
s.bind((host, port))
s.setblocking(0)
quitting = False
print "Server started"

# while the server has not quit, recieve data from the clients and broadcast it to all other clients.
while not quitting:
    try:
        data, addr= s.recvfrom(1024)
        if "Quit" in str(data):
            quitting = True

        # If the client is not already registered with the server, add it to the server's list of clients.
        if addr not in clients:
            clients.append(addr)

        # Printing the message in the server window.
        print time.ctime(time.time()) + str(addr) + ": :" + str(data)
        clientData = "<- <From" + str(addr) + ">" + str(data)

        # Broadcast the message to all the clients that have registered with the server.
        for client in clients:
            s.sendto(clientData, client)
    except:
        pass

# Close the socket once the server has quit.
s.close()



