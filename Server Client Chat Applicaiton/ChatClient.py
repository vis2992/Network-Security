import socket
import threading
import time
import sys
import argparse

# creating a lock
tLock = threading.Lock()
shutdown = False

# parsing the command line arguments and options
parser = argparse.ArgumentParser()
parser.add_argument("-sip", help="give the server ip", default=None)
parser.add_argument("-sp", help="give the server port", default=None, type=int)
args = parser.parse_args()

# Checking for server ip and port
if args.sp is None:
    print "error, server port is not mentioned, this is a required field, use option -h to see usage"
    exit(0)

if args.sip is None:
    print "error, server ip is not mentioned, this is a required field, use option -h to see usage"
    exit(0)


# Aquiring the lock and receiving the data from the server
def receiving(name, sock):
    while not shutdown:
        try:
            tLock.acquire()
            while True:
                data, addr = sock.recvfrom(1024)
                print str(data)
        except:
            pass
        finally:
            tLock.release()

# loopback ip given to the client
host = '127.0.0.1'
port = 0

# initializing the server using the arguments passed
server = (str(args.sip), int(args.sp))

# creating the socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error, e:
    print "Error creating socket: %s" % e
    sys.exit(1)

s.bind((host, port))
s.setblocking(0)

# Creating and starting a thread for the client to receive the data
rT = threading.Thread(target=receiving, args=("RecvThread",s))
rT.start()

# Getting a message from the user
message = raw_input("+> ")
while message != 'q':
    # send the message to the server and aquire the lock so that no other client can send data at the same time.
    if message != '':
        s.sendto(": " + message, server)
    tLock.acquire()
    message = raw_input("+> ")
    # Release the lock
    tLock.release()
    time.sleep(0.2)

# Stopping the receiving thread and quitting the client when a "q" message is typed in.
shutdown = True
rT.join()
s.close()
print "quitting client"
exit(0)


