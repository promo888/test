from time import time,sleep
import zmq
context = zmq.Context()
socket = context.socket(zmq.SUB)
# We can connect to several endpoints if we desire, and receive from all.
socket.connect('tcp://127.0.0.1:2000')

# We must declare the socket as of type SUBSCRIBER, and pass a prefix filter.
# Here, the filter is the empty string, wich means we receive all messages.
# We may subscribe to several filters, thus receiving from all.

##socket.setsockopt(zmq.SUBSCRIBE, '')
#message = socket.recv_pyobj()
#print(message.get(1)[2])

#message = socket.recv_pyobj()
#print(message.get(1)[2])
print('connected')
SECS = 5
count = 0
start = time()
while(True): #(time() - start < SECS):
    #message = socket.recv_pyobj()
    #message = socket.recv() #(1024)
    message = socket.recv_string()
    count += 1
    print(message)
    print(message.get(1)[2])
print("{} msgs subscribed within {} secs".format(count, SECS))