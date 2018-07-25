from time import sleep, time
import zmq

context = zmq.Context()
socket = context.socket(zmq.PUB)  # PUB PUSH
socket.bind('tcp://127.0.0.1:2000') #127.0.0.1:2000')

# Allow clients to connect before sending data
#sleep(10) #10
SECS = 5
buffer = 1000
start = time()
count = 0
while (True): #(time() - start < SECS):

    #sleep(3)
    #socket.send_pyobj({1: [1, 2, 3]})
    socket.send_string('x' * buffer)
    count += 1
print("ZMQ PUB started and {}messages/sec published {}bytes/msg ".format(count // SECS, buffer))
