import sys, time, random
import zmq

PORT_PUB = "7777"
msg = 'x' * 1000

# if len(sys.argv) > 1:
#     port = int(sys.argv[1])

context = zmq.Context()
socket = context.socket(zmq.REP)
socket.bind("tcp://*:%s" % PORT_PUB)
while True:
    message = socket.recv()
    #socket.send("Echo: " + msg)
    socket.send_string(msg)  ##("%d %d" % (topic, messagedata))
    #print("Echo: " + msg)
#     ##time.sleep(0.5)