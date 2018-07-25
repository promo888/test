import sys, time
import zmq

client_num = 0
PORT_PUB = "7777"
PORT_REP = "8888"
msg = 'x' * 100

# if len(sys.argv) > 1:
#     port = int(sys.argv[1])

#
# if len(sys.argv) > 2:
#     port1 = int(sys.argv[2])


# Socket to talk to server
context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect("tcp://localhost:%s" % PORT_REP) #PORT_PUB)  # ("tcp://10.20.42.88:%s" % port) #("tcp://localhost:%s" % port)

# if len(sys.argv) > 1: #2:
#     socket.connect("tcp://localhost:%s" % PORT_PUB)
#     client_num = sys.argv[1]
# print('Req #%s started' % client_num)


start = time.time()
duration = 1
msg_count = 0
while time.time() - start < duration:
    socket.send(msg.encode('utf-8')) #(b"Hello") #(bytes(msg, 'utf-8'))  #
    message = string = socket.recv_string()
    #message = socket.recv()
    #print(message)
    msg_count += 1
    #print("Received reply %s [%s]" % (msg_count, message))
print('%s responses from ZMQ_REP accepted within %s sec duration' % (msg_count, duration))


# with open('zmq_client_req.log', 'a') as f:
#     f.write('Client%s got %s msgs within %s secs \n' % (client_num, msg_count, duration))
# print('Client%s got %s msgs within %s secs \n' % (client_num, msg_count, duration))
