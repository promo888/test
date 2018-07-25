import sys, time
import zmq

client_num = 0
PORT_PUB = "7777"
PORT_SUB = "8888"

# if len(sys.argv) > 1:
#     port = int(sys.argv[1])

#
# if len(sys.argv) > 2:
#     port1 = int(sys.argv[2])


# Socket to talk to server
context = zmq.Context()
socket = context.socket(zmq.SUB)

#print ("Collecting updates from weather server...")
socket.connect("tcp://localhost:%s" % PORT_PUB) #("tcp://10.20.42.88:%s" % port) #("tcp://localhost:%s" % port)

if len(sys.argv) > 1: #2:
    socket.connect("tcp://localhost:%s" % PORT_PUB)
    client_num = sys.argv[1]
print('Subscriber #%s started' % client_num)


# Subscribe to zipcode, default is NYC, 10001
# topicfilter = "10001"
# socket.setsockopt(zmq.SUBSCRIBE, bytes(topicfilter, 'utf8'))
# # Process 5 updates
# total_value = 0
# for update_nbr in range (5):
#     #string = socket.recv()
#     string = socket.recv_string()
#     topic, messagedata = string.split()
#     total_value += int(messagedata)
#     print('SUB', topic, messagedata)
# print ("SUB, Average messagedata value for topic '%s' was %dF" % (topicfilter, total_value / update_nbr))


socket.setsockopt(zmq.SUBSCRIBE, b'')
start = time.time()
duration = 10
msg_count = 0
while time.time() - start < duration:
    string = socket.recv_string()
    #print(string)
    msg_count += 1
with open('zmq_client.log', 'a') as f:
    f.write('Client%s got %s msgs within %s secs \n' % (client_num, msg_count, duration))
print('Client%s got %s msgs within %s secs \n' % (client_num, msg_count, duration))