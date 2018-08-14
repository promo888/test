import zmq, socket
import random
import sys
import time
from time import sleep
import threading
from queue import Queue
from multiprocessing import Process, Manager, Pool
import itertools
from utils import *
from v import *

duration = 1
client_num = 0
PORT_PUB = "7777"
PORT_REP = "8888"
PORT_UDP = 9999
msg = 'x' * 1000000 #100000 #~50-60 on localhost size from 10 to 100 000 bytes ~5-30mb + sending 1mb =~ 200mb/sec on localhost
WORKERS = 3#3
Q = Queue()

# PORT_PUB_SERVER = 5555   # Optional fanout
# PORT_SUB_CLIENT = 6666   # Optional subscribe
# PORT_REP_SERVER = 7777   # Receiving data from the world TXs, quiries ...etc
# PORT_UDP_SERVER = 8888   # Receiving data from miners
#PORT_UDP_CLIENT = 9999   # Submitting/Requesting data from the miners
TYPES = ['rep', 'udps']


# Socket to talk to server
context = zmq.Context()

def init_server(type):
   #print('type', type, flush=True)
   if type is 'rep':
       rep_socket = context.socket(zmq.REP)
       rep_socket.bind("tcp://*:%s" % PORT_REP)
       print('Starting REP server tcp://localhost:%s' % PORT_REP_SERVER, flush=True)
       while True:
           rep_msg = rep_socket.recv()
           Q.put_nowait(rep_msg)
           rep_socket.send(rep_msg)


   if type is 'udps':
       udps_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
       udps_socket.bind(('', PORT_UDP))
       print('Starting UDP server udp://localhost:%s' % PORT_UDP_SERVER, flush=True)
       while True:
           udp_msg = udps_socket.recvfrom(1024)
           data = udp_msg[0]
           addr = udp_msg[1]
           Q.put_nowait(udp_msg[0])

           if not data:
               break

           reply = data
           udps_socket.sendto(reply, addr)
           # print('Message[' + addr[0] + ':' + str(addr[1]) + '] - ') # + data.strip())


   if type is 'pub':
       pub_socket = context.socket(zmq.PUB)
       pub_socket.bind("tcp://*:%s" % PORT_PUB)
       print('Starting PUB server tcp://localhost:%s' % PORT_PUB, flush=True)
       while True:
           try:
               if not Q.empty():
                   pub_msg = Q.get_nowait()
                   pub_socket.send(pub_msg)
           except Exception as ex:
               print('PUB Exception: %s' % ex, flush=True)
               #TODO logger

   if type is 'sub':
       sub_socket = context.socket(zmq.SUB)
       sub_socket.connect("tcp://localhost:%s" % PORT_PUB)
       sub_socket.setsockopt(zmq.SUBSCRIBE, b'')
       print('Starting SUB server tcp://localhost:%s' % PORT_PUB, flush=True)
       count = 0
       while True:
           sub_msg = sub_socket.recv() #TODO bytes
           if sub_msg: count += 1
           if count % 10 == 0: print('sub_msg_count', count)


   if type is 'req':
       req_socket = context.socket(zmq.REQ)
       req_socket.connect("tcp://localhost:%s" % PORT_REP)
       print('Starting REQ server tcp://localhost:%s' % PORT_REP, flush=True)
       msg_count = 0
       while True:
           msg_count += 1
           req_msg_req = ('%s %s' % (msg_count, msg)).encode('utf-8')
           #print('REQ request', req_msg_req)
           req_socket.send(req_msg_req)
           req_msg_res = req_socket.recv()
           if msg_count % 10 == 0: print('req_msg_res_count', msg_count)
           #print('REQ response', req_msg_res)


   if type is 'udpc':
       udpc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #test #TODO to remove
       print('Starting UDP client', flush=True)
       msg_count = 0
       while True:
           udp_msg_req = ('%s %s' % (msg_count, msg)).encode('utf-8')
           udpc_socket.sendto(udp_msg_req, ('127.0.0.1', PORT_UDP))
           d = udpc_socket.recvfrom(1024)
           msg_count += 1
           #reply = d[0]
           #addr = d[1]
           # print('Server reply : ' + d[0].decode('utf-8'))
           #req_msg_res = req_socket.recv()
           if msg_count % 100 == 0: print('udp_msg_res_count', msg_count)
           #print('REQ response', req_msg_res)



def sendUDP(bin_msg, host, port):
    udpc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpc_socket.sendto(bin_msg, (host, port))
    response = udpc_socket.recvfrom(1024)
    return response


def init_servers():
    workers = []
    print('TYPES', TYPES)
    for s in range(len(TYPES)):
            print('Starting server %s' % TYPES[s])
            t = threading.Thread(target=init_server, args=(TYPES[s],), name='server-%s' % TYPES[s])  # (target=init_server(TYPES[s]), name='server-%s' % TYPES[s])
            t.daemon = True
            t.start()
            workers.append(t)
            #sleep(3) #TODO increase to 10 from 70-120 to 180-500 ? #3sec for sub req connections
    sleep(1)
    # for s in workers: #FOREVER LOOP
    #     s.join()


def init_servers2():
    # start for workers
    pool = []
    for i in range(len(TYPES)):
        if TYPES[i] in ['req', 'sub']:
            p = Process(target=init_server, args=(TYPES[i],), name='server-%s' % TYPES[i])
            p.start()
            pool.append(p)


#from utils import * #setNodeId, getNodeId
def start_node(pub_key):
    if not pub_key is None:
        setNodeId(pub_key)
        start = time.time()
        init_servers()
        insertGenesis()
        print('Started at %s' % time.ctime(start))
        print(RUNTIME_CONFIG)



#TODO if main startNode(pbk) #19773ac41f111ea4ad5ef20ff1273aa0739f15661dafa3b4787961fd84bfb369
start_node('71a758746fc3eb4d3e1e7efb8522a8a13d08c80cbf4eb5cdd0e6e4b473f27b16') #test2
print('GENESIS exist: ', isDBvalue(b'TX_GENESIS', NODE_DB))
#run_version(v1.test)
#run_version(v1.test, 'Some Value')
