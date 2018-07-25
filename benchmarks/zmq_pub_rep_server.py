import zmq, socket
import random
import sys
import time
from time import sleep
import shelve
import msgpack
import threading
from queue import Queue
from multiprocessing import Process, Manager, Pool
import itertools

#TODO http://zguide.zeromq.org/py:mspoller


duration = 1
client_num = 0
PORT_PUB = "7777"
PORT_REP = "8888"
PORT_UDP = 9999
msg = 'x' * 1000000 #100000 #~50-60 on localhost size from 10 to 100 000 bytes ~5-30mb + sending 1mb =~ 200mb/sec on localhost
WORKERS = 3#3
Q = Queue()
TYPES = ['pub', 'sub', 'rep', 'req', ] #'udps', 'udpc']
#['pub', 'sub', 'udps', 'udpc'] #440-1000+ (23690) #['pub', 'sub', 'rep', 'req'] #300-700 (7000)
#udp =+50-100% over tcp + ??? Sometimes only 10-20%
#UDP packet size has a limit of ~1500 bytes [65k] , while TCP no limits

# Socket to talk to server
context = zmq.Context()

# pub_socket.bind("tcp://*:%s" % PORT_PUB)  # ("tcp://10.20.42.88:%s" % port) #("tcp://localhost:%s" % port)
# rep_socket.bind("tcp://*:%s" % PORT_REP)
# sub_socket.connect("tcp://localhost:%s" % PORT_PUB)
# #sleep(0.01)
# sub_socket.setsockopt(zmq.SUBSCRIBE, b'')
# req_socket.connect("tcp://localhost:%s" % PORT_REP)

def init_server(type):
   print('type', type, flush=True)
   if type is 'rep':
       rep_socket = context.socket(zmq.REP)
       rep_socket.bind("tcp://*:%s" % PORT_REP)
       print('Starting REP server', flush=True)
       while True:
           rep_msg = rep_socket.recv() #string  #TODO bytes
           #rep_socket.send_string(rep_msg.decode('utf-8'))
           Q.put_nowait(rep_msg) #put(rep_msg) #
           #Q.task_done()
           rep_socket.send(rep_msg)
           ##print('rep_msg_res', rep_msg, flush=True)
           #Q.put_nowait(str(rep_msg)) #.put(rep_msg, False, 0.002)


   if type is 'udps':
       udps_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
       udps_socket.bind(('', PORT_UDP))
       print('Starting UDP server', flush=True)
       while True:
           udp_msg = udps_socket.recvfrom(1024) #(100000) #(1024)
           data = udp_msg[0]
           addr = udp_msg[1]
           Q.put_nowait(udp_msg[0])

           if not data:
               break

           reply = data  # 'OK...' #.encode() + data
           udps_socket.sendto(reply, addr)
           # print('Message[' + addr[0] + ':' + str(addr[1]) + '] - ') # + data.strip())


   if type is 'pub':
       pub_socket = context.socket(zmq.PUB)
       pub_socket.bind("tcp://*:%s" % PORT_PUB)
       print('Starting PUB server', flush=True)
       while True:
           try:
               #pub_msg = msg
               #Q.put_nowait(pub_msg) # put(msg, False, 0.002)
               #Q.task_done()

               if not Q.empty():
                   pub_msg = Q.get_nowait() #.get(False) # , 0.02) # 'x' # Q.get() #_ TODO no_wait exceptions
                   ##print('pub_msg', pub_msg, flush=True) #sys.stdout.flush()
                   ##pub_socket.send_string(str(pub_msg))  # (rep_message)
                   pub_socket.send(pub_msg) #.decode('utf-8')) #TODO bytes
               #Q.task_done()
               ##sleep(0.02)
           except Exception as ex:
               print('PUB Exception: %s' % ex, flush=True)
               #continue
               #pass

   if type is 'sub':
       #pass
       sub_socket = context.socket(zmq.SUB)
       sub_socket.connect("tcp://localhost:%s" % PORT_PUB)
       # sleep(0.01)
       sub_socket.setsockopt(zmq.SUBSCRIBE, b'')
       print('Starting SUB server', flush=True)
       count = 0
       while True:
           ##sub_msg = sub_socket.recv_string()
           sub_msg = sub_socket.recv() #TODO bytes
           if sub_msg: count += 1
           if count % 10 == 0: print('sub_msg_count', count)
           #print('sub_msg', sub_msg, flush=True)


   if type is 'req':
       #pass
       req_socket = context.socket(zmq.REQ)
       req_socket.connect("tcp://localhost:%s" % PORT_REP)
       print('Starting REQ server', flush=True)
       msg_count = 0
       while True:
           msg_count += 1
           req_msg_req = ('%s %s' % (msg_count, msg)).encode('utf-8')
           ##print('REQ request', req_msg_req)
           req_socket.send(req_msg_req)
           req_msg_res = req_socket.recv()
           if msg_count % 10 == 0: print('req_msg_res_count', msg_count)
           #print('REQ response', req_msg_res)


   if type is 'udpc':
       #pass
       udpc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
       print('Starting UDP client', flush=True)
       msg_count = 0
       while True:
           udp_msg_req = ('%s %s' % (msg_count, msg)).encode('utf-8')
           udpc_socket.sendto(udp_msg_req, ('127.0.0.1', PORT_UDP))
           ##print('UDP request', msg_count) #str(udp_msg_req))
           # receive data from client (data, addr)
           d = udpc_socket.recvfrom(1024)
           msg_count += 1
           #reply = d[0]
           #addr = d[1]
           # print('Server reply : ' + d[0].decode('utf-8'))
           #req_msg_res = req_socket.recv()
           if msg_count % 100 == 0: print('udp_msg_res_count', msg_count)
           #print('REQ response', req_msg_res)


def init_servers():
    workers = []
    print('TYPES', TYPES)
    for s in range(len(TYPES)):
            print('Starting server %s' % TYPES[s])
            t = threading.Thread(target=init_server, args=(TYPES[s],), name='server-%s' % TYPES[s])  # (target=init_server(TYPES[s]), name='server-%s' % TYPES[s])
            t.daemon = True
            t.start()
            workers.append(t)
            sleep(3) #TODO increase from 70-120 to 180-500 ? #3sec for sub req connections
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


start = time.time()
msg_count = 0
init_servers()
print('Started at %s' % time.ctime(start))
#sleep(1)
#while time.time() - start < duration:
    #sleep(0.1)
    # msg_count += 1
    # rep_msg = rep_socket.recv()
    # print('rep_msg', rep_msg)
    # print('REQ request')
    # req_socket.send(('%s %s' % (msg_count, msg)).encode('utf-8'))
    # print('req_msg_req', req_msg)
    # Q.put(rep_msg, False) #, 0.002)  #(rep_msg.encode('utf-8'), False, 0.002)
    ##req_msg = req_socket.recv_string()
    ##print('req_msg_res', req_msg)
    # pub_msg = Q.get(False, 0.02)
    # pub_socket.send_string(pub_msg) #(rep_message)
    # print('pub_msg', pub_msg)
    #sub_msg = sub_socket.recv_string()
    #print('sub_msg', sub_msg, flush=True)

    #message = socket.recv()
    #print(message)
    #print("Received reply %s [%s]" % (msg_count, message))
sleep(duration)
print('Ended at %s' % time.ctime(time.time()))
sys.exit(0)

#messages Prefix = MessageType = BytesMsgStruct
#1 tx_perfix t - Prefix/VerNum/CoinAssetType/TxType/FromPK(320b->20b or 64b Hash)/ToPK(Hash)/Sig(320b)
#1 tx_vote txv - MsgType/VerNum/FromPK/ToPK/Sig(
#1 tx savep
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
#1 tx prefix t
