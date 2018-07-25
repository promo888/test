import os,sys,datetime,time
from benchmarks.config import *
from benchmarks.utils import *
import multiprocessing

# http://learning-0mq-with-pyzmq.readthedocs.io/en/latest/pyzmq/patterns/pubsub.html
# python pub_server.py 5556
# python pub_server.py 5546
# python sub_client.py 5556 5546

print(os.getcwd())
cmds = [
    "python zmq_server_pub2.py > zmq_server_pub2_py_7777.log",
    "python zmq_client_sub2.py 1 > zmq_server_sub2_1.log",
#     "python zmq_client_sub2.py 2 > zmq_server_sub2_2.log",
# "python zmq_client_sub2.py 3 > zmq_server_sub2_3.log",
# "python zmq_client_sub2.py 4 > zmq_server_sub2_4.log",
# "python zmq_client_sub2.py 5 > zmq_server_sub2_5.log",
# "python zmq_client_sub2.py 6 > zmq_server_sub2_6.log",
# "python zmq_client_sub2.py 7 > zmq_server_sub2_7.log",
# "python zmq_client_sub2.py 8 > zmq_server_sub2_8.log",
# "python zmq_client_sub2.py 9 > zmq_server_sub2_9.log",
# "python zmq_client_sub2.py 10 > zmq_server_sub2_10.log",

# "python zmq_client_sub2.py 11 > zmq_server_sub2_11.log",
# "python zmq_client_sub2.py 12 > zmq_server_sub2_12.log",
# "python zmq_client_sub2.py 13 > zmq_server_sub2_13.log",
# "python zmq_client_sub2.py 14 > zmq_server_sub2_14.log",
# "python zmq_client_sub2.py 15 > zmq_server_sub2_15.log",
# "python zmq_client_sub2.py 16 > zmq_server_sub2_16.log",
# "python zmq_client_sub2.py 17 > zmq_server_sub2_17.log",
# "python zmq_client_sub2.py 18 > zmq_server_sub2_18.log",
# "python zmq_client_sub2.py 19 > zmq_server_sub2_19.log",
# "python zmq_client_sub2.py 20 > zmq_server_sub2_20.log",
# "python zmq_client_sub2.py 21 > zmq_server_sub2_21.log",
# "python zmq_client_sub2.py 22 > zmq_server_sub2_22.log",
# "python zmq_client_sub2.py 23 > zmq_server_sub2_23.log",
# "python zmq_client_sub2.py 24 > zmq_server_sub2_24.log",
# "python zmq_client_sub2.py 25 > zmq_server_sub2_25.log",
# "python zmq_client_sub2.py 26 > zmq_server_sub2_26.log",
# "python zmq_client_sub2.py 27 > zmq_server_sub2_27.log",
# "python zmq_client_sub2.py 28 > zmq_server_sub2_28.log",
# "python zmq_client_sub2.py 29 > zmq_server_sub2_29.log",
# "python zmq_client_sub2.py 30 > zmq_server_sub2_30.log",
# "python zmq_client_sub2.py 31 > zmq_server_sub2_31.log",
# "python zmq_client_sub2.py 32 > zmq_server_sub2_32.log",
# "python zmq_client_sub2.py 33 > zmq_server_sub2_33.log",
# "python zmq_client_sub2.py 34 > zmq_server_sub2_34.log",




]



def runCmd(cmd):
    print('Starting cmd: %s' % cmd)
    subprocess.Popen(cmd, shell=True)

count = 0
for cmd in cmds:
    count += 1
    multiprocessing.Process(target=runCmd(cmd))



if __name__ == "__main__":
    # Define IPC manager
    manager = multiprocessing.Manager()

    # Define a list (queue) for tasks and computation results
    tasks = manager.Queue()
    results = manager.Queue()


# http://learning-0mq-with-pyzmq.readthedocs.io/en/latest/pyzmq/multiprocess/multiprocess.html
# import zmq
# import time
# import sys
# from multiprocessing import Process
#
#
# def server(port="5556"):
#     context = zmq.Context()
#     socket = context.socket(zmq.REP)
#     socket.bind("tcp://*:%s" % port)
#     print
#     "Running server on port: ", port
#     # serves only 5 request and dies
#     for reqnum in range(5):
#         # Wait for next request from client
#         message = socket.recv()
#         print
#         "Received request #%s: %s" % (reqnum, message)
#         socket.send("World from %s" % port)
#
#
# def client(ports=["5556"]):
#     context = zmq.Context()
#     print
#     "Connecting to server with ports %s" % ports
#     socket = context.socket(zmq.REQ)
#     for port in ports:
#         socket.connect("tcp://localhost:%s" % port)
#     for request in range(20):
#         print
#         "Sending request ", request, "..."
#         socket.send("Hello")
#         message = socket.recv()
#         print
#         "Received reply ", request, "[", message, "]"
#         time.sleep(1)
#
#
# if __name__ == "__main__":
#     # Now we can run a few servers
#     server_ports = range(5550, 5558, 2)
#     for server_port in server_ports:
#         Process(target=server, args=(server_port,)).start()
#
#     # Now we can connect a client to all these servers
#     Process(target=client, args=(server_ports,)).start()