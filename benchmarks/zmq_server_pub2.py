import zmq
import random
import sys
import time
import shelve
import msgpack
import threading
from queue import Queue
from multiprocessing import Process, Manager, Pool
import itertools

WORKERS = 3#3
Q = Queue()
PORT_PUB = "7777"
msg = 'x' * 1000
# if len(sys.argv) > 1:
#     port = int(sys.argv[1])


# context = zmq.Context()
# socket = context.socket(zmq.PUB)
# socket.bind("tcp://*:%s" % PORT_PUB)
# while True:
#     topic = random.randrange(9999, 10005)
#     messagedata = random.randrange(1, 215) - 80
#     ##print ("%d %d" % (topic, messagedata))
#     # socket.send("%d %d" % (topic, messagedata))
#     socket.send_string('x' * 1000)  ##("%d %d" % (topic, messagedata))
#     ##time.sleep(0.5)

def persist(binmsg, strindex=''):
    with shelve.open('q.db') as db:
        if strindex:
            key = strindex
        else:
            key = str(time.time())
        db[key] = binmsg
        ##print('msg persisted', time.time())


def worker():
    while True:
        if not Q.empty():
            #print('Get queue')
            #do work
            #url = Q.get()
            #download(url)
            msg = Q.get()
            try:
                persist(msg)
                Q.task_done()
            except:
                Q.put(msg, timeout=0.002)


def init_workers():
    for w in range(WORKERS):
            t = threading.Thread(target=worker, name='worker-%s' % w)
            t.daemon = True
            t.start()
            ##print('worker-%s started' % w)


def init_workers2():
    # start for workers
    pool = []
    for i in range(WORKERS):
        p = Process(target=worker)
        p.start()
        pool.append(p)


def init_pub():
    start = time.time()
    context = zmq.Context()
    socket = context.socket(zmq.PUB)
    socket.bind("tcp://*:%s" % PORT_PUB)
    init_workers()
    #init_workers2()
    while time.time() - start < 1: #True:
        msg = 'x' * 1000
        topic = random.randrange(9999, 10005)
        messagedata = random.randrange(1, 215) - 80
        ##print ("%d %d" % (topic, messagedata))
        #socket.send("%d %d" % (topic, messagedata))
        #Q.put_nowait(msg)
        Q.put(msg.encode('utf-8'), False, 0.002)
        socket.send_string(msg) ##("%d %d" % (topic, messagedata))
        ##time.sleep(0.5)
    else:
        #Q.join() #TODO release threads by timeout
        print('Server stopped')
        sys.exit(0)



#Q.put(msg, timeout=0.01)
#persist(msg.encode('utf-8'))
#persist(msg.encode('utf-8'), '1')

init_pub()

# if __name__ == "__main__":
#     # num_workers = 4
#     # manager = Manager()
#     # results = manager.list()
#     # works = manager.Queue(num_workers)
#     pass
