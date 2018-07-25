import socket
import websockets,asyncio
import sys,os
import time

host = 'localhost'
port = 8000
buffersize = 8
server_address = (host, port)
client_address = (host, port+1)
N = 1000000


def benchmark_UDP():
    socket_UDP = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    socket_UDP.bind(client_address)

    print("Benchmark UDP...")

    duration = 0.0
    for i in range(0, N):
        b = bytes("a"*buffersize, "utf-8")
        start = time.time()
        socket_UDP.sendto(b, server_address)
        data, from_address = socket_UDP.recvfrom(buffersize)
        duration += time.time() - start

        if data != b:
            print("Error: Sent and received data are bot the same")

    print(duration*pow(10, 6)/N, "µs for UDP")


def benchmark_TCP():
    socket_TCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_TCP.connect(server_address)

    print("Benchmark TCP...")

    duration = 0.0
    for i in range(0, N):
        b = bytes("a"*buffersize, "utf-8")
        start = time.time()
        socket_TCP.sendall(b)
        data = socket_TCP.recv(buffersize)
        duration += time.time() - start

        if data != b:
            print("Error: Sent and received data are bot the same")

    print(duration*pow(10, 6)/N, "µs for TCP")
    socket_TCP.close()


def benchmark2_TCP():
    #os.system("nohup python ./socket_server.py 2&1>/dev/null &")
    #os.popen("python ./socket_server.py")
    #time.sleep(3)
    socket_TCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_TCP.connect(server_address)

    print("Benchmark TCP...")

    duration = 10
    start = time.time()
    buffersize = 10000
    count = 0
    while(time.time()-start <= duration):
        b = bytes("x"*buffersize, "utf-8")
        socket_TCP.sendall(b)
        data = socket_TCP.recv(buffersize)
        #data = socket_TCP.recv(2)
        count += 1
        #if data != b:
        #    print("Error: Sent and received data are bot the same")
        #print("Response: ", str(data))

    print(duration, "sec,", count, " req/res of ", buffersize, " bytes, total: ", count*buffersize/1024/1024/duration, "mb/sec")
    socket_TCP.close()


def single_TCP():
    socket_TCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_TCP.connect(server_address)

    print("Single TCP request...")
    print(socket_TCP)
    #print(dir(socket_TCP))

    buffersize = 10
    b = bytes("x"*buffersize+"\r\n", "utf-8")
    socket_TCP.sendall(b)
    data = socket_TCP.recv(1024)
    print("Response: ", data)
    # print(dir(data))

    #if data != b:
    #    print("Error: Sent and received data are bot the same")
    #print("Response: ", str(data))


    socket_TCP.close()



def single_asyncio():
    PORT = '8000'
    buffersize = 10
    async def sendWithRetry(ws, data):
        try:
            await ws.send(data)
            return True
        except Exception as e:
            print("send error: ", e, " retrying...")
            try:
                await ws.send(data)
                return True
            except Exception as e:
                print("send error: ", e, " cancel")
                return False


    x = 0
    async def send(uri):
        async with websockets.connect(uri) as websocket:
            #s = websocket.send("x") # * buffersize)
            # await websocket.send("x" * buffersize)
            # async with timeout(0.1) as t:
            s = await sendWithRetry(websocket, "x") # * buffersize)
            if not s:
                print('Failed to submit to {}', format(uri))
                return
            msg = await websocket.recv()
            print(msg)
            #global x
            #x += 1
            #print(x, "msgs accepted")

    async def recv(websocket, path):
        async for message in websocket:
            websocket.send(message)
            # await websocket.send(message)
            # print(message)

    # asyncio.get_event_loop().run_until_complete(websockets.serve(recv))

    duration = 5
    start = time.time()
    buffersize = 10
    count = 0
    #while (time.time() - start <= duration):
    asyncio.get_event_loop().run_until_complete(send('ws://localhost:%s' % PORT))
    # count += 1

    #print(duration, "sec,", count, " req/res of ", buffersize, " bytes, total: ",  count * buffersize / 1024 / 1024 / duration, "mb/sec")



#benchmark_TCP()
#benchmark2_TCP()
#single_TCP()

#
# Single TCP request...
# <socket.socket fd=288, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('127.0.0.1', 64357), raddr=('127.0.0.1', 8000)>
# ['__class__', '__del__', '__delattr__', '__dir__', '__doc__', '__enter__', '__eq__', '__exit__', '__format__', '__ge__', '__getattribute__', '__getstate_
# ubclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__slots__', '
# accept', '_check_sendfile_params', '_closed', '_decref_socketios', '_io_refs', '_real_close', '_sendfile_use_send', '_sendfile_use_sendfile', 'accept', '
# h', 'dup', 'family', 'fileno', 'get_inheritable', 'getpeername', 'getsockname', 'getsockopt', 'gettimeout', 'ioctl', 'listen', 'makefile', 'proto', 'recv
# end', 'sendall', 'sendfile', 'sendto', 'set_inheritable', 'setblocking', 'setsockopt', 'settimeout', 'share', 'shutdown', 'timeout', 'type']
# Traceback (most recent call last):



single_asyncio()

#http://websockets.readthedocs.io/en/stable/intro.html
#https://gist.github.com/sandrogauci/9618007 #asyncio forwarder

#https://opensourcehacker.com/2008/06/30/relativity-of-time-shortcomings-in-python-datetime-and-workaround/
