import asyncio
import websockets
import logging

#https://github.com/aaugustin/websockets


logging.basicConfig(filename='asyncio_server.log',level=logging.INFO)
log = logging.getLogger(__name__)


async def echo(websocket, path):
    #print(dir(websocket))
    #print(websocket) #websocket.remote_address
    #print(dir(path))
    #print(path)
    async for message in websocket:
        #websocket.send(message)
        await websocket.send(message)
        print('received: ', message) #(message)
        #print(dir(message))
        #log.info('a' * 100)

counter = 0
async def echo2(websocket, path):
    async for message in websocket:
        global counter
        counter += 1
        websocket.send(message)
        #await websocket.send(message)
        print('#', counter, " msg sent") #(message)
        #log.info('a' * 100)


async def handle_echo(reader, writer, server=''):
    data = await reader.read(100)
    message = data.decode()
    addr = writer.get_extra_info('peername')
    print("Received %r from %r" % (message, addr))

    print("Send: %r" % message)
    writer.write(data)
    await writer.drain()

    print("Close the client socket")
    writer.close()


    #if server.strip: stop(server)

async def stop(server):
    server.close()


log.info("Starting server")
#asyncio.get_event_loop().run_until_complete(websockets.serve(echo2, 'localhost', 8000))
loop = asyncio.get_event_loop()
coro = asyncio.start_server(echo2, '127.0.0.1', 8000, loop=loop)
server = loop.run_until_complete(coro)


#asyncio.get_event_loop().run_until_complete( websockets.serve(echo2, 'localhost', 8001) )
#asyncio.get_event_loop().run_until_complete( websockets.serve(echo, 'localhost', 8888) )
asyncio.get_event_loop().run_forever()


#https://github.com/ethereum/pydevp2p/blob/develop/devp2p/tests/test_peermanager.py



#https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
#import socket
#socket.gethostbyname(socket.gethostname())
#10.72.8.45
#https://whatismyipaddress.com/ https://whatismyipaddress.com/ip/81.218.83.200

#https://docs.python.org/2/library/socket.html
#https://stackoverflow.com/questions/25691062/how-do-i-get-my-asyncio-client-to-call-a-socket-server-and-waiting-for-response
# wait + timeout
#loop = asyncio.get_event_loop()
# coro = loop.create_server(EchoServer, '127.0.0.1', 8888)
#server = loop.run_until_complete(coro)
#print('serving on {}'.format(server.sockets[0].getsockname()))