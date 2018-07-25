#!/usr/bin/python3.4
import asyncio
import websockets
#from .config import *



#https://hackernoon.com/threaded-asynchronous-magic-and-how-to-wield-it-bba9ed602c32
#https://7webpages.com/blog/writing-online-multiplayer-game-with-python-and-asyncio-writing-game-loop/
# https://docs.python.org/3.3/library/configparser.html
# https://docs.python.org/2/tutorial/modules.html

@asyncio.coroutine
def handle_hello(reader, writer):
    peer = writer.get_extra_info('peername')
    writer.write("Hello, {0[0]}:{0[1]}!\n".format(peer).encode("utf-8"))
    writer.close()


async def echo(websocket, path):
    async for message in websocket:
        #peer = path.get_extra_info('peername')
        peer = path
        #resp = "Hello, {0[0]}:{0[1]}!\n".format(peer).encode("utf-8")
        resp = "ok"
        await websocket.send(message)

if __name__ == "__main__":
    # config = load_config()
    # config['bitbucket.org']['User'] = 'new user'
    # print('Run-Time value: ' + config['bitbucket.org']['User'])

    loop = asyncio.get_event_loop()
    servers = []
    for i in range(3):
        print("Starting server {0}".format(i+1))
        # server = loop.run_until_complete(
        #         asyncio.start_server(echo, '127.0.0.1', 8000+i, loop=loop))
        # servers.append(server)

        server = asyncio.get_event_loop().run_until_complete(websockets.serve(echo, 'localhost', 8000+i))
        servers.append(server)


    try:
        print("Running... Press ^C to shutdown")
        loop.run_forever()
        #asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass

    for i, server in enumerate(servers):
        print("Closing server {0}".format(i+1))
        server.close()
        loop.run_until_complete(server.wait_closed())
    loop.close()