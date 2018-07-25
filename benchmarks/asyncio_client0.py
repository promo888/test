import os, sys
import argparse
import asyncio
import websockets
import time, async_timeout as timeout
import logging

# https://github.com/aaugustin/websockets/blob/master/websockets/py36/_test_client_server.py
# https://github.com/aio-libs/async-timeout
# https://7webpages.com/blog/writing-online-multiplayer-game-with-python-and-asyncio-writing-game-loop/
# https://github.com/dano/aioprocessing
# https://www.tutorialspoint.com/python/python_command_line_arguments.htm
# https://www.red-dove.com/config-doc/

log = logging.getLogger(__name__)
PORT = 8000
PORT2 = '8001'
PORT3 = '11111'

parser = argparse.ArgumentParser(description='Load test generator')
parser.add_argument('-p', type=int, default=8000, help='Localhost Server port')
args = parser.parse_args()
# print('args: ', args)
if not args.p is None: PORT = args.p


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


async def send(uri):  # ,buffersize=1000):
    print('uri: ', uri)
    async with websockets.connect(uri) as websocket:
        # websocket.send("x")
        # await websocket.send("x\r\n\r\n") # * buffersize)
        # async with timeout(0.1) as t:

        # s = await sendWithRetry(websocket, "x" * 10) #buffersize
        s = sendWithRetry(websocket, "x" * 1000)
        if not s: print('Failed to submit to %' % uri)

        msg = websocket.recv()
        print(msg)
        global x
        x += 1
    print(x, "msgs accepted")


async def recv(websocket):
    async for message in websocket:
        websocket.send(message)
        # await websocket.send(message)
        print(message)


# asyncio.get_event_loop().run_until_complete(websockets.serve(recv))

duration = 5
start = time.time()
buffersize = 1000000
count = 0
# while(time.time()-start <= duration):
#     asyncio.get_event_loop().run_until_complete(send('ws://localhost:%s' % PORT))
#     asyncio.get_event_loop().run_until_complete(send('ws://localhost:%s' % PORT2))
#     count += 1
# print(duration, "sec,", count, " req/res of ", buffersize, " bytes, total: ", count * buffersize / 1024 / 1024 / duration, "mb/sec")

uri = 'ws://localhost:%s' % PORT
print(uri)
asyncio.get_event_loop().run_until_complete(send(uri))
# asyncio.get_event_loop().run_until_complete(send('ws://localhost:%s' % PORT2))


# async with websockets.connect(uri) as websocket:
#     websocket.send("x")
#     # msg = await websocket.recv()
#     # print (msg)



async def run_client():
    async with websockets.connect(uri) as ws:
       await ws.send("ping")

#asyncio.get_event_loop().run_until_complete(run_client())
