#!/usr/local/bin/python3.5
import asyncio
from datetime import datetime
from aiohttp import web
import random,time

# from node import Node
import argparse
from utils import *  # whoIsMaster,getNode
import logging
import os, re, glob

# https://github.com/aio-libs/aiohttp #ws.handler

HOST = '127.0.0.1'
PORT = 8000
parser = argparse.ArgumentParser(description='Node init')
# parser.add_argument('-h', type=str, default='127.0.0.1', help='Server ip')
parser.add_argument('-p', type=int, default=8000, help='Server port')
args = parser.parse_args()
# print('args: ', args)
if not args.p is None: PORT = args.p
# if not args.h is None: HOST = args.h

import glob, os, multiprocessing
# p = multiprocessing.Pool(4)
# p.map(os.remove, glob.glob("*_server*.log"))

#p.map(os.remove, glob.glob("*_server*.log"))
#print(glob.glob("*_server*.log"))

# import os, re, os.path
# pattern = "^\d+*_server.*log$"
# mypath = os.getcwd() + "/benchmarks"
# for root, dirs, files in os.walk(mypath):
#      for file in filter(lambda x: re.match(pattern, x), files):
#          print(os.path.join(root, file))
         #os.remove(os.path.join(root, file))



def purge(dir, pattern):
    for f in os.listdir(dir):
        if re.search(pattern, f):
            os.remove(os.path.join(dir, f))


async def hello(request):
    name = request.match_info.get("name", "foo")
    n = datetime.now().isoformat()
    delay = 0  # random.randint(0, 3)
    await asyncio.sleep(delay)
    headers = {"content_type": "text/html", "delay": str(delay)}
    # opening file is not async here, so it may block, to improve
    # efficiency of this you can consider using asyncio Executors
    # that will delegate file operation to separate thread or process
    # and improve performance
    # https://docs.python.org/3/library/asyncio-eventloop.html#executor
    # https://pymotw.com/3/asyncio/executors.html
    # with open("frank.html", "rb") as html_body:
    #     print("{}: {} delay: {}".format(n, request.path, delay))
    #     response = web.Response(body=html_body.read(), headers=headers)
    response = web.Response(status=200, text="Ok")
    return response


async def wshandler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    async for msg in ws:
        if msg.type == web.MsgType.text:
            await ws.send_str("Hello, {}".format(msg.data))
        elif msg.type == web.MsgType.binary:
            await ws.send_bytes(msg.data)
        elif msg.type == web.MsgType.close:
            break

    return ws


async def redirect2Y(request):
    return await redirect(request, "http://www.yahoo.com")
    #return web.Response(body='POST from {}'.format(PORT).encode('utf-8'))

async def amImaster():
    master = whoIsMaster()
    if (host == HOST and int(port) == PORT): return True
    else: return False


last_slave_index = 0
async def tx(request, debug=True):
    global last_slave_index
    if request.method == 'POST':
        request.app['txid'] = (await request.post())['txid']  # new tx
        #return web.Response(body='POST response from master from {} txid: {}'.format(PORT, request.app['txid']).encode('utf-8'))
        return await redirect(request, "http://www.yahoo.com")
        # print(whoIsMaster())
        master = whoIsMaster()
        logging.info('master: %s' % (master))
        host, port = master.split(":")
        if (host == HOST and int(port) == PORT):  # I'm a master
            if last_slave_index == 0:
                node_index = 0
            elif last_slave_index < len(slave_nodes):
                node_index = last_slave_index
            else:
                node_index = last_slave_index % len(slave_nodes)

            #print(node_index)
            slave_node =  getNode(node_index, slave_nodes)
            msg = 'Redirecting to slave node: ' #+ slave_node
            #print('{}:{} Redirecting to slave node: '.format(HOST, PORT), slave_node)
            #if debug:
            #logging.debug("POST Request from: " + str(request.transport.get_extra_info('peername')))
            logging.debug('{}:{} Redirecting POST to slave node: {}'.format(HOST, PORT, slave_node))
            last_slave_index += 1
            #return web.Response(body=bytes(msg, 'utf-8'))  # (body=b'thanks for the data')
            #request.app['master'] = 'true'

            return await redirect(request, "http://" + slave_node + "/tx2")
            #return web.Response(body='POST response from master from {} txid: {}'.format(PORT, request.app['txid']).encode('utf-8'))

        # print('KeyError' in request.app['txid2'] ) #TODO wrap try/catch for invalid requests
        else:
            last_slave_index = 0
            #print('%s:%s Redirecting to master: %s' % (HOST, PORT, master))
            #if debug:
            #logging.debug("POST Request from: " + str(request.transport.get_extra_info('peername')))
            logging.debug('%s:%s Redirecting POST to master: %s' % (HOST, PORT, master))
            # return redirect(request, master)
            #await redirect(request, master + "/tx")
            #if request.app['master'] is None:

            return await redirect(request, "http://" + master + "/tx")
            #else
            #return web.Response(body='Post response slave from {} txid: {}'.format(PORT, request.app['txid']).encode('utf-8'))
                #return web.Response(body='POST response slave from {}'.format(PORT).encode('utf-8'))  # get tx
    else:
        #return web.Response(body='GET response from {} txid: {}'.format(PORT, request.app['txid']).encode('utf-8'))  # get tx
        logging.debug("GET Request from: " + str(request.transport.get_extra_info('peername')))
        return web.Response(body='GET response from {}'.format(PORT).encode('utf-8'))  # get tx
        #return await web.Response(body='from {} txid: {}'.format(PORT, request.app['txid']).encode('utf-8'))

#response = yield from request(method='GET', url=url, allow_redirects=False)
#resp = yield from aiohttp.request('post', url, data=payload, connector=conn)
#    return (yield from resp.text())

async def tx2(request):
    #return await redirect(request, "http://" + master + "/tx2")
    #return web.Response(body='Post response slave from {} txid: {}'.format(PORT, request.app['txid']).encode('utf-8'))

    return web.Response(body='POST response slave from {}'.format(PORT).encode('utf-8'))


async def redirect(request, redirect_url):
    return web.Response(
        status=307,
        headers={
            #"master" : str(amImaster),
            'location': redirect_url,
        },
    )


import sys

#print(glob.glob("*_server.log"))
purge(os.getcwd(), "^" + str(PORT) + "_server.log$")
logging.basicConfig(filename='%s_server.log' % PORT, level=logging.DEBUG, format='%(asctime)s %(message)s')


print("args: ", sys.argv)
#killByPort(':8000')

configuration = load_config()
nodes = configuration['nodes']
slave_nodes = {k: v for k, v in nodes.items() if not '%s:%s' % (HOST, PORT) in v}
print(slave_nodes)

app = web.Application()
app.router.add_route("GET", "/", wshandler)
app.router.add_route("GET", "/web", hello)
app.router.add_get('/tx', tx)
app.router.add_post('/tx', tx)
app.router.add_post('/tx2', tx2) #
app.router.add_post('/redirect2Y', redirect2Y)
web.run_app(app, host=HOST, port=PORT)
# print("AIOHTTP server started")


if __name__ == '__main__':
    #killByPort(':8000')  # , ':8001', ':8002', ':8003', ':8004', ':8005')

    purge(os.getcwd(), "^" + str(PORT) + "_server.log$")
    logging.basicConfig(filename='%s_server.log' % PORT, level=logging.DEBUG, format='%(asctime)s %(message)s')

    print("args: ", sys.argv)
    # killByPort(':8000')

    configuration = load_config()
    nodes = configuration['nodes']
    slave_nodes = {k: v for k, v in nodes.items() if not '%s:%s' % (HOST, PORT) in v}
    print(slave_nodes)

    app = web.Application()
    app.router.add_route("GET", "/", wshandler)
    app.router.add_route("GET", "/web", hello)
    app.router.add_get('/tx', tx)
    app.router.add_post('/tx', tx)
    app.router.add_post('/tx2', tx2)
    app.router.add_post('/redirect2Y', redirect2Y)
    web.run_app(app, host=HOST, port=PORT)