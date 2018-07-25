#!/usr/local/bin/python3.5

# https://pawelmhm.github.io/asyncio/python/aiohttp/2016/04/22/asyncio-aiohttp.html
# https://aiohttp.readthedocs.io/en/stable/
# https://aiohttp.readthedocs.io/en/stable/web.html
#https://docs.aiohttp.org/en/stable/client.html

import asyncio
from aiohttp import ClientSession
#from time import *
from utils import *
#from node import Node
from time import gmtime, strftime, ctime
from datetime import datetime


secs = 5
count = 0

import requests
from urllib3 import *
import urllib.request
import urllib.parse

url = 'http://127.0.0.1:8000/web'
# start = time()
# while (time() - start < secs):
#     r = requests.get(url)
#     # print(r)
#     # nf = get_host(url)
#     # page = nf.read()
#     # end = time.time()
#     # nf.close()
#     # print(nf)
#     # f = urllib.request.urlopen(url)
#     # print(f.read().decode('utf-8'))
#     count += 1
# print("{} get requests/sec sync".format(count / secs))


async def fetch(url, session):
    async with session.get(url) as response:
        return await response.read()


secs = 10
count = 0


async def get(url, secs=0):
    # async with ClientSession() as session:
    #     async with session.get(url) as response:
    #          response = await response.read()
    #          print(response)
    start = time()
    global count
    tasks = []
    while (time() - start < secs):
        async with ClientSession() as session:
            for i in range(10000):
                # async with async_timeout.timeout(5):
                async with session.get(url) as response:
                    response = await response.read()
                    count += 1
                print(response)

            # for i in range(1000):
            #     task = asyncio.ensure_future(fetch(url, session))
            #     tasks.append(task)
            #     responses = await asyncio.gather(*tasks)
            #     count += 1
    # print(responses)


start = time()
#import json
url = 'http://127.0.0.1:8000/tx'
async def post(url,secs):
    # master = whoIsMaster()
    # url = 'http://%s/tx' % master

    global count
    while (time() - start < secs):
        async with ClientSession() as session:
            async with session.post(url, data={'txid': 'new'} * 1000) as resp:
                response = await resp.read()
                count += 1
                print(count, response, str(datetime.now())) #strftime("%Y-%m-%d %H:%M:%S", gmtime()) str(datetime.now()) time.ctime()


async def post2(url): #single request
    async with ClientSession() as session:
        async with session.post(url, data={'txid': 'new' * 1000}) as resp:
            response = await resp.read()
            #print(response)


# async with aiohttp.ClientSession(json_serialize=json.dumps) as session:
#     async with session.post(json={'txid': 'new'})

# params = {'key1': 'value1', 'key2': 'value2'}
# async with session.get('http://httpbin.org/get',
#                        params=params) as resp:
#     assert str(resp.url) == 'http://httpbin.org/get?key2=value2&key1=value1'

master = whoIsMaster()
url = 'http://%s/tx' % master
print('start master: ', master)
url2 = 'http://127.0.0.1:8000/tx2'

loop = asyncio.get_event_loop()
##loop.run_until_complete(get(url, secs))
#loop.run_until_complete(post2(url2))
loop.run_until_complete(post(url2, secs))
print("{} AIOHTTP post requests/sec".format(count / secs))  # per sec".format(count//secs))

#loop.run_until_complete(post2(url))
# future = asyncio.ensure_future(get(url, secs))
# loop.run_until_complete(future)
#print("{} AIOHTTP get requests/sec".format(count / secs))  # per sec".format(count//secs))
# loop.run_forever()
