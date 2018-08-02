import sys
import asyncio
import websockets
from gevent.libev.corecext import async

from .utils import *


class Node:

    def __init__(self, myip, myport, loop=None):  # TODO add to nodes config
        self.config = load_config()
        self.ip = myip
        self.port = myport
        self.syncTime()
        self.knownnodes = self.getNodesList()
        if not loop is None:
            start_server = websockets.serve(self.getPing, myip, myport, loop=loop)
            asyncio.get_event_loop().run_until_complete(start_server)

             # self.server = loop.run_until_complete(
             #     asyncio.start_server(websockets.serve(self.getPing), myip, myport, loop=loop))

    def syncTime(self):  # sync to GMT0 time
        pass

    def getHost(self):
        pass

    def getIP(self):
        return str(self.ip)

    def getPort(self):
        return int(self.port)

    def loadConfig(self):
        config = configparser.ConfigParser()
        with open(path, 'r') as configfile:
            return config.read(configfile)

    def whoIsMaster(self):
        """

        :return: miner's turn index in config
        """
        start_time = datetime(2017, 1, 1)  # BlockChain start - TODO change to 2018 real start date
        current_time = datetime.utcnow()
        s = calendar.timegm(start_time.utctimetuple())
        e = calendar.timegm(current_time.utctimetuple())
        ellapsed_sec = (s - e)  # seconds ellapsed since genesis
        miners_amount = len(self.config['nodes'])
        return (ellapsed_sec % miners_amount)  # miner's index in config

    def redirectToMaster(self):
        pass

    def sendPing(self):
        pass

    def broadcastPing(self):
        pass

    def sendToUrl(self):
        pass

    def sendPendingTxToMaster(self):
        pass

    def sendTxToMaster(self):
        pass

    def sendTxBroadcast(self):
        pass

    def sendBlockBroadcast(self):
        pass

    def validateTx(self):
        pass

    def validateBlock(self):
        pass

    def voteTxToMaster(self):
        pass

    def voteBlockToMaster(self):
        pass

    def setPendingTxDb(self):
        pass

    def setTxDb(self):
        pass

    def setBlockDb(self):
        pass

    def getTx(self):
        pass

    def getBlock(self):
        pass

    def getBalance(self):
        pass

    def getNodesList(self):
        nodes_list = []
        for key in self.config['nodes']:
            nodes_list.append({'sig': key, 'ip': self.config['nodes'][key]})
        return nodes_list

    def veirifyNode(self, nodesig="", nodeip='localhost'):
        pass

    def addNode(self, nodesig, nodeip):
        self.verifyNode(nodesig, nodeip)
        pass

    def isNodeAlive(self, nodeip):
        pass

    def syncWithNode(self):
        pass

    def penaltyNode(self):
        pass

    def messageToChat(self):
        pass

    def proposeChange(self):
        pass

    def getCodeChecksum(self):
        pass

    def getDbChecksum(self):
        pass

    def signMessage(self):
        pass

    def updateNodeIP(self):
        pass

    def isQuorum(self):
        pass

    def isNodeValid(self):
        pass

    def isMessageValid(self):
        pass

    def isTxValid(self):
        pass

    def isBlockValid(self):
        pass

    def markTxAsPrivate(self):
        pass

    def changeAssets(self):
        pass

    def verifyResults(self):
        pass

    def executeCode(self):
        pass

    # #@asyncio.coroutine
    # def getUrl(reader, writer):
    #     peer = writer.get_extra_info('peername')
    #     writer.write("Hello, {0[0]}:{0[1]}!\n".format(peer).encode("utf-8"))
    #     writer.close()
    #
    #
    #
    # #@asyncio.coroutine
    # def getPong(reader, writer):
    #     peer = writer.get_extra_info('peername')
    #     writer.write("Hello, {0[0]}:{0[1]}!\n".format(peer).encode("utf-8"))
    #     writer.close()

    COUNTER = 0
    async def getPing(self, websocket, client):
        async for message in websocket:
            # print(websocket)
            global COUNTER
            #COUNTER += 1
            #resp = self.ip + " pong # " + COUNTER + " myMaster: " + whoIsMaster()
            resp = self.ip + " pong # "  + " myMaster: " + str(self.whoIsMaster())
            await websocket.send(resp)
            #websocket.send(resp)


    @asyncio.coroutine
    def handle_echo(self, reader, writer):
        # data = await reader.read(8192)
        # message = data.decode()
        # addr = writer.get_extra_info('peername')
        # print("Received %r from %r" % (message, addr))
        #
        # #print("Send: %r" % message)
        # print("IP:%s PORT:%s, Current Master index:%s " % (self.ip, self.port, self.whoIsMaster()))
        # #writer.write(data)
        # writer.write(bytes("IP:%s PORT:%s, Current Master index:%s " % (self.ip, self.port, self.whoIsMaster()), 'utf-8'))
        # await writer.drain()
        #
        # print("Close the client socket")
        # writer.close()

        data = (yield from reader.read(8192)).decode("utf-8")
        #data = reader.read(8192)
        #request = data.decode('utf-8')
        print("Request: ", data)
        writer.write(
            bytes("IP:%s PORT:%s, Current Master index:%s \r\n\r\n" % (self.ip, self.port, self.whoIsMaster()), 'utf-8'))
        yield from writer.drain()
        writer.close()
        print("Client socket closed")

# if __name__ == "__main__":
#     pass