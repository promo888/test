import zmq

from v.v1 import logger, config, node, crypto, web, \
                 sdb, db, transaction, message, block, \
                 contract, ico, exchange, utils

class Network():
   #import time, socket, zmq, asyncio
   def __init__(self):
       #self.logger = Logger('Network')
       self.Config = config.Config

   def __new__(cls): #singleton
       if not hasattr(cls, 'instance'):
           cls.instance = super(Network, cls).__new__(cls)
       return cls.instance

   def sendMsgZmqReq(self, bin_msg, host, port):
       #requests from the wallets/outside, pay/sendMsg(TX/ICO/Contract) or retrieve wallets/txs/blocks/contracts ...etc

       context = zmq.Context()
       socket = context.socket(zmq.REQ)
       socket.connect("tcp://%s:%s" % (host, port))
       socket.send(bin_msg)
       response = socket.recv_string()
       print("sendMsgZmqReq: ", crypto.Crypto.to_HMAC(bin_msg))
       print('ZMQ REQ response: ', response)
       if 'OK:'.upper() in response.upper():
           return True
       else:
           return False


   def sendMsgZmqUdp(self, bin_msg, host, port):
       # Miners Request/Fanout Traffic - # TX_LIST, BLOCK, VOTE, DATA ...etc
       pass

   def getNodesList(self):  # todo
       pass

   def getValidNodesList(self):  # todo
       return [('localhost', self.Config.PORT_REP)]