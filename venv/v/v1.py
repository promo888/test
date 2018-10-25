import os, sys , subprocess, psutil, pkgutil
import msgpack as mp
import sqlite3, leveldb
import datetime, time, configparser
import logging
from logging.handlers import RotatingFileHandler
import configparser
from nacl.bindings import crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES
from nacl.public import Box, PrivateKey, PublicKey
from nacl.bindings.crypto_sign import crypto_sign_open as verify, crypto_sign as sign, \
    crypto_sign_seed_keypair as keys_from_seed
from nacl.signing import SigningKey, VerifyKey
from Crypto.Hash import SHA256, HMAC, RIPEMD



class Test():

    def persistKeysInServiceDB(self, bin_priv, bin_pub, bin_seed, pub_addr_str, nick=''):
        sql_v1_test_accounts = '''CREATE TABLE if not exists v1_test_accounts
                                           (                     
                                            priv_key BLOB NOT NULL UNIQUE,
                                            pub_key BLOB NOT NULL UNIQUE,
                                            seed BLOB UNIQUE NOT NULL ,
                                            pub_addr TEXT NOT NULL UNIQUE,
                                            nick TEXT DEFAULT NULL UNIQUE,
                                           PRIMARY KEY(pub_addr) 
                                           );'''

        sql = "INSERT INTO v1_test_accounts (priv_key,pub_key,seed,pub_addr,nick) values (?,?,?,?,?)"
        con = ServiceDb().getServiceDB()
        try:
            with con:
                cur = con.cursor()
                con.execute(sql_v1_test_accounts)
                cur.execute(sql, [sqlite3.Binary(bin_priv), sqlite3.Binary(bin_pub), sqlite3.Binary(bin_seed), pub_addr_str, nick])
                con.commit()
        except Exception as ex:
            logger = Logger()
            err_msg = 'Exception on Select (%s) from SqlLite NODE_SERVICE_DB: %s, %s' % (sql, Logger.exc_info(), ex)
            logger.logp(err_msg, logging.ERROR)
            return None


        def persistPendingTX(self, bin_priv, bin_pub, bin_seed, pub_addr_str, nick=''):
            sql_v1_test_accounts = '''CREATE TABLE if not exists v1_test_accounts
                                               (                     
                                                priv_key BLOB NOT NULL UNIQUE,
                                                pub_key BLOB NOT NULL UNIQUE,
                                                seed BLOB UNIQUE NOT NULL ,
                                                pub_addr TEXT NOT NULL UNIQUE,
                                                nick TEXT DEFAULT NULL UNIQUE,
                                               PRIMARY KEY(pub_addr) 
                                               );'''

            sql = "INSERT INTO v1_test_accounts (priv_key,pub_key,seed,pub_addr,nick) values (?,?,?,?,?)"
            con = ServiceDb().getServiceDB()
            try:
                with con:
                    cur = con.cursor()
                    con.execute(sql_v1_test_accounts)
                    cur.execute(sql, [sqlite3.Binary(bin_priv), sqlite3.Binary(bin_pub), sqlite3.Binary(bin_seed),
                                      pub_addr_str, nick])
                    con.commit()
            except Exception as ex:
                logger = Logger('Test')
                err_msg = 'Exception on Select (%s) from SqlLite NODE_SERVICE_DB: %s, %s' % (sql, Logger.exc_info(), ex)
                logger.logp(err_msg, logging.ERROR)
                return None



class Helper:
    import msgpack as mp

    def b(self, str):
        try:
            return bytes(str, 'utf8')
        except:
            return None#str


    def packb(self, obj):
        try:
            return mp.packb(obj)
        except:
            return None


    def unpackb(self, packed_obj):
        try:
            return mp.unpackb(packed_obj)
        except:
            return None



class MsgType:
    UNSPENT_TX = b'\x00'
    SPENT_TX = b'\x01'
    PARENT_MSG = b'\x02'
    SPEND_MULTI_SIG_TX = b'\x03'
    MINER_FEE_TX = b'\x04'
    MINER_ISSUE_TX = b'\x05'
    BLOCK_MSG = b'\xb0'
    VOTE_MSG = b'\xb1'
    CONTRACT_TX = b'\xc0'
    CONTRACT_CONFIRM_TX = b'\xc1'
    CONTRACT_MSG = b'\xc2'
    REGISTER_TX = b'\xe1'
    EXCHANGE_TX = b'\x88'
    AGENT_TX = b'\xa7'
    INVOKE_TX = b'\xd1'
    RELAY_TX = b'\xd2'
    MSG_MSG = b'\xd3'

    @staticmethod
    def toName(self, value):
        if isinstance(value, int):
            value = value.to_bytes(1, 'little')
        for key, item in TransactionType.__dict__.items():
            if value == item:
                return key
        return None

    @staticmethod
    def getValue(self, keyName):
        if not isinstance(keyName, str):
            return None
        else:
            for key, value in TransactionType.__dict__.items():
                if key == keyName.upper():
                    return value



# class MsgType:
#     SPEND_TX_MSG_FIELDS = (
#     'ver_num', 'msg_type', 'sigs', 'sig_type', 'pub_keys', 'input_txs', 'output_txs', 'from_addr', 'to_addrs',
#     'asset_type', 'amounts', 'ts', )



class Structure(object):
    def __init__(self):
        self.version = "1"


class Config():
    def __init__(self):
        self.ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        self.NODE_SERVICE_DB = '%s/../service_db/DATA/service.db' % self.ROOT_DIR
        self.NODE_DB = '%s/../db/DATA' % self.ROOT_DIR
        self.LOGS = '%s/../logs' % self.ROOT_DIR


class Logger():


    def create_rotating_log(self, path, label="Rotating Log"):
        """
        Creates a rotating log
        """
        self.logger = logging.getLogger(label)
        self.logger.setLevel(logging.INFO)

        # add a rotating handler
        self.handler = RotatingFileHandler(path, maxBytes=10000000, backupCount=10000)
        self.logger.addHandler(self.handler)
        return self.logger


    def setup_logger(self, logger_name, log_file, level=logging.INFO):
        self.log_setup = logging.getLogger(logger_name)
        self.formatter = logging.Formatter('%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
        self.fileHandler = logging.FileHandler(log_file, mode='a')
        self.fileHandler.setFormatter(formatter)
        self.streamHandler = logging.StreamHandler()
        self.streamHandler.setFormatter(formatter)
        self.log_setup.setLevel(level)
        self.log_setup.addHandler(fileHandler)
        self.log_setup.addHandler(streamHandler)

    def logger(self, msg, level, logfile):
        if self.logfile == 'logger2': self.log = logging.getLogger('logger2')
        if self.logfile == 'logger3': self.log = logging.getLogger('logger3')
        if self.level == 'info': self.log.info(msg)
        if self.level == 'warning': self.log.warning(msg)
        if self.level == 'error': self.log.error(msg)


    def __init__(self, log_file='Node'):
        self.log_file = None
        self.Logger = None
        self.getLogger(log_file)


    def utc():
        return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')

    def exc_info():
        exc_type, exc_value, exc_tb = sys.exc_info()
        return '%s %s' % (os.path.basename(exc_tb.tb_frame.f_code.co_filename), exc_tb.tb_lineno)



    def getLogger(self, logFile='Node'):
        if self.Logger is None:
            self.log_file = "%s/%s.log" % (Config().LOGS, logFile)
            self.Logger = self.create_rotating_log(self.log_file, "logger")
        return self.Logger


    def logp(self, msg, mode, console=True):
        msg = '%s %s' % (Logger.utc(), msg)
        if mode == logging.ERROR:
            self.getLogger().error(msg)
        elif mode == logging.WARNING:
            self.getLogger().warning(msg)
        else:
            self.getLogger().info(msg)
        if console:
            print(msg)




class Network():
   import time, socket, zmq, asyncio
   def __init__(self):
       self.logger = Logger('Network')

   def sendMsgZmqReq(self, bin_msg, host, port):
       import zmq

       #requests from the wallets/outside, pay/sendMsg(TX/ICO/Contract) or retrieve wallets/txs/blocks/contracts ...etc
       context = zmq.Context()
       socket = context.socket(zmq.REQ)
       socket.connect("tcp://%s:%s" % (host, port))
       socket.send(bin_msg)
       response = socket.recv_string()
       print('ZMQ REQ response: ', response)



   def sendMsgZmqUdp(self, bin_msg, host, port):
       # Miners Request/Fanout Traffic - # TX_LIST, BLOCK, VOTE, DATA ...etc
       pass



class Crypto():
    def __init__(self):
        self.logger = Logger('Crypto')

    def getKeysFromRandomSeed(self):
        '''Random Private/Signing and Public/Verify keys'''
        try:
            sk = SigningKey(nacl.utils.random(32))
            return sk
        except:
            return None

    def getKeysFromSeed(self, seed):
        '''Return 25519 Curve priv_key,pub_key nacl objects'''
        try:
            if isinstance(seed, str):
                seed = bytes(seed.ljust(32), 'utf8')
            elif not isinstance(seed, bytes):
                seed = packb(seed)
            # pub, priv = keys_from_seed(bin_str)
            sk = priv_key = SigningKey(seed)
            vk = pub_key = VerifyKey(sk.verify_key._key)
            return sk, vk
        except:
            return None

    def sign(self, msg, SignKey):
        ''' Return Curve 25519 Signature - msg hexdigest'''
        try:
            signed_msg = SignKey.sign(msg)
            return signed_msg
        except Exception as ex:

            err_msg = 'Exception on sign msg: %s \n%s, %s' % (msg, Logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            return None

    def verify(self, signed_msg, VerifyingKey):
        '''Return True if msg verified, otherwise false'''
        try:
            VerifyingKey.verify(signed_msg)
            return True
        except:
            return False

    def getPubAddr(self, VK):
        '''Return HMAC hash from pub_key/verify_key'''
        try:
            pub_addr = HMAC.new(VK._key).hexdigest()
            return pub_addr
        except:
            return None


    def to_HMAC(self, bytes_msg):
        '''Return HMAC hash from bytes'''
        try:
            return HMAC.new(bytes_msg).hexdigest()
        except:
            return None



class Transaction():
    def __init__(self):
        self.logger = Logger('Transaction')
        self.version = "1"
        self.TX_MSG_FIELDS = {'ver_num': str, 'msg_type': str, 'input_txs': list, 'output_txs': list, 'from_addr': str,
                              'to_addrs': list, 'asset_type': str, 'amounts': list, 'ts': datetime,
                              'sig_type': str, 'sigs': bytes, 'pub_keys': bytes}

    def setTX(self, ver_num, msg_type, input_txs, output_txs, from_addr, to_addrs, asset_type, amounts, ts, sig_type, sig, pub_keys):
        tx = ()
        tx += (ver_num,)
        tx += (msg_type,)
        tx += (input_txs,)
        tx += (output_txs,)
        tx += (from_addr,)
        tx += (to_addrs,)
        tx += (asset_type,)
        tx += (amounts,)
        tx += (ts,)
        tx += (sig_type,)
        tx += (sig,)
        tx += (pub_keys,)
        return tx #validateTX(tx)


    def validateTX(self, tx):
        if len(tx) > 30000: #TODO config
            return False
        print('validateTX: TX size is %s bytes' % len(tx))
        return True

    def signTX():
        pass

    def sendTX():
        pass

    def verifyTX():
        pass


    def btx2ptx(self):
        pass

    @staticmethod
    def persistTX4verify():
        pass

    def ptx2btx(self):
        pass

    @staticmethod
    def persistTX(): #from pending sqlLite to LevelDB + insertUnspentTx after blockVoted & verified
        pass

    def deletePtx(self): #delete from pending DB after block & TXs have been persisted
        pass

    def relayTX(self, tx_list): #relay to MasterNode if not is Master myself
        pass

    def getTX(self, tx_hash): # query if TX exist in DB used for confirmations, verifications and DoubleSpent check
        pass



class Contract():
    pass

class Ico():
    pass

class Block():

    def sendBlock(self): #by MasterMiner
        pass

    def voteBlock(self):#to MasterMiner or NextOnDutyMiner
        pass

    def verifyBlock(self):
        pass

    def getBlock(self, block_hash): #get block msg
        pass

    @staticmethod
    def persistBlock(self):
        pass


class ServiceDb():
    def __init__(self):
        # self.ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        # self.NODE_SERVICE_DB = '%s/../service_db/DATA/service.db' % self.ROOT_DIR
        # self.NODE_DB = '%s/../db/DATA' % self.ROOT_DIR
        # self.LOGS = '%s/../logs' % self.ROOT_DIR
        config = Config()
        self.logger = Logger('ServiceDb')
        self.ROOT_DIR = config.ROOT_DIR
        self.NODE_SERVICE_DB = config.NODE_SERVICE_DB
        self.NODE_DB = config.NODE_DB
        self.LOGS = config.LOGS
        print('NODE_DB, NODE_SERVICE_DB', self.NODE_DB, self.NODE_SERVICE_DB)
        self.createNodeDbIfNotExist()
        self.SERVICE_DB = sqlite3.connect(self.NODE_SERVICE_DB, isolation_level=None)


    def createNodeDbIfNotExist(self):
        dirs = [self.NODE_DB,  self.NODE_SERVICE_DB, self.LOGS]
        for folder in dirs:
            if not os.path.exists(folder):
                if folder == self.NODE_SERVICE_DB:
                    folder = folder.replace('/service.db', '')
                os.makedirs(folder)


    def getServiceDB(self):
        try:
            if self.SERVICE_DB is None:
                self.SERVICE_DB = sqlite3.connect(self.NODE_SERVICE_DB, isolation_level=None) #TODO ConfigMap
            return self.SERVICE_DB
        except Exception as ex:
            err_msg = 'Exception on get serviceDbConnection to SqlLite NODE_SERVICE_DB: %s, %s' % (Logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            return None


    def queryServiceDB(self, sql):
        try:
            if self.SERVICE_DB is None:
                self.SERVICE_DB = sqlite3.connect(self.NODE_SERVICE_DB, isolation_level=None) #TODO ConfigMap
            return self.SERVICE_DB.execute(sql).fetchall()
        except Exception as ex:
            err_msg = 'Exception on Select (%s) from SqlLite NODE_SERVICE_DB: %s, %s' % (sql, Logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            return None


class Db():
    def __init__(self):
        self.logger = Logger('Db')
        self.LEVEL_DB = None


    def insertDB(self, bin_key, bin_value, db_path):
        # print('Insert to DB %s with Closed connection %s, key: %s, value: %s ' % (db_path, DB is None, bin_key, bin_value))
        try:
            if self.DB.LEVEL_DB is None:
                self.DB.LEVEL_DB = leveldb.LevelDB(db_path)
            self.DB.LEVEL_DB.Put(bin_key, bin_value)
        except Exception as ex:
            err_msg = 'Exception on insert (key %s) (value %s) to LevelDB NODE_DB: %s %s ' % (
            bin_key, bin_value, exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)

    def getDB(self, bin_key, db_path):

        try:
            if self.DB.LEVEL_DB is None:
                self.DB.LEVEL_DB = leveldb.LevelDB(db_path)
            return self.DB.LEVEL_DB.Get(bin_key)
        except:
            return None

    def deleteDB(self, bin_key, db_path):

        try:
            if self.DB.LEVEL_DB is None:
                self.DB.LEVEL_DB = leveldb.LevelDB(db_path)
                self.DB.LEVEL_DB.Delete(bin_key)
        except Exception as ex:
            err_msg = 'Exception on delete (key %s) from LevelDB NODE_DB: %s %s ' % (
            bin_key, exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)


    def isDBvalue(self, bin_key, db_path, dbm='db'):

        try:
            dbm = self.DB.LEVEL_DB
            if dbm is None:
                dbm = leveldb.LevelDB(db_path)  # Once init held by the process
            value = dbm.Get(bin_key)
            # print('isDBvalue key=%s, \nvalue=%s' % (bin_key, value)
            return True
        except Exception as ex:
            return False


class Node():

    def __init__(self):
        from queue import Queue
        self.logger = Logger('Node')
        self.PORT_REP = 7777  # Receiving data from the world TXs, quiries ...etc
        self.PORT_UDP = 8888  # Submitting/Requesting data from the miners
        self.PORT_PUB = 9999  # Publish to Miners fanout
        self.PORT_PUB_SERVER = 5555   # Optional fanout
        self.PORT_SUB_CLIENT = 6666   # Optional subscribe
        self.WORKERS = 3
        self.Q = Queue()
        self.init_servers()


    def restartServer(self, type): #kill process and restart the server
        pass


    def init_server(self, type):
        import time, socket, zmq, asyncio
        from time import sleep
        import threading
        from multiprocessing import Process
        from msgpack import packb, unpackb

        if type is 'rep':
            context = zmq.Context()
            rep_socket = context.socket(zmq.REP)
            rep_socket.bind("tcp://*:%s" % self.PORT_REP)
            print('Starting REP server tcp://localhost:%s' % self.PORT_REP, flush=True)
            while True:
                rep_msg = rep_socket.recv()
                self.Q.put_nowait(rep_msg)
                rep_socket.send(b'ok') #(rep_msg)
                print('REP got a msg: {} bytes \n {}'.format(len(rep_msg), unpackb(rep_msg))) #TODO to continue msg&tx validation
                tx_hash = tools.Crypto.to_HMAC(rep_msg)
                print(tx_hash, ' Key Exist in DB ', tools.isDBvalue(tools.b(tx_hash), tools.NODE_DB))
                tools.validateTX(rep_msg)

        if type is 'udps':
            udps_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udps_socket.bind(('', self.PORT_UDP))
            print('Starting UDP server udp://localhost:%s' % self.PORT_UDP, flush=True)
            while True:
                udp_msg = udps_socket.recvfrom(1024)
                data = udp_msg[0]
                addr = udp_msg[1]
                self.Q.put_nowait(udp_msg[0])

                if not data:
                    break

                reply = data
                udps_socket.sendto(reply, addr)
                # print('Message[' + addr[0] + ':' + str(addr[1]) + '] - ') # + data.strip()) #ToDo validation on MinersIP + verify

        if type is 'pub':
            context = zmq.Context()
            pub_socket = context.socket(zmq.PUB)
            pub_socket.bind("tcp://*:%s" % self.PORT_PUB)
            print('Starting PUB server tcp://localhost:%s' % self.PORT_PUB, flush=True)
            while True:
                try:
                    if not self.Q.empty():
                        pub_msg = Q.get_nowait()
                        pub_socket.send(pub_msg)
                except Exception as ex:
                    print('PUB Exception: %s' % ex, flush=True)
                    #self.logger.logp('Publish Error: ', logging.ERROR, ex)

        if type is 'sub':
            context = zmq.Context()
            sub_socket = context.socket(zmq.SUB)
            sub_socket.connect("tcp://localhost:%s" % self.PORT_PUB)
            sub_socket.setsockopt(zmq.SUBSCRIBE, b'')
            print('Starting SUB server tcp://localhost:%s' % self.PORT_PUB, flush=True)
            count = 0
            while True:
                sub_msg = sub_socket.recv()  # TODO bytes
                if sub_msg: count += 1
                #if count % 10 == 0: print('sub_msg_count', count)

        if type is 'req':
            context = zmq.Context()
            req_socket = context.socket(zmq.REQ)
            req_socket.connect("tcp://localhost:%s" % self.PORT_REP)
            print('Starting REQ server tcp://localhost:%s' % self.PORT_REP, flush=True)


        if type is 'udpc':
            udpc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # test #TODO to remove
            print('Starting UDP client', flush=True)


    # def sendUDP(self, bin_msg, host='localhost', port=self.PORT_UDP):
    #     udpc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     udpc_socket.sendto(bin_msg, (host, port))
    #     response = udpc_socket.recvfrom(1024)
    #     print('Response from %s:%s response: \n%s' %(host, port, response))
    #     return response


    def init_servers(self):
        from time import sleep
        import threading

        TYPES = ['rep', 'udps']
        workers = []
        print('TYPES', TYPES)
        for s in range(len(TYPES)):
            print('Starting server %s' % TYPES[s])
            t = threading.Thread(target=self.init_server, args=(TYPES[s],), name='server-%s' % TYPES[
                s])
            t.daemon = True
            t.start()
            workers.append(t)
        sleep(1)



class Wallet():
    pass

class Exchange():
    pass

class Shop():
    pass

class Relay():
    pass

class Agent():
    pass

class Invoke():
    pass

class Tools(Structure, Config, Crypto, Network, Db, ServiceDb, Transaction, Block, Contract, Wallet, Node, Ico, Agent, Exchange, Shop, Invoke):
    import msgpack as mp
    def __init__(self):
        config = Config()
        #self.Helper = Helper()
        #self.Logger = Logger() #TODO TO remove Doubles
        self.ROOT_DIR = config.ROOT_DIR
        self.NODE_DB = config.NODE_DB
        self.NODE_SERVICE_DB = config.NODE_SERVICE_DB
        self.DB = Db()
        self.SERVICE_DB = ServiceDb()
        self.MsgType = MsgType()
        self.Transaction = Transaction()
        self.Crypto = Crypto()
        self.Network = Network()
        self.Node = Node()

    def utc(self):
        return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')

    def b(self, str):
        try:
            return bytes(str, 'utf8')
        except:
            return None  # str

    def packb(self, obj):
        try:
            return mp.packb(obj)
        except:
            return None

    def unpackb(self, packed_obj):
        try:
            return mp.unpackb(packed_obj)
        except:
            return None



    @staticmethod
    def p(s):
        print(s)

    def pp(self, s):
        print(s)







if __name__ == "__main__":
    Tools.p("v1.Tools running as a stand-alone script")
    #print('Tools version %s' % Tools().version)
    tools = Tools()
    test = Test()
    SK, VK = tools.getKeysFromSeed('Bob')
    msg = b'msg'
    signed_msg = tools.sign(msg, SK)
    verified_sig = tools.verify(signed_msg, VK)
    pub_addr = tools.getPubAddr(VK)
    print("msg verified %s for publicKey: %s" % (verified_sig, pub_addr))  # VK == VerifyKey(VK._key)
    #test.persistKeysInServiceDB(SK._signing_key, SK.verify_key._key, SK._seed, pub_addr, 'Bob')
    query = "select * from v1_test_accounts where pub_addr='%s'" % pub_addr
    rec = tools.SERVICE_DB.queryServiceDB(query)
    # genesis_tx = ('1', MSG_TYPE_SPEND_TX, ['%s,%s' % (genesis_sig['r'], genesis_sig['s'])], '1/1', ['%s,%s' % (genesis_pub_key['x'], genesis_pub_key['y'])], ['TX-GENESIS'], ['TX_GENESIS'], 'GENESIS', genesis_to_addr, '1', 10000000000.12345, merkle_date)
    ##tx = tools.Transaction.setTX('1', 'PTX', ['TX_GENESIS'], [tools.to_HMAC(tools.b('TX_GENESIS_%s' % pub_addr))], 'Genesis', [pub_addr], '1', [1000.1234], '2018-01-01 00:00:00.000000', '1/1', signed_msg._signature, VK._key)
    tx = tools.Transaction.setTX('1', tools.MsgType.PARENT_MSG, [tools.MsgType.UNSPENT_TX + b'GENESIS'],
                                 [tools.to_HMAC(tools.MsgType.UNSPENT_TX + tools.b('GENESIS_%s' % pub_addr))],
                                 'Genesis', [pub_addr], '1', [1000.1234], '2018-01-01 00:00:00.000000', '1/1',
                                 signed_msg._signature, VK._key)
    from msgpack import packb, unpackb
    signed_msg = tools.sign(str(tx[:-2]).encode(), SK)
    bin_signed_msg = (signed_msg.message, signed_msg.signature, VK._key)
    assert tools.verify(signed_msg, VK) #tools.verify(signed_msg, VerifyKey(bin_signed_msg[-1]))
    assert VerifyKey(rec[0][1]) == VK
    tx_hash = tools.Crypto.to_HMAC(packb(bin_signed_msg))
    tx_bytes = packb(bin_signed_msg)
    tools.insertDB(tools.b(tx_hash), tx_bytes, tools.NODE_DB)
    ##print(tools.getDB(tools.b(tx_hash), tools.NODE_DB))
    print('LevelDB tx_hash: %s value: \n' % tx_hash, tools.unpackb(tools.getDB(tools.b(tx_hash), tools.NODE_DB)))
    #tools.sendTX()
    tools.sendMsgZmqReq(tx_bytes, 'localhost', tools.Node.PORT_REP)
   # tools.logp('Finished', logging.INFO)
#len(bin_signed_msg[0]) #181 == len(str(tx[:-2]).encode()) == TX_MSG 1input/1output/1amount 32+32+8=72 * 10  = +720b
#len(signed_msg.signature) #64 Sig
#len(bin_signed_msg[2]) #32  VK
#181+64+32=277b/Msg ~300b per input ~30kb - 100tx limit #246-287b
    # while True: #Accept connections 4ever
    #     time.sleep(0.001)

#Test