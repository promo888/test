import os, sys, subprocess, psutil, pkgutil
import msgpack as mp
import sqlite3, plyvel #leveldb
import datetime, time, configparser
import logging
from logging.handlers import RotatingFileHandler
from msgpack import packb, unpackb
from copy import deepcopy

import configparser
from nacl.bindings import crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES
from nacl.public import Box, PrivateKey, PublicKey
from nacl.bindings.crypto_sign import crypto_sign_open as verify, crypto_sign as sign, \
    crypto_sign_seed_keypair as keys_from_seed
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from Crypto.Hash import SHA256, HMAC, RIPEMD
from decimal import Decimal

import time, socket, zmq, asyncio
from time import sleep
import threading
from multiprocessing import Process #ToDo killPorts+watchdog
from queue import Queue

class Test():

    def deleteDir(self, path):
        """deletes the path entirely"""
        if sys.platform == "win32":
            cmd = "RMDIR " + path + " /s /q"
        else:
            cmd = "rm -rf " + path
        result = os.system(cmd)
        print('res: %s cmd: %s' % (result, cmd))


    def getCaller(self):
        import inspect
        curframe = inspect.currentframe()
        calframe = inspect.getouterframes(curframe, 2)
        print('Caller name: ', calframe[1][3])
        print('Caller name: ', inspect.stack()[1][3])
        #print('Caller name: ', sys._getframe().f_back.f_code.co_name)


    def persistKeysInServiceDB(self, bin_priv, bin_pub, bin_seed, pub_addr_str, nick=''):
        ddl_v1_test_accounts = '''CREATE TABLE if not exists v1_test_accounts
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
                con.execute(ddl_v1_test_accounts)
                cur.execute(sql, [sqlite3.Binary(bin_priv), sqlite3.Binary(bin_pub), sqlite3.Binary(bin_seed), pub_addr_str, nick])
                con.commit()
        except Exception as ex:
            # logger = Logger('Test')
            # err_msg = 'Exception on Select (%s) from SqlLite NODE_SERVICE_DB: %s, %s' % (sql, Logger.exc_info(), ex)
            # logger.logp(err_msg, logging.ERROR)
            return None


        def persistPendingTX(self, bin_priv, bin_pub, bin_seed, pub_addr_str, nick=''):
            ddl_v1_pending_tx = '''
                   CREATE TABLE IF NOT EXISTS 'v1_pending_tx' (
                   'ver_num'	TEXT NOT NULL,
                   'msg_type'	TEXT NOT NULL,
                   'input_txs'	TEXT NOT NULL,
                   'output_txs'	TEXT NOT NULL,
                   'to_addrs'	TEXT NOT NULL,
                   'asset_type'	TEXT NOT NULL,
                   'amounts'	TEXT NOT NULL,                                               
                   'pub_keys'	BLOB NOT NULL,
                   'msg_hash'   TEXT NOT NULL, 
                   'from_addr'	TEXT NOT NULL,
                   'node_verified'	INTEGER DEFAULT 0,
                   'node_date'  TEXT DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY(msg_hash) 
                   
               );
               '''
#TODO sigtype is required on create MultiSig Wallet + MultiSigTx

            sql = "INSERT INTO v1_test_accounts (priv_key,pub_key,seed,pub_addr,nick) values (?,?,?,?,?)"
            con = self.getServiceDb() #ServiceDb().getServiceDB()
            try:
                with con:
                    cur = con.cursor()
                    con.execute(ddl_v1_pending_tx)
                    cur.execute(sql, [sqlite3.Binary(bin_priv), sqlite3.Binary(bin_pub), sqlite3.Binary(bin_seed),
                                      pub_addr_str, nick])
                    con.commit()
            except Exception as ex:
                # logger = Logger('Test')
                # err_msg = 'Exception on Select (%s) from SqlLite NODE_SERVICE_DB: %s, %s' % (sql, Logger.exc_info(), ex)
                # logger.logp(err_msg, logging.ERROR)
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


# class Events:
#     MSG_ACCEPTED
#     MSG_VERIFIED
#     BLOCK_ACCEPTED
#     BLOCK_VOTE_ACCEPTED
#     I_AM_A_MASTER
#     MASTER_IS_NOT_AVAILABLE
#     NODE_PENALTIED
#     CONTRACT_DUE
#     CONTRACT_SIDE_CONFIRMED
#     CONTRACT_RELEASE
#     ORACLE_INVOLVED

#tools.MsgType.__class__.__dict__.values()
class Types(): #b'\xa7' in Types.__dict__.values() tools.MsgType.__getattribute__('UNSPENT_TX')

    #Transactions/Messages
    UNSPENT_TX = '+'    #b'+' #b'\x00'
    SPENT_TX = '-'      #b'-'   #b'\x01'
    PARENT_TX_MSG = '*' #b'*' #b'\x02'
    PARENT_TX_MSG_MAX_SIZE = 1024
    SPEND_MULTI_SIG_TX = b'\x03'
    MINER_FEE_TX = b'\x04'
    MINER_ISSUE_TX = b'\x05'
    BLOCK_MSG = b'B' #b'\xb0'
    BLOCK_MSG_MAX_SIZE = 4096
    VOTE_MSG = b'V' #b'\xb1'
    CONTRACT_TX = b'C' #b'\xc0'
    CONTRACT_CONFIRM_TX = b'T' #b'\xc1'
    CONTRACT_MSG = b'D' #b'\xc2'
    REGISTER_TX = b'\xe1'
    EXCHANGE_TX = b'E' #b'\x88'
    ICO_TX = b'I' #b'\xa6'
    AGENT_TX = b'A' #b'\xa7'
    INVOKE_TX = b'\xd1'
    RELAY_TX = b'R' #b'\xd2'
    MSG_MSG = b'M'  #b'\xd3'


    def isValidType(self, typeValue):
        if typeValue is None or len(typeValue) != 1:
            return None
        return next((k for k, v in tools.MsgType.__class__.__dict__.items() if v == typeValue), None)


    def getMsgTypes(self):
        return ['UNSPENT_TX', 'SPENT_TX', 'PARENT_TX_MSG', 'SPEND_MULTI_SIG_TX',
                'MINER_FEE_TX', 'MINER_ISSUE_TX', 'BLOCK_MSG', 'VOTE_MSG',
                'CONTRACT_TX', 'CONTRACT_CONFIRM_TX', 'CONTRACT_MSG',
                'REGISTER_TX', 'EXCHANGE_TX', 'ICO_TX', 'AGENT_TX',
                'INVOKE_TX', 'RELAY_TX', 'MSG_MSG'
        ]


    def getMsgType(self, msg_type):
        return self.isValidType(msg_type)


    def changeMsgType(self, msg, toType):
        if toType in self.getMsgTypes():
            msg[1] = tools.MsgType.__getattribute__(toType)
            return msg
        return None


    #Wallets

    #CREATE_ASSET_TX
    #MULTI_SIG_WALLET_CREATE_TX
    #SYNC_WALLET_REQUEST
    #GET_TX_REQUEST
    #GET_BLOCK_REQUEST
    #GET_MINER_NODES_REQUEST
    #GET_MINER_PENALTIES_REQUEST
    #VERIFY_BTC_REQUEST
    #VERIFY_ETH_REQUEST
    #ASSIGN_ORACLE
    #ANONYMOUS TX
    #

    #Config
    MAX_MSG_SIZE_BYTES = 32768

    # @staticmethod
    # def toName(self, value):
    #     if isinstance(value, int):
    #         value = value.to_bytes(1, 'little')
    #     for key, item in TransactionType.__dict__.items():
    #         if value == item:
    #             return key
    #     return None
    #
    # @staticmethod
    # def getValue(self, keyName):
    #     if not isinstance(keyName, str):
    #         return None
    #     else:
    #         for key, value in tools.MsgType.types: # .__dict__.items():
    #             if key == keyName.upper():
    #                 return value



# class MsgType:
#     SPEND_TX_MSG_FIELDS = (
#     'ver_num', 'msg_type', 'pub_keys', 'input_txs', 'output_txs', 'from_addr', 'to_addrs',
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
        self.MAIN_COIN = '1' #todo 2change 4meaningful name

class Logger():


    def create_rotating_log(self, path, label="Rotating Log"):
        """
        Creates a rotating log
        """
        self.logger = logging.getLogger(label)
        self.logger.setLevel(logging.INFO)

        #create file if not exist
        directory = os.path.dirname(path)
        if not os.path.exists(directory):
            os.makedirs(directory)
        if not os.path.exists(path):
            with open(path, 'w'): pass


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
       #self.logger = Logger('Network')
       pass

   def sendMsgZmqReq(self, bin_msg, host, port):
       #requests from the wallets/outside, pay/sendMsg(TX/ICO/Contract) or retrieve wallets/txs/blocks/contracts ...etc

       context = zmq.Context()
       socket = context.socket(zmq.REQ)
       socket.connect("tcp://%s:%s" % (host, port))
       socket.send(bin_msg)
       response = socket.recv_string()
       print('ZMQ REQ response: ', response)
       if 'OK:'.upper() in response.upper():
           return True
       else:
           return False



   def sendMsgZmqUdp(self, bin_msg, host, port):
       # Miners Request/Fanout Traffic - # TX_LIST, BLOCK, VOTE, DATA ...etc
       pass



class Crypto():
    def __init__(self):
        #self.logger = Logger('Crypto')
        pass

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

    def signMsg(self, msg, SignKey):
        ''' Return Curve 25519 Signature - msg hexdigest'''
        try:
            if not isinstance(SignKey, SigningKey):
                SignKey = SigningKey(SignKey)
            signed_msg = SignKey.sign(msg)
            return signed_msg
        except Exception as ex:
            err_msg = 'Exception on sign msg: %s \n%s, %s' % (msg, Logger.exc_info(), ex)
            ##self.logger.logp(err_msg, logging.ERROR)
            tools.logger.logp(err_msg, logging.ERROR)
            return None

    def verifyMsgSig(self, signed_msg, VerifyingKey):
        '''Return True if msg verified, otherwise false'''
        try:
            SM = signed_msg
            VK = VerifyingKey
            if type(signed_msg) is not SignedMessage:
                SM = SignedMessage(signed_msg)
            if type(VerifyingKey) is not VerifyKey:
                VK = VerifyKey(VerifyingKey) #TODO assert VerifyKey(signed_msg[-32:]) == VK
            #print('SM', SM)
            #print('VK', VK)
            #print('Unpacked MsgType: ', type(unpackb(signed_msg)))
            verified_msg = VK.verify(SM)
            print('MsgSigVerified: ', type(unpackb(verified_msg)), unpackb(verified_msg))
            #TODO check if msg[0] is list|tuple unsigned tx list|signed_tx_list utx|stx
            #sigVerified, signedMsg =tools.verifyMsgSig( block_signed_msg_vk[0], bvk)
            #unsigned_ptx = unpackb(signedMsg)
            #for i in len(unsigned_ptx[-1]): #TODO getBlock | tuple? fields_index
            #    print(unpackb(unsigned_ptx[i]))
            #    child_tx = unsigned_ptx[0][i]
            #    res = validateMsg(tx)
            return True, verified_msg
        except Exception as ex:
            print('ErrorLine: ', ex.__traceback__.tb_lineno)
            return False, None

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
        #self.logger = Logger('Transaction')
        self.version = "1"
        self.TX_MSG_FIELDS = {'ver_num': str, 'msg_type': str, 'input_txs': list, #'output_txs': list, # 'from_addr': str,->Multisig
                              'to_addrs': list, 'asset_type': str, 'amounts': list, 'pub_keys': bytes}
        self.TX_MSG_FIELDS_INDEX = {0: 'ver_num', 1: 'msg_type', 2: 'input_txs', 3: 'to_addrs',
                                    4: 'asset_type', 5: 'amounts', 6: 'pub_keys'}

    def setTX(self, ver_num, msg_type, input_txs, to_addrs, asset_type, amounts, pub_keys): #output_txs,
        tx = ()
        tx += (ver_num,)
        tx += (msg_type,)
        tx += (input_txs,)
#        tx += (output_txs,)
        tx += (to_addrs,)
        tx += (asset_type,)
        tx += (amounts,) # = Decimal('100000000000.1234567890') #TODO from decimal import Decimal; type(d) is Decimal #len('100000000000.1234567890'.encode()) MAX_LEN 21 + .8n
        #TODO continue len(str(amounts[0]).split('.')[1]) , '100000000000.12345678' 21chars + < b108 MAX_SUPPLY
        #TODO sig_type,sigs for MultiWalletTX
        #tx += (sig_type,)
        #tx += (sigs,)
        tx += (pub_keys,)
        return tx #validateTX(tx)
    #len((639).to_bytes(2, 'little').decode()) == 2
    #len(str(100).encode()) == 3


    def validateMsgSize(self, msgType, bin_msg):
        msg_max_size = {self.MsgType.PARENT_TX_MSG: self.MsgType.MAX_MSG_SIZE_BYTES} #32678} #TODO config
        if msgType not in msg_max_size.keys() or len(bin_msg) > msg_max_size[msgType]:
            return False
        return True


    def decodeMsg(self, msg_with_bin_values):
        try:
            decoded_msg = ()
            for f in msg_with_bin_values:
                if type(f) is bytes:
                    t = self.dec(f)
                    decoded_msg += (t,)
                elif type(f) is list:
                    l = [self.dec(v) if type(v) is bytes else v for v in f]
                    decoded_msg += (l,)
                else:
                    decoded_msg += (f,)
            return decoded_msg
        except:
            return None
       #tuple(unpackb(packb(msg_with_bin_values))) == msg_with_bin_values
       #((packb(str(decoded_msg[5][0]))))

    # con = sqlite3.connect(":memory:")
    # cur = con.cursor()
    # l = [b'1.1', b'2.2', b'3.3']
    # print(packb(l))
    # cur.execute("drop table if exists test")
    # cur.execute("create table if not exists test(b BLOB, b1 BLOB, b2 BLOB, b3 BLOB, b4 BLOB,b5 BLOB,b6 BLOB)")
    # b = packb(l)
    # # print(sqlite3.Binary(b))
    # cur.execute("insert into test (b, b1, b2 ,b3, b4, b5 ,b6) values(?,?,?,?,?,?,?)",
    #             [sqlite3.Binary(b), sqlite3.Binary(b), sqlite3.Binary(b), sqlite3.Binary(b), sqlite3.Binary(b),
    #              sqlite3.Binary(b), sqlite3.Binary(b)])
    # con.commit()
    # print(cur.execute("select * from test").fetchall())
    #
    # unpackb(packb(999999999.88888888)) == 999999999.88888888
    #len(packb(999999999.8888888890))  == 9 #decimal #999999999 ==5 999999999012 ==9 999999999012.12345678 ==9
    # Decimal(unpackb(packb(999999999012.12345678)))
    #len((('999999999012.12345678'.encode())))
    #Decimal((b'999999999012.12345678').decode())


    def verifyMsg(self, decoded_msg):
        try:
            if decoded_msg[1] == tools.MsgType.PARENT_TX_MSG:
                if not tools.verifyPTX(decoded_msg):
                    return False
            elif decoded_msg[1] == tools.MsgType.CONTRACT_TX:
                pass #todo continue
            else:
                return False
        except Exception as ex:
            print('ErrorLine: ', ex.__traceback__.tb_lineno)
            return False


    def validateMsg(self, bin_msg): #used for tmp persistance handled by tasks
        #print('ValidateMsg...')
        #TODO verifyWalletSenderExist
        # isinstance(VerifyKey(unpackb(bin_msg)[1]), VerifyKey) #pub_k hash
        #and
        #tools.isDBvalue( VerifyKey((unpackb(bin_msg)[1]))._key ) #pub_k hash
        #or?
        # tools.isDBvalue(tools.to_HMAC(unpackb(bin_msg)[1])) #pub_k hash

        #check that wallet exist and msg(duplicate) not exist
        #msg__db_wallet = tools.b(tools.to_HMAC(VerifyKey(bin_msg[-32:])._key))
        #msg_db_hash = tools.b(tools.to_HMAC( bin_msg[:-32])) #msg_hash


        try:
            if len(bin_msg) > tools.MsgType.MAX_MSG_SIZE_BYTES:
                return False
            #TODO if msg is list -> type(unpackb(bin_msg)) is list -> elem unpackb is Tuple
            unpacked_msg = unpackb(bin_msg) if not isinstance(bin_msg, tuple) else bin_msg
            msg = tuple(unpackb(unpacked_msg[0]))
            decoded_msg = tools.decodeMsg(msg)
            if decoded_msg is None:
                return False
            # if not self.validateMsgSize(decoded_msg[1], bin_msg):
            #     return False
            if type(unpacked_msg[1]) is not VerifyKey:
                vk = VerifyKey(unpacked_msg[1])
            if decoded_msg[1] == tools.MsgType.PARENT_TX_MSG:
               return tools.validateTX(decoded_msg) #, unpacked_msg[1], vk): #self.to_HMAC(bin_msg)
            elif msg[1] == tools.MsgType.BLOCK_MSG: #tools #TODO add decoderByMsgType
                print('################## NEW BLOCK TODO ##################')
                return tools.validateBlock(msg)
                #TODO insert SDB block
                #return msg #, unpacked_msg[-2], unpacked_msg[-1]
            else:
                return False
        except Exception as ex:
            #print(tools.logger.exc_info())
            print('ErrorLine: ',ex.__traceback__.tb_lineno)
            return False


    def validateTX(self, tx_msg, pub_key=None, verifyTX=False):
        #print('ValidateTX...')
        try:
            if type(self) is Tools:
                tx_msg_fields = self.Transaction.TX_MSG_FIELDS
                tx_msg_fields_index = self.Transaction.TX_MSG_FIELDS_INDEX
            else:
                tx_msg_fields = self.TX_MSG_FIELDS
                tx_msg_fields_index = self.TX_MSG_FIELDS_INDEX
            tx_field_names = list(tx_msg_fields_index.values())[:-2] #fields amount
            for i in range(len(tx_field_names)):
                field_value = tx_msg[i]
                if type(field_value) is not tx_msg_fields[tx_field_names[i]]: #fields type
                    print('ERROR: field type %s, expected %s' % (type(field_value), tx_msg_fields[tx_field_names[i]]))
                    return False
                if (type(field_value) is list):
                    restricted_list_types = [v for v in field_value if type(v) not in (bytes, str)] #list_fields type
                    if len(restricted_list_types) > 0:
                        print('ERROR: restricted_list_types %s', restricted_list_types)
                        return False
            return tx_msg
        except Exception as ex:
            return False


#tools
    def signTX(self, ver_num, msg_type, input_txs, to_addrs, asset_type, amounts, pub_keys=[b"*" * 32], seed=b"*" * 32):
        try:
            tx = self.setTX(ver_num, msg_type, input_txs, to_addrs, asset_type, amounts, pub_keys)
            if tx is not None and self.validateTX(tx):
                sk, vk = tools.getKeysFromSeed(seed)
                signed_msg = tools.signMsg(packb(tx[:-2]), sk)
                bin_signed_msg = (signed_msg.message, signed_msg.signature, vk._key)
                return bin_signed_msg
        except Exception as ex:
            return None

    #
    # def signTX(self, tx_msg, pub_keys=b"*" * 32, seed=b"*" * 32):
    #     try:
    #         tx = self.setTX(ver_num, msg_type, input_txs, to_addrs, asset_type, amounts, pub_keys)
    #         if tx is not None and self.validateTX(tx):
    #             sk, vk = tools.getKeysFromSeed(seed)
    #             signed_msg = tools.signMsg(packb(tx[0]), sk)
    #             bin_signed_msg = (signed_msg.message, signed_msg.signature, vk._key)
    #             return bin_signed_msg
    #     except Exception as ex:
    #         return None

    def sendMsg(self, bin_signed_msg, host='localhost', port=7777):
        #TODO to continue with NewBlock ->New Wallet
        #sk = msg[1] if type(msg[1]) is SigningKey else SigningKey(msg[1])
        #vk = msg[2] if type(msg[2]) is VerifyKey else VerifyKey(msg[2])
        #signed_msg = tools.signMsg(packb(msg[0]), sk)
        #bin_signed_msg = (signed_msg.message, vk._key)if
        if bin_signed_msg is not None:
            return tools.sendMsgZmqReq(bin_signed_msg, host, port)

    def sendTX(self, ver_num, msg_type, input_txs, to_addrs, asset_type, amounts, seed=None, host=None, port=None,sendTx=True):
        bin_signed_msg = self.signTX(ver_num, msg_type, input_txs, to_addrs, asset_type, amounts, seed=seed)
        if bin_signed_msg is not None and host is not None and port is not None:
            if sendTx and bin_signed_msg is not None:
                tools.sendMsgZmqReq(packb(bin_signed_msg), host, port)
        return bin_signed_msg


    def submitTX(self, tx, seed=None, host=None, port=None, submitTx=True):
        bin_signed_msg = self.signTX(tx[0], tx[1], tx[2], tx[3], tx[4], tx[5], tx[6], seed=seed)
        if bin_signed_msg is not None and host is not None and port is not None:
            if submitTx:
                tools.sendMsgZmqReq(packb(bin_signed_msg), host, port)
        return bin_signed_msg


    def decodeDbMsg(self, bin_msg):
        try:
            return tools.decodeMsg(unpackb(unpackb(bin_msg)[0]))
        except:
            return None


    #tools methods
    def insertDbTx(self, bin_signed_msg, msg_type='*', override=False):
        print('version', tools.s(unpackb(bin_signed_msg[0])[0]))
        print('msgType', tools.s(unpackb(bin_signed_msg[0])[1]))
        print('txType', tools.s(unpackb(bin_signed_msg[0])[2][0])[0:1])
        print('inputTx', tools.s(unpackb(bin_signed_msg[0])[2][0])[1:])
        tx_hash = tools.Crypto.to_HMAC(packb(bin_signed_msg))
        tx_bytes = packb(bin_signed_msg)
        valid_msg = self.validateMsg(tx_bytes)
        #for itx in (unpackb(bin_signed_msg[0])[2]:
        #    if tools.is
        if valid_msg:
            return tools.insertDbKey(tools.b(tx_hash), tx_bytes, tools.NODE_DB, override) #tools.b(msg_type + tx_hash)
        else:
            return None


    def stx2btx(self, stx):
        try:
            list_fields_names = [k for k in tools.Transaction.TX_MSG_FIELDS
                                 if tools.Transaction.TX_MSG_FIELDS[k] is list]
            list_field_indexes = [k for (k, v) in tools.Transaction.TX_MSG_FIELDS_INDEX.items() if
                                  v in list_fields_names and v in tools.Transaction.TX_MSG_FIELDS_INDEX.values()]
            list_stx = list(stx)
            for i in list_field_indexes:
                list_stx[i] = list_stx[i][1:-1].split(",")
            tx_fields_len = len(tools.Transaction.TX_MSG_FIELDS_INDEX.keys())
            sdb_tx = tuple(list_stx[:tx_fields_len])
            btx = (packb(sdb_tx[0]), sdb_tx[-2], sdb_tx[-1])
            btx_hash = tools.Crypto.to_HMAC(packb((packb(sdb_tx[:-2]), sdb_tx[-2], sdb_tx[-1])))
            return packb(btx), btx_hash
        except Exception as ex:
            err_msg = 'Exception Transaction.stx2btx Failed to convert TX from sqlDb into levelDB format(b): %s, %s' % (
            Logger.exc_info(), ex)
            #self.logger.logp(err_msg, logging.ERROR)
            print(err_msg)
            return None


    def btx2stx(self, bmsg):
        try:
            stx = tools.decodeDbMsg(bmsg)
            sig = unpackb(bmsg)[1]
            pubk = unpackb(bmsg)[2]
            sdb_tx = stx
            sdb_tx += (sig,)
            sdb_tx += (pubk,)
            btx = packb(stx), sig, pubk
            btxp = packb(btx)
            stx_hash = tools.Crypto.to_HMAC(btxp) #TODO cryptoPubK
            return sdb_tx, stx_hash
        except Exception as ex:
            return None


    def sdbtx2btx(self, sdb_msg_hash):
        try:
            stx = tools.SERVICE_DB.queryServiceDB("select * from v1_pending_tx where msg_hash='%s'" % sdb_msg_hash)
            if len(stx) != 1:
                return None
            stx = stx[0]

            return tools.stx2btx(stx)
        except Exception as ex:
            err_msg = 'Exception Transaction.sdbtx2btx Failed to convert TX from sqlDb into levelDB format(b): %s, %s' % (
            Logger.exc_info(), ex)
            #self.logger.logp(err_msg, logging.ERROR)
            print(err_msg)
            return None


    def dbtx2stx(self, db_msg_hash):
        try:
            bmsg = tools.getDbRec(db_msg_hash)
            if bmsg is None:
                return None
            return tools.btx2stx(bmsg)
        except Exception as ex:
            err_msg = 'Exception Transaction.dbtx2sdbbtx Failed to convert TX from LevelDB to sqlDb format(b): %s, %s' % (
            Logger.exc_info(), ex)
            #self.logger.logp(err_msg, logging.ERROR)
            print(err_msg)
            return None



    def getServiceDbTx(self, msg_hash, unique=True):
        records = tools.SERVICE_DB.queryServiceDB("select * from v1_pending_tx where msg_hash='%s'" % msg_hash)
        print('%s Records Found' % len(records))
        if len(records) == 0:
            return None
        else:
            res = records[0] if unique else records
            return res


    def getTxAmount(self, stx):
        try:
            asset_field_index = list(tools.Transaction.TX_MSG_FIELDS_INDEX.values()).index('asset_type')
            asset_type = stx[asset_field_index]
            amounts_field_index = list(tools.Transaction.TX_MSG_FIELDS_INDEX.values()).index('amounts')
            list_amounts = (stx[amounts_field_index][1:-1].split(","))
            decimal_list_amounts = [Decimal(x) for x in list_amounts]
            total_outputs_amount = (format(sum(decimal_list_amounts), '.8f'))
            #assert sum(decimal_list_amounts) == Decimal(format(sum(decimal_list_amounts), '.8f'))

            return asset_type, total_outputs_amount
        except Exception as ex:
            #TODO logger
            return None



    def verifyTX(self, ptx_msg):
        pass


    #TODO verifyBlock or sdb_msg_limit
    def verifyPTX(self, ptx_msg):
        ptx_hash = tools.Crypto.to_HMAC(packb(ptx_msg))
        if tools.isDBvalue(ptx_hash) is not None:
            return False
        else:
            pass #return verifyTX



    # @staticmethod
    def persistTX4verify():
        pass

    def ptx2btx(self):
        pass

    # @staticmethod
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
    def createAsset(self, id, name, supply, create_asset_fee): #fee is tx without To -> Burn -> Recycle -
        if not tools.isDBvalue(id):
            return tools.insertDbKey(id, (name, supply))
        else:
            return False #todo reason?

    def createContract(self):
        pass



class State():
    def __init__(self):
        self.blockData = {'msg_hash': set(), 'itx': set(), 'from': set(), 'to': set(), '*': set()}
        self.blockChain = {'last_block': None, 'last_block_state': None, 'current_block': None}
        self.taskRunner = {'task': set(), 'task_state': set()}


class Block():
    def __init__(self):
        #self.logger = Logger('Block')
        self.version = "1"
        self.BLOCK_MSG_FIELD_TYPE = {'ver_num': bytes, 'msg_type': bytes, 'input_msgs': list, 'miner_pub_key': bytes}
        self.BLOCK_MSG_INDEX_FIELD = {0: 'ver_num', 1: 'msg_type', 2: 'input_msgs', 3: 'miner_pub_key'}
        self.BLOCK_MSG_FIELD_INDEX = {'ver_num': 0, 'msg_type': 1, 'input_msgs': 2, 'miner_pub_key': 3}


    def insertGenesis(self, genesis_block):
        gSK, gVK = tools.getKeysFromSeed('Miner0')
        g_wallet = tools.to_HMAC(gVK._key)

        createdWallet = tools.createWallet(g_wallet)
        assert createdWallet
        createdAsset = tools.createAsset('1', 'MainCoin', 128000000000, 0.0001)
        assert createdAsset

        unspent_input_genesis_tx = tools.MsgType.UNSPENT_TX + 'GENESIS'.ljust(32)
        genesis_tx = tools.Transaction.setTX('1', tools.MsgType.PARENT_TX_MSG, [unspent_input_genesis_tx],
                                     [g_wallet], '1', [b'999999999.12345678'],
                                     gVK._key)
        g_signed_msg = tools.signMsg(packb(genesis_tx[:-1]), gSK)
        g_tx_hash = tools.to_HMAC(g_signed_msg._message)
        g_sig_verified, g_verified_msg = tools.verifyMsgSig(g_signed_msg, gVK._key)
        # tools.verify(g_signed_msg, VerifyKey(g_bin_signed_msg[-1]))
        assert g_sig_verified
        assert g_verified_msg == g_signed_msg._message
        g_signed_msg_and_key = (g_signed_msg, gVK._key) #TODO persistKe2WalletIfNotExist
        g_signed_msg_and_key_bytes = packb(g_signed_msg_and_key)
        print('G2 TX hash', g_tx_hash)
        #TODo valid - temp disabled
        # tools.insertDbKey(g_tx_hash, g_signed_msg_and_key_bytes, tools.DB.DB_PATH)
        # signed_msg, pub_key = unpackb(tools.getDbRec(g_tx_hash))
        # verified, msg = tools.verifyMsgSig(SignedMessage(signed_msg), pub_key)
        # assert verified

        g_tx_hash_arr = [g_tx_hash]
        g_block_msg = '1', tools.MsgType.BLOCK_MSG, g_tx_hash_arr
        g_signed_block_msg = tools.signMsg(packb(g_block_msg), gVK._key)
        g_signed_block_msg_and_key_bytes = packb((g_signed_msg, gVK._key))

        genesis_block = []

        block_bin = tools.validateMsg(genesis_block)
        block_verified, block_msg = tools.verifyMsg(block_bin)
        assert block_msg is not None
        block_hash = tools.to_HMAC(block_bin)
        tx_bin = tools.validateMsg(block_msg[0])
        tx_msg = tools.verifyPTX(tx_bin)
        tx_hash = tools.to_HMAC(tx_bin)


        #todo refactor return false wirh raise Exception+rollback
        #tools.insertDbKeys()
        pass

    def sendBlock(self): #by MasterMiner
        pass

    def voteBlock(self):#to MasterMiner or NextOnDutyMiner
        pass


    def validateBlock(self, block_msg):
        #print('ValidateTX...')
        try:
            if not block_msg[1] is self.MsgType.BLOCK_MSG:
                return False
            if len(packb(block_msg)) > self.MsgType.BLOCK_MSG_MAX_SIZE:
                return False #TODO with key
            if type(self) is Tools:
                block_msg_fields = self.Block.BLOCK_MSG_FIELDS #TODO getMsgFields(msgType) + msgLimit
                block_msg_fields_index = self.Block.BLOCK_MSG_FIELDS_INDEX
                block_field_names = list(block_msg_fields_index.values()) #[0] #fields amount
                for i in range(len(block_field_names)-1):
                    field_value = block_msg[i]
                    if type(field_value) is not block_msg_fields[block_field_names[i]]: #fields type
                        return False
                    if (type(field_value) is list):
                        for msg in field_value:
                            #restricted_list_types = [v for v in list_value if type(v) not in (bytes, str, list)] #list_fields type
                            #if len(restricted_list_types) > 0:
                                 #return False
                            if len(msg) != 32 or type(msg) is not bytes: #32b hash_id
                                return False
                return block_msg
            else:
                return False
        except Exception as ex:
            print('ErrorLine: ', ex.__traceback__.tb_lineno)
            return False



    def verifyBlock(self, msgtype_arr):
        to_persist_arr = []
        arr_hash = tools.Crypto.to_HMAC(packb(msgtype_arr))
        block_hash = tools.MsgType.BLOCK_MSG + arr_hash
        if tools.isDBvalue(arr_hash) or tools.isDBvalue(block_hash):
            return False
        for msgtype in msgtype_arr:
            valid_msg = tools.validateMsg(msgtype)
            if not valid_msg:
                return False
            if not tools.verifyMsg(valid_msg):
                return False
            #TODO get/add additional recs to persist byType -> tx + spent- unspent...
        return to_persist_arr


    def getBlock(self, block_hash): #get block msg
        pass

    #@staticmethod
    def persistBlock(self, msgtype_arr):
        verified_block = self.verifyBlock(msgtype_arr)
        if verified_block and type(verified_block) is list:
            print('TO_IMPLEMENT PERSIST TXs -> RM SDB')
            pass

    def block2db(self, verified_decoded_block):
        #validateVerifyEachMsg
        #ignore/return  ifNotAssertedValidatedVerified
        #persistTx -> createOrUpdateWallet
        #persistBlock
        # persistUnspentTxs | Msgs ... other types


        pass


class ServiceDb():
    def __init__(self):
        # self.ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        # self.NODE_SERVICE_DB = '%s/../service_db/DATA/service.db' % self.ROOT_DIR
        # self.NODE_DB = '%s/../db/DATA' % self.ROOT_DIR
        # self.LOGS = '%s/../logs' % self.ROOT_DIR
        config = Config()
        self.logger = Logger() #('ServiceDb')
        self.ROOT_DIR = config.ROOT_DIR
        self.NODE_SERVICE_DB = config.NODE_SERVICE_DB
        self.NODE_DB = config.NODE_DB
        self.LOGS = config.LOGS
        print('NODE_DB, NODE_SERVICE_DB', self.NODE_DB, self.NODE_SERVICE_DB)
        self.createNodeDbIfNotExist()
        self.SERVICE_DB = sqlite3.connect(self.NODE_SERVICE_DB, isolation_level=None, check_same_thread=False)
        self.createTablesIfNotExist()


    def createTablesIfNotExist(self):
        ddl_v1_pending_msg = '''
                                           CREATE TABLE  if not exists  v1_pending_msg (
                                           'signed_msg_hash' TEXT NOT NULL,
                                           'signed_msg'	BLOB NOT NULL,
                                           'pub_key'	BLOB NOT NULL,
                                           'node_verified'	INTEGER DEFAULT 0,
                                           'node_date'	timestamp default current_timestamp,
                                            PRIMARY KEY(signed_msg_hash)
                                       );
                                       '''
        ddl_v1_pending_blk = '''
                                  CREATE TABLE  if not exists  v1_pending_blk (
                                  'ver_num'	TEXT NOT NULL,
                                  'msg_type'	TEXT NOT NULL,
                                  'block_num'	TEXT NOT NULL,
                                  'msg_list'	TEXT NOT NULL,
                                  'master_pub_key'	BLOB NOT NULL,
                                  'msg_hash'   TEXT NOT NULL,
                                  'from_addr'	TEXT NOT NULL,
                                  'node_verified'	INTEGER DEFAULT 0,
                                  'node_date'	timestamp default current_timestamp,
                                   PRIMARY KEY(msg_hash)
                              );
                              '''

        ddl_v1_pending_tx = '''
                           CREATE TABLE  if not exists  v1_pending_tx (
                           'ver_num'	TEXT NOT NULL,
                           'msg_type'	TEXT NOT NULL,
                           'input_txs'	TEXT NOT NULL,
                           'to_addrs'	TEXT NOT NULL,
                           'asset_type'	TEXT NOT NULL,
                           'amounts'	TEXT NOT NULL,                                         
                           'pub_keys'	BLOB NOT NULL,
                           'msg_hash'   TEXT NOT NULL,
                           'from_addr'	TEXT NOT NULL,
                           'node_verified'	INTEGER DEFAULT 0,
                           'node_date'	timestamp default current_timestamp,
                            PRIMARY KEY(msg_hash)
                       );
                       '''


        ddl_list = [ddl_v1_pending_msg, ddl_v1_pending_blk, ddl_v1_pending_tx]
        con = self.SERVICE_DB
        try:
            with con:
                #cur = con.cursor()
                for ddl in ddl_list:
                    con.execute(ddl)
                con.commit()
        except Exception as ex:
            #logger = Logger('ServiceDb')
            err_msg = 'Exception ServiceDb.createTablesIfNotExist SqlLite NODE_SERVICE_DB: %s, %s' % (Logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            raise Exception(err_msg)



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


    def insertServiceDB(self, sql, *params):
        try:
            if self.SERVICE_DB is None:
                self.SERVICE_DB = sqlite3.connect(self.NODE_SERVICE_DB, isolation_level=None, check_same_thread=False) #TODO ConfigMap

            con = self.SERVICE_DB
            with con:
                #cur = con.cursor()
                con.execute(sql, params[0]) #ServiceDb().SERVICE_DB.execute(sql, params) #tools.SERVICE_DB.insertServiceDBpendingTX(sql, params[0])
                con.commit()
                return True
        except Exception as ex:
            #logger = Logger('ServiceDb')
            err_msg = 'Exception ServiceDb.insertServiceDBpendingTX SqlLite NODE_SERVICE_DB: %s, %s' % (
            Logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            #tools.SERVICE_DB.logger.logp(err_msg, logging.ERROR)
            return False


class Db():
    def __init__(self, db_path):
        #self.logger = Logger() #Logger('Db')
        self.LEVEL_DB = None
        self.DB_PATH = db_path

    def insertDbKey(self, bin_key, bin_value, db_path, override=False):
        # print('Insert to DB %s with Closed connection %s, key: %s, value: %s ' % (db_path, DB is None, bin_key, bin_value))
        try:
            if db_path is None:
                db_path = tools.DB.DB_PATH
            if not isinstance(bin_key, bytes):
                bin_key = tools.b(bin_key)
            if not isinstance(bin_value, bytes):
                bin_value = tools.b(bin_value)
            if self.DB.LEVEL_DB is None:
                self.DB.LEVEL_DB = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(db_path) #self.DB.DB_PATH
            if self.getDbKey(bin_key, db_path) is None or override:
                self.DB.LEVEL_DB.put(bin_key, bin_value) #Put is not plyvel
                print("Inserting Key/Value: %s/%s" % (bin_key, bin_value))
                return True
            else:
                print('ERROR: Key %s Exist in DB' % bin_key)
                return False
        except Exception as ex:
            err_msg = 'Exception on insert (key %s) (value %s) to LevelDB NODE_DB: %s %s ' % (
            bin_key, bin_value, Logger.exc_info(), ex)
            #tools.logger.logp(err_msg, logging.ERROR)
            print('ERROR:', err_msg)
            return None


    def insertDbKeys(self, kv_dict, db_path, override=False):
        try:
            if self.DB.LEVEL_DB is None:
                self.DB.LEVEL_DB = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(db_path) #self.DB.DB_PATH
            with db.write_batch() as wb:
                for k, v in kv_dict.items():
                    wb.put(k, v)
            return True
        except Exception as ex:
            err_msg = 'Exception on insert (key %s) (value %s) to LevelDB NODE_DB: %s %s ' % (
            bin_key, bin_value, Logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            return None



    def getDbKey(self, bin_key, db_path):
        if type(bin_key) is not bytes:
            bin_key = str(bin_key).encode() #self.b(bin_key)
        try:
            _db = None
            if type(self) is Tools: #db_path is None:
                _db_path = self.DB.DB_PATH
                _db = self.DB.LEVEL_DB
            else:
                _db_path = db_path
                _db = self.LEVEL_DB
            if _db is None:
                _db = plyvel.DB(db_path) #leveldb.LevelDB(_db_path)
            return bytes(_db.get(bin_key)) #bytes(_db.Get(bin_key))
        except Exception as ex:
            return None



    def deleteDbKey(self, bin_key, db_path):
        try:
            if self.DB.LEVEL_DB is None:
                self.DB.LEVEL_DB = plyvel.DB(db_path) #leveldb.LevelDB(db_path)
                self.DB.LEVEL_DB.delete(bin_key) #Delete(bin_key)
        except Exception as ex:
            err_msg = 'Exception on delete (key %s) from LevelDB NODE_DB: %s %s ' % (
            bin_key, exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)


    def isDBvalue(self, bin_key, db_path=None, dbm='db'):
        try:
            if not isinstance(bin_key, bytes):
                bin_key = tools.b(bin_key)
            if db_path is None:
                _db_path = self.DB.DB_PATH
                dbm = self.DB.LEVEL_DB
            else:
                _db_path = db_path
                dbm = self.LEVEL_DB
            if dbm is None:
                dbm = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(_db_path)  # Once init held by the process
            value = dbm.get(bin_key) #dbm.Get(bin_key)
            # print('isDBvalue key=%s, \nvalue=%s' % (bin_key, value)
            return True
        except Exception as ex:
            return False


    def getDbRec(self, msg_hash, db_path = None):
        if db_path is None:
            _db_path = self.DB.DB_PATH
        else:
            _db_path = db_path
        try:
            value = self.getDbKey(msg_hash, _db_path) # self.DB.DB_PATH
            if value is not None:
                return value #self.decodeMsg(unpackb(unpackb(value)[0]))
            else:
                return None
        except Exception as ex:
            return None


    # def decodeDbMsg(self, bin_msg):
    #     try:
    #         return self.decodeMsg(unpackb(unpackb(bin_msg)[0]))
    #     except:
    #         return None
    #
    #
    # #tools methods
    # def insertDbTx(self, bin_signed_msg, override=False):
    #     tx_hash = self.Crypto.to_HMAC(packb(bin_signed_msg))
    #     tx_bytes = packb(bin_signed_msg)
    #     valid_msg =  self.validateMsg(tx_bytes)
    #     if valid_msg:
    #         return self.insertDbKey(tools.b(tx_hash), tx_bytes, tools.NODE_DB, override)




class Node():

    def __init__(self):
        #from queue import Queue
        #import celery
        #self.logger = Logger() #('Node')
        self.PORT_REP = 7777  # Receiving data from the world TXs, queries ...etc
        self.PORT_UDP = 8888  # Submitting/Requesting data from the miners
        self.PORT_PUB = 9999  # Publish to Miners fanout
        self.PORT_PUB_SERVER = 5555   # Optional fanout
        self.PORT_SUB_CLIENT = 6666   # Optional subscribe
        self.WORKERS = 3
        self.Q = Queue()
        self.init_servers()
        #self.logger.logp('Node Started', logging.INFO)
        #Tools.logger.logp('Node Started', logging.INFO)


    def killByPort(self, ports):
        lines = subprocess.check_output(["netstat", "-ano"], universal_newlines=True) #"-ano" "-ltnp"
        rows = []
        pids = []
        for port in ports:
            for line in lines.splitlines()[4:]:
                # print (line)
                c = line.split()
                if port not in c: #[1]:
                    continue
                rows.append(line)
                print("%s port is open " % port)
                col = {}
                col['proto'] = c[0]
                col['localaddress'] = c[1]
                col['foreignaddress'] = c[2]
                col['state'] = c[3]
                col['pid'] = c[4]
                if int(col['pid']) > 0:
                    pids.append(col['pid'])
                    print("Trying to kill port:%s pid:%s " % (port, col['pid']))
            if (os.name.lower() == 'nt' and len(pids) > 0):
                os.popen("taskkill /F /PID " + " ".join(pids))
            if (os.name.lower() != 'nt' and len(pids) > 0):
                os.popen("kill -9 " + " ".join(pids))
        else:
            print("Ports: ", ports, " are free")


    def restartServer(self, type): #kill process and restart the server
        pass


    def init_server(self, type):
        # import time, socket, zmq, asyncio
        # from time import sleep
        # import threading #TODO scheduled Q
        # from multiprocessing import Process #ToDo killPorts+watchdog
        # from msgpack import packb, unpackb

        if type is 'rep':
            context = zmq.Context()
            rep_socket = context.socket(zmq.REP)
            rep_socket.bind("tcp://*:%s" % self.PORT_REP)
            print('Starting REP server tcp://localhost:%s' % self.PORT_REP, flush=True)
            while True:
                rep_msg = rep_socket.recv(1024)
                # self.Q.put_nowait(rep_msg)
                # rep_socket.send(b'OK:') #(rep_msg)

                print('ZMQ REP request: {} bytes \n {}'.format(len(rep_msg), unpackb(rep_msg))) #TODO to continue msg&tx validation

                error = ""
                #print(tx_hash, ' Key Exist in DB ', tools.isDBvalue(tools.b(tx_hash), tools.NODE_DB))
                validated_msg = tools.validateMsg(rep_msg)
                if not validated_msg or validated_msg is None:
                    print('Error: Msg Validation failed')
                    rep_socket.send(b'Error: Msg Validation failed')
                msgType = validated_msg[1]
                if isinstance(validated_msg[1], bytes):
                    msgType = unpackb(validated_msg[1])
               # print('validated_msg_TYPE: ', tools.MsgType.getMsgType(msgType))
                #TODO to continue
                if validated_msg[1] == tools.MsgType.BLOCK_MSG:
                    print('OK: Msg is Valid')
                    rep_socket.send(b'OK: Msg is Valid')

                msg_hash = tools.Crypto.to_HMAC(rep_msg)
                msg_in_db = tools.DB.getDbRec(msg_hash, tools.DB.DB_PATH)
                msg_in_sdb = tools.getServiceDbTx(msg_hash)
                if not msg_in_sdb and validated_msg and msg_in_db is None: #TODO reject if ipaddr > 1 or from_addr within the same block
                    umsg = unpackb(rep_msg)
                    from_addr = tools.Crypto.to_HMAC(umsg[1])
                    values = [v if isinstance(v, str) else '[' + ",".join([l for l in v]) + ']' for v in validated_msg]
                    values += [sqlite3.Binary(umsg[1]), msg_hash, from_addr, 0, tools.utc()]
                    #ServiceDb().getServiceDB().
                    insert = tools.SERVICE_DB.insertServiceDB(
                        "insert into v1_pending_tx (ver_num, msg_type, input_txs, to_addrs, "
                        "asset_type, amounts, pub_keys, msg_hash, from_addr, "
                        "node_verified, node_date) values (?,?,?,?,?,?,?,?,?,?,?) ",
                        values)

                    # tools.SERVICE_DB.insertServiceDBpendingTX(
                    #     "insert into v1_pending_tx (ver_num, msg_type, input_txs, to_addrs, asset_type, amounts, pub_keys, msg_hash, from_addr, node_verified, node_date) values (?,?,?,?,?,?,?,?,?,?,?,?,?) ",
                    #     values)
                    # #07-11-2018 08:17:27.818358 Exception ServiceDb.insertServiceDBpendingTX SqlLite NODE_SERVICE_DB: v1_0.py 630, UNIQUE constraint failed: v1_pending_tx.msg_hash

#smsg = tools.SERVICE_DB.queryServiceDB("select * from v1_pending_tx")[0]
                    # restored_msg = ()
                    # for f in smsg[:-4]:
                    #     if isinstance(f, str) and '[' not in f:
                    #         restored_msg += (f,)
                    #     else:
                    #         restored_msg += ([str(v) for v in f],)
                    # restored_msg
#TODO to continue restored_msg[0] == validated_msg, packb(restored_msg) == rep_msg

                    #TODO Q
                    self.Q.put_nowait(rep_msg) if insert else None
                    #print('rep_msg[0:-2] HMAC: ', tools.Crypto.to_HMAC(tools.Crypto.verify([0], msg[2])))
                    msg_hash = tools.Crypto.to_HMAC(rep_msg) #tools.Crypto.to_HMAC(unpackb(rep_msg)[0]) #tools.Crypto.to_HMAC(packb(umsg[0])) #tools.Crypto.to_HMAC(rep_msg)#tools.Crypto.to_HMAC(packb(umsg))
                    print('msg hash: ', msg_hash)
                    if tools.isDBvalue(msg_hash, tools.NODE_DB):
                        rep_socket.send(b'Error: Msg Exist')
                    else: #TODO after persist + in Verify
                        #TODO ? tools.verifyMsgSig(SignedMessage(umsg[0]), VerifyKey(umsg[2]))
                        #print('signed_msg after  req', umsg[0])
                        #print('signed_msg req: ', unpackb(umsg[0])) #TODO ToFIX SignedMsg
                        ##verified_sig, signed_msg = tools.verifyMsgSig(umsg[0], umsg[2])
                        ##if verified_sig:
                        ##    rep_socket.send(b'OK: SigVerified')
                        ##else:
                        ##    rep_socket.send(b'Error: Invalid Sig')
                        rep_socket.send(b'OK: Msg is Valid')
                else:
                    error = "Msg Exist" if msg_in_db is not None else "Invalid Msg"
                    rep_socket.send(b'Error: ' + error.encode())

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
        # from time import sleep
        # import threading

        ports = [self.PORT_REP, self.PORT_UDP, self.PORT_PUB, self.PORT_PUB_SERVER]
        self.killByPort(ports)


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
    def __init__(self, version='1', sig_type='1/1', multi_sig_pubkeys=[], assets=[], msgs=[], contracts=[]):
        self.data = {}
        self.data['version'] = version  #pub_keys for multiSig, for 1sig is not required
        self.data['sig_type'] = sig_type
        self.data['multi_sig_pubkeys'] = multi_sig_pubkeys
        self.data['wallet_id'] = None #hash(pub_key._key)
        self.data['asset_msgs'] = {'asset_id': None, 'inputs': [], 'outputs': []}
        self.data['assets'] = assets #TODO create asset /later assets FX,Popular, ...etc
        self.data['msgs'] = msgs
        self.data['contracts'] = contracts

        self.WLT_DATA_FIELDS = {'ver_num': str, 'sig_type': str, 'multi_sig_pubkeys': list, \
                                'wallet_id': str, 'assets': list, 'msgs': list, \
                                'contracts': list}
            #{'ver_num': str, 'inputs': list, 'outputs': list, 'pub_keys': list}

        self.WLT_DATA_FIELDS_INDEX = {0: 'ver_num', 1: 'sig_type', 3: 'multi_sig_pubkeys', \
                                      4: 'wallet_id', 5: 'assets', 6: 'msgs', 7: 'contracts'}
            #{0: 'ver_num', 1: 'inputs', 2: 'outputs', 3: 'pub_keys'}

        #vernum,pubk - insecure, hence walletId k= pubks(hashId)?
        #sig  addrs ?
        #wallet_struct = {'vernum': b'1', sig_accept: '1/1', 'sig_addrs': [b'x' * 32] , 'assets': {'inputs': [], 'outputs: []'}, 'messages': [], 'contracts': []}

        #self.INPUTS = 'inputs'
        #self.OUTPUTS = 'outputs'
        #self.ASSSETS = 'ASSETS' #recalc onLoad, onUpdate

    # TODO 4multisi, 4 1sig it's 1/1 + wallet generated from TX with fee deduction
    # TODo 4multisig wallets TX doesnt create wallet,
    #  but creationWithExistingPKaddrs required + WalletID_Hash = ALL_PKs_Hash
    # def createWallet(self, msg) #, pub_keys, sig_accept_num):
    #     cmd = b"cW" #todo globals
    #     #if verifyMsg keyLen and len > 1
    #     pks = pub_keys if isinstance()
    #     pass


    def getWalletchecksum(self):
        pass #used for updates

    def isPrevDataExist(self):
        pass  # used


    def createWallet(self, pubkey_hash_id):
        if not tools.isDBvalue(pubkey_hash_id):
            tools.insertDbKey(pubkey_hash_id, {'ver_num': tools.version, 'assets': \
                {tools.config.MAIN_COIN: {'inputs': [], 'outputs': []}}}, \
                 tools.DB.DB_PATH) #todo change '1' to meaningful coin name
            return True
        return False


    def updateWallet(self, update_type, update_data):
        pass

    def insertDataToWallet(self, decoded_msg, msg_hash):
        if decoded_msg[1] == tools.MsgType.PARENT_TX_MSG:
            self.insertTxToWallet(decoded_msg)
        else:
            pass


    def insertTxToWallet(self, pub_addr, decoded_tx):
        if tools.isDBvalue(tx_hash) is not None or tools.isDBvalue(pub_addr) is None:
            return False
        try:
            wallet = self.getDbWallet(pub_addr)
            assets = [{x: wallet[self.ASSSETS][x]} for x in wallet[self.ASSSETS].keys()]
            tx_amount = [a for a in tx['amounts']]
            if tx['asset_type'] not in tx[self.ASSSETS].keys():
                pass #TODO to continue
                #'{0:.8g}'.format(sum(Decimal(x) for x in d.values()))  '3.9125000'
                # '{0:.8g}'.format(sum(d.values())) # '3.9125'

            wallet[self.INPUTS] += tx[self.INPUTS]
            wallet[self.OUTPUTS] += tx[self.OUTPUTS]
            return True
        except Exception as ex:
            return False

    def getDbWallet(self, pub_addr):
        wallet = tools.getDbRec(pub_addr)
        if wallet is None:
            return self #{self.INPUTS: [], self.OUTPUTS: [], self.ASSSETS: {}}
        else:
            return unpackb(wallet)

    def getWalletUnspentAsset(self, asset_type):
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

class Tools(Structure, Config, State, Node, Crypto, Network, Db, ServiceDb, Transaction, Block, Contract, Wallet, Ico, Agent, Exchange, Shop, Invoke):
    #import msgpack as mp
    def __init__(self):
        self.version = Structure().version #TODO toolkit(tools(ver_num)
        self.config = Config()
        #self.Helper = Helper()
        #self.logger = Logger()
        self.ROOT_DIR = self.config.ROOT_DIR
        self.NODE_DB = self.config.NODE_DB
        self.NODE_SERVICE_DB = self.config.NODE_SERVICE_DB
        self.DB = Db(self.NODE_DB)
        self.SERVICE_DB = ServiceDb()
        self.MsgType = Types()
        self.Transaction = Transaction()
        self.Crypto = Crypto()
        self.Network = Network()
        self.Node = Node()
        self.Block = Block()

    def utc(self):
        return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')

    def b(self, str):
        try:
            return bytes(str, 'utf8')
        except:
            return None

    def s(self, o):
        try:
            return str(o, 'utf8')
        except:
            return None

    def dec(self, b):
        try:
            try:
                v = b.decode() #is str
            except:
                #TODO to continue
                return self.bdecimal2str(b) #DoublePacked number

            return v
        except:
            return b


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


    def isStrNumber(self, str):
        try:
            Decimal(str)
            return True
        except:
            return False


    def strdecimal2bytes(self, str_decimal):
        if not isinstance(str_decimal, str):
            return None
        if len(str_decimal) > 21: # ToDo fromConfig->updateHome -> n9.n8 100m MaxTx(9)-??? 4now 100b(12)
            return None
        if "." in str_decimal:
            nums = str_decimal.split(".")
            int_num = nums[0]
            float_num = nums[1]
            if not self.isStrNumber(int_num) or not self.isStrNumber(float_num):
                return None
            if len(int_num) > 9 or len(float_num) > 8: #ToDo config = 4b.4b
                return None
            return int(int_num).to_bytes(4, byteorder='big') + int(float_num).to_bytes(4, byteorder='big')
        else:
            int_num = str_decimal
            if not self.isStrNumber(int_num):
                return None
            if len(int_num) > 9:  # ToDo config = 4b
                return None
            return int(int_num).to_bytes(4, byteorder='big')


    def bdecimal2str(self, b_decimal):
        if not isinstance(b_decimal, bytes):
            return None
        else:
            if len(b_decimal) > 4: # is float
                int_num = str(int.from_bytes(b_decimal[:4], 'big'))
                float_num = str(int.from_bytes(b_decimal[4:], 'big'))
                if int_num is None or not self.isStrNumber(int_num) or not self.isStrNumber(float_num):
                    return None
                if float_num is not None:
                    return str(Decimal(int_num + '.' + float_num))
                else:
                    return str(Decimal(int_num)) #point . exist without an exp
            else:
                int_num = str(int.from_bytes(b_decimal[:4], 'big')) # is int
                if not self.isStrNumber(int_num):
                    return None
                if len(int_num) > 9:  # ToDo config = 4b
                    return None
                return str(Decimal(int_num))



    @staticmethod
    def p(s):
        print(s)

    def pp(self, s):
        print(s)



if __name__ == "__main__":
    #TODO sync time ->
    # sudo timedatectl set-ntp on;sudo timedatectl set-timezone America/New_York;
    # timedatectl; assert == both Network time on: and NTP synchronized: should read yes

    test = Test()
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    test.deleteDir(os.path.join(ROOT_DIR, '../db'))
    test.deleteDir(os.path.join(ROOT_DIR, '../service_db'))
    test.deleteDir(os.path.join(ROOT_DIR, '../logs'))


    Tools.p("v1.Tools running as a stand-alone script -> DB,Logs folders created")
    tools = Tools()
    print('Tools version %s' % tools.version)


    SK, VK = tools.getKeysFromSeed('Bob')
    msg = b'msg'
    msg2 = b'msg2'
    signed_msg = tools.signMsg(msg, SK)
    signed_msg2 = tools.signMsg(msg2, SK)
    assert signed_msg._signature != signed_msg2._signature
    print('msg 1,2 sigs', signed_msg._signature, signed_msg2._signature)
    verified_sig = tools.verifyMsgSig(signed_msg, VK)
    pub_addr = tools.getPubAddr(VK)
    print("msg verified %s for publicKey: %s" % (verified_sig, pub_addr))  # VK == VerifyKey(VK._key)
    test.persistKeysInServiceDB(SK._signing_key, SK.verify_key._key, SK._seed, pub_addr, 'Bob')
    SK2, VK2 = tools.getKeysFromSeed('Alice')
    pub_addr2 = tools.getPubAddr(VK2)
    test.persistKeysInServiceDB(SK2._signing_key, SK2.verify_key._key, SK2._seed, pub_addr2, 'Alice')
    query = "select * from v1_test_accounts where pub_addr='%s'" % pub_addr
    rec = tools.SERVICE_DB.queryServiceDB(query)
    # genesis_tx = ('1', MSG_TYPE_SPEND_TX, ['%s,%s' % (genesis_sig['r'], genesis_sig['s'])], '1/1', ['%s,%s' % (genesis_pub_key['x'], genesis_pub_key['y'])], ['TX-GENESIS'], ['TX_GENESIS'], 'GENESIS', genesis_to_addr, '1', 10000000000.12345, merkle_date)
    ##tx = tools.Transaction.setTX('1', 'PTX', ['TX_GENESIS'], [tools.to_HMAC(tools.b('TX_GENESIS_%s' % pub_addr))], 'Genesis', [pub_addr], '1', [1000.1234], '2018-01-01 00:00:00.000000', '1/1', signed_msg._signature, VK._key)
    unspent_input_genesis_tx = tools.MsgType.UNSPENT_TX + 'GENESIS'.ljust(32)
    unspent_output_genesis_tx = tools.MsgType.UNSPENT_TX + 'GENESIS'.ljust(32)
                                #tools.to_HMAC(tools.b('%s_%s' %  (unspent_input_genesis_tx, pub_addr)))
    # tx = tools.Transaction.setTX('1', tools.MsgType.PARENT_TX_MSG, [unspent_input_genesis_tx], [unspent_output_genesis_tx],
    #                              [pub_addr], '1', [10000000000000.1234567890], '98/99', signed_msg._signature, VK._key) #100000000000.123 #ToDo 4567890 248b 245b
    #TODO test limits of float and MAX_FIELD_SIZES
    bf = tools.strdecimal2bytes('999999999.12345678')
    sf = tools.bdecimal2str(bf)
    tx = tools.Transaction.setTX('1', tools.MsgType.PARENT_TX_MSG, [unspent_input_genesis_tx],
                                 [pub_addr], '1', [b'999999999.12345678'],
                                 VK._key) #10000000000000.12345678
    #tools.str2floatb('999999999.12345678')

    signed_msg = tools.signMsg(packb(tx[:-1]), SK)
    print('G TX hash' , tools.to_HMAC(signed_msg.message))
    print('signed_G msg before req', signed_msg)
    verified, verified_msg = tools.verifyMsgSig(signed_msg, VK._key) #tools.verify(signed_msg, VerifyKey(bin_signed_msg[-1]))
    assert verified
    assert VerifyKey(rec[0][1]) == VK
    bin_signed_msg = (signed_msg.message, VK._key)
    tx_bytes = packb(bin_signed_msg)
    res_valid = tools.sendMsgZmqReq(tx_bytes, 'localhost', tools.Node.PORT_REP)
    print('genesis tx resp: ', res_valid)
    assert res_valid

    ###########
    multi_recv = []
    multi_amounts = []
    for i in range(1, 5):
        receiver_seed = 'Alice%s' % i
        priv_k, pub_k = tools.getKeysFromSeed(receiver_seed)
        receiver_pub_addr = tools.getPubAddr(pub_k)
        multi_recv.append(receiver_pub_addr)
        multi_amounts.append(b'1')
    unsigned_tx_multi = '1', tools.MsgType.PARENT_TX_MSG, [
        unspent_input_genesis_tx], multi_recv, '1', multi_amounts,
    signed_multi_tx = tools.signMsg(packb(unsigned_tx_multi), SK)
    signed_multi_tx_vk = (signed_multi_tx.message, VK._key)
    # tx_multi = tools.Transaction.setTX(unsigned_tx_multi, signed_tx_multi._signature, VK._key)  # 10000000000000.12345678
    verified_multi_tx_sig = tools.verifyMsgSig(signed_multi_tx, VK) #Bob
    assert verified_multi_tx_sig[0]
    print('tx_multi VK: ', VK._key)
    print('tx_multi signed_tx_multi.message: ', signed_multi_tx.message)
    ##tx_hash_multi = tools.Crypto.to_HMAC(packb(bin_signed_multi))
    signed_multi_tx_vk_bytes = packb(signed_multi_tx_vk)
    signed_multi_tx_vk_bytes_hash = tools.to_HMAC(signed_multi_tx_vk_bytes)
    res_valid = tools.sendMsgZmqReq(signed_multi_tx_vk_bytes, 'localhost', tools.Node.PORT_REP)
    print('multi tx resp: ', res_valid)
    assert res_valid
    ##############################
    bsk, bvk = tools.getKeysFromSeed('Miner1')
    tx_arr_bin = [bin_signed_msg, signed_multi_tx_vk]
    tx_hash_arr = [signed_multi_tx_vk_bytes_hash]
    block_msg = '1', tools.MsgType.BLOCK_MSG, tx_hash_arr
    block_signed_msg = tools.signMsg(packb(block_msg), bsk)
    block_signed_msg_vk = (block_signed_msg.message, bvk._key) #TODO vk is last 32bit
    vres, dmsg = tools.verifyMsgSig(block_signed_msg, bvk) #bvk.verify(block_signed_msg)
    assert vres #TODO persistBlock(priority=100) serviceDB
    print('Block Sig is Valid')

    res_valid = tools.Transaction.sendMsg(packb(block_signed_msg_vk), "localhost", tools.Node.PORT_REP)
    print('block tx resp: ', res_valid)

#    if res_valid and dmsg is not None:
#        for msg in block_msg[2]:#todo txs_fields_index
#            in_sdb = tools.getServiceDbTx(msg)
#            in_db = tools.getDbRec(msg, tools.DB.DB_PATH)

           # msg_pk = msg[0], msg[1]
           # print('Msg Validated', tools.validateMsg(packb(msg_pk)))
    # verified = tools.verifyBlock(block_msg)


    tools.insertGenesis(packb(block_signed_msg_vk))
    exit(0)


    ##########################################


    tx_hash = tools.Crypto.to_HMAC(packb(bin_signed_msg)) #tools.s(tx[1]) +
    tx_bytes = packb(bin_signed_msg)
    ##tools.validateMsg(tx_bytes) #Test
    ##tools.insertDbKey(tools.b(tx_hash), tx_bytes, tools.NODE_DB) #GENESIS
    tools.insertDbTx(bin_signed_msg)

    ##print(tools.getDB(tools.b(tx_hash), tools.NODE_DB))
    ##print('LevelDB tx_hash: %s value: \n' % tx_hash, tools.decodeMsg(unpackb(unpackb(tools.getDbKey(tx_hash, tools.NODE_DB))[0])))
    print('LevelDB tx_hash: %s value: \n' % tx_hash, tools.getDbRec(tx_hash))
    #tools.sendTX()

    #Test
    # start = time.time()
    # print('Start: ', tools.utc())
    # for i in range(10000):
    #     tools.sendMsgZmqReq(tx_bytes, 'localhost', tools.Node.PORT_REP)
    # print('End  : ', tools.utc(), 'Duration: ', time.time() - start, 'secs')

    #tools.sendMsgZmqReq(tx_bytes, 'localhost', tools.Node.PORT_REP)

    # tools.Transaction.sendTX('1', tools.MsgType.PARENT_TX_MSG, [unspent_input_genesis_tx],
    #                              [pub_addr], '1', [b'999999999.12345678'], '98/99', "Bob", "localhost", tools.Node.PORT_REP)

    # tools.Transaction.sendTX('1', tools.MsgType.PARENT_TX_MSG, [unspent_input_genesis_tx],
    #                          ['INVALID_ADDR'], '1', [b'999999999.12345678'], '98/99', "Bob", "localhost", tools.Node.PORT_REP)

    tx2 = ('1', tools.MsgType.PARENT_TX_MSG, [unspent_input_genesis_tx],
           [pub_addr, pub_addr], '1', [b'1.12345678', b'2.123'], '1/1', "Bob",
           "localhost", tools.Node.PORT_REP)
    bin_signed_msg2 = tools.Transaction.sendTX('1', tools.MsgType.PARENT_TX_MSG, [unspent_input_genesis_tx],
                      [pub_addr, pub_addr], '1', [b'1.12345678', b'2.123'], '1/1', "Bob",
                      "localhost", tools.Node.PORT_REP)
    tx_hash2 = tools.Crypto.to_HMAC(packb(bin_signed_msg2))
    print('tx_hash2', tx_hash2)
    bin_signed_msg3 = tools.Transaction.submitTX(tx2, "Bob", "localhost", tools.Node.PORT_REP)
    assert bin_signed_msg2 == bin_signed_msg3
    ##tools.insertDbKey(tools.b(tx_hash2), packb(bin_signed_msg2), tools.NODE_DB)  # TODO to remove ->INvalid
    tools.insertDbTx(bin_signed_msg2) # TODO to remove ->INvalid
    bmsg = tools.getDbRec(tx_hash2)
    #bmsg2 = tools.getDbMsg(tx_hash2) #ServiceDB notDB
    assert tools.Crypto.to_HMAC(bmsg) == tx_hash2
    #assert tools.Crypto.to_HMAC(bmsg) == '*' + tx_hash2
    #assert tools.Crypto.to_HMAC(bmsg2) == tx_hash2

    btx = tools.decodeDbMsg(bmsg)
    stx = tools.SERVICE_DB.queryServiceDB("select * from v1_pending_tx where msg_hash='%s'" % tx_hash2)[0] #not exist in DB
    stx2 = tools.getServiceDbTx(tx_hash2) #[0]
    print(type(stx), type(stx2))
    print(stx2)
    #assert type(stx) == type(stx2)
    assert stx == stx2

    #assert btx == stx[:-6] ##TODO repack of Amounts field ->repack parts with BigEndian
    list_fields_names = [k for k in tools.Transaction.TX_MSG_FIELDS
                         if tools.Transaction.TX_MSG_FIELDS[k] is list]
    list_field_indexes = [k for (k, v) in tools.Transaction.TX_MSG_FIELDS_INDEX.items() if
                          v in list_fields_names and v in tools.Transaction.TX_MSG_FIELDS_INDEX.values()]
    amounts_field_index = list(tools.Transaction.TX_MSG_FIELDS_INDEX.values()).index('amounts')
    list_amounts = (stx[amounts_field_index][1:-1].split(","))
    decimal_list_amounts = [Decimal(x) for x in list_amounts]
    total_outputs_amount = format(sum(decimal_list_amounts), '.8f')
    list_stx = list(stx)
    for i in list_field_indexes:
        list_stx[i] = list_stx[i][1:-1].split(",")
    #assert tuple(list_stx[:-6]) == btx #still not in DB
    tx_fields_len = len(tools.Transaction.TX_MSG_FIELDS_INDEX.keys())

    sdb_tx = tuple(list_stx[:tx_fields_len])
    db_tx = btx
    db_tx += (unpackb(bmsg)[1],)
    db_tx += (unpackb(bmsg)[2],)
    assert sdb_tx == db_tx
    assert packb((packb(sdb_tx[:-2]), sdb_tx[-2], sdb_tx[-1])) == bmsg
    assert tools.Crypto.to_HMAC(packb((packb(sdb_tx[:-2]), sdb_tx[-2], sdb_tx[-1]))) == tx_hash2

    bmsg2, bmsg2hash = tools.sdbtx2btx(tx_hash2)
    assert bmsg2hash == tx_hash2
    print('stx2 amount (asset_type, str_total_outputs_amount):', tools.getTxAmount(stx2))
    btx3, btx3hash = tools.dbtx2stx(tx_hash2)
    assert btx3hash == tx_hash2

    #TODO asset_type should be persisted with GenesisBlock - > createAsset(tx, fees...)

   # tools.sendMsgZmqReq(tx_bytes, 'localhost', tools.Node.PORT_REP)
   # tools.logp('Finished', logging.INFO)
#len(bin_signed_msg[0]) #181 == len(str(tx[:-2]).encode()) == TX_MSG 1input/1output/1amount 32+32+8=72 * 10  = +720b
#len(signed_msg.signature) #64 Sig
#len(bin_signed_msg[2]) #32  VK
#181+64+32=277b/Msg ~300b per input ~30kb - 100tx limit #246-287b
    # while True: #Accept connections 4ever
    #     time.sleep(0.001)

#Test
   #block = {blockNum, blockHash, ptxsArr(ptx->BlockNum)}
    receivers = []
    for i in range(1, 101):
        receiver_seed = 'Alice%s' % i
        SK, VK = tools.getKeysFromSeed(receiver_seed)
        priv_k, pub_k = tools.getKeysFromSeed(receiver_seed)
        receiver_pub_addr = tools.getPubAddr(pub_k)
        receivers.append(receiver_pub_addr)

#     ptxArr = []
#     dbTxArr = []
#     for i in range(1, 10):
#         sender_seed = 'Bob' #%s' % i #constructs priv and pub keys ->can be copied/constructed from the external devices
#         receiver_seed = 'Alice%s' % i
#         SK, VK = tools.getKeysFromSeed(sender_seed)
#         priv_k, pub_k = tools.getKeysFromSeed(receiver_seed)
#         sender_pub_addr = tools.getPubAddr(VK)
#         receiver_pub_addr = tools.getPubAddr(pub_k)
#         txBob = ('1', tools.MsgType.PARENT_TX_MSG, [unspent_input_genesis_tx],
#                  [receiver_pub_addr, receiver_pub_addr, receiver_pub_addr], '1',
#                  [b'1.12345678', b'2.123', b'3'], '1/1', sender_seed, "localhost", tools.Node.PORT_REP)
#         #tx = (txBob[:7],  signed_msg._signature, VK._key)
#         #tx = tools.Transaction.setTX(txBob[:7],  signed_msg._signature, VK._key)
#         tx = txBob
#         signed_msg = tools.signMsg(packb(tx), SK)
#         bin_signed_msg = (signed_msg.message, signed_msg.signature, VK._key)
#         signed_ptx = bin_signed_msg
#         tx_hash = tools.Crypto.to_HMAC(packb(signed_ptx))
#         tools.insertDbTx(signed_ptx) #TEMP 4TEST todo to disable
#         dbTxArr.append({tools.b(tx_hash): signed_ptx})  #todo IfExist to disable remFromQ & remFromStxDb ifExist
#         print(tx_hash, 'Exist in LevelDb', tools.isDBvalue(tools.b(tx_hash))) #, signed_ptx))
#         print(unpackb(unpackb(tools.getDbKey(tx_hash, tools.DB.DB_PATH))[0]))
#
#    tools.decodeMsg(unpackb(unpackb(tools.getDbKey(tx_hash, tools.DB.DB_PATH))[0])[:-3])
#
#     print("DbPtxsHashes: ", dbTxArr)
#     print(tools.isDBvalue(tools.b(tx_hash2)))
#     print(tools.isDBvalue(tools.b('*'+tx_hash2)))
#     print(unpackb(unpackb(tools.getDbKey(tx_hash2, tools.DB.DB_PATH))[0]))


##############################################################################
#TOdo
# bmsg -> validate(binMsgHash) -> sdb -> taskVerify -> blockWriteDb -> delSdb
# db2wlt, db2tx, db2blk,
# pQWorker(type) -> (['r2db', 'w2db',  'ex'
# # [Verify', 'txValidate, ...
# msg -val(wallet)-savemSdb
# readSdb - verify - publish2master(new) - master-republish-new
# masterPublishBlock - nodeVerify(true|false) - nodeVote(true | false)


#getTxArrFromPtx -> wallets
##############################################################################