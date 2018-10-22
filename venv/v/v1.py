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


class TransactionType:
    UNSPENT_TX = b'\x00'
    SPENT_TX = b'\x01'
    SPEND_TX = b'\x02'
    SPEND_MULTI_SIG_TX = b'\x03'
    MINER_FEE_TX = b'\x04'
    MINER_ISSUE_TX = b'\x05'
    BLOCK_TX = b'\xb0'
    VOTE_TX = b'\xb1'
    CONTRACT_TX = b'\xc0'
    CONTRACT_CONFIRM_TX = b'\xc1'
    REGISTER_TX = b'\xe1'
    EXCHANGE_TX = b'\x88'
    AGENT_TX = b'\xa7'
    INVOKE_TX = b'\xd1'
    RELAY_TX = b'\xd2'
    MSG_TX = b'\xd3'

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



class MsgType:
    SPEND_TX_MSG_FIELDS = (
    'ver_num', 'msg_type', 'sigs', 'sig_type', 'pub_keys', 'input_txs', 'output_txs', 'from_addr', 'to_addrs',
    'asset_type', 'amounts', 'ts', )



class Structure(object):
    def __init__(self):
        self.version = "1"

class Config():
   pass


class Logger():
    def __init__(self):
        self.Logger = Logger()


    def utc(self):
        return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')


    def exc_info(self):
        exc_type, exc_value, exc_tb = sys.exc_info()
        return '%s %s' % (os.path.basename(exc_tb.tb_frame.f_code.co_filename), exc_tb.tb_lineno)


    def getLogger(self, logFile='node'):
        #global LOGGER
        if self.LOGGER is None:
            log_file = "logs/%s.log" % logFile
            self.LOGGER = create_rotating_log(log_file, "logger")
        return self.LOGGER


    def logp(msg, mode, console=True):
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
   pass

class Crypto():
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
        except:
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


class Transaction(Logger):
    def __init__(self):
        self.version = "1"
        self.TX_MSG_FIELDS = {'ver_num': str, 'msg_type': str, 'input_txs': list, 'output_txs': list, 'from_addr': str,
                              'to_addrs': list, 'asset_type': str, 'amounts': list, 'ts': datetime,
                              'sig_type': str, 'sigs': bytes, 'pub_keys': bytes}

    def setTX():
        pass

    def validateTX():
        pass

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





class Contract():
    pass

class Ico():
    pass

class Block(Logger):
    pass

    def sendBlock():
        pass

    def voteBlock():
        pass

    def verifyBlock():
        pass

    @staticmethod
    def persistBlock():
        pass


class ServiceDb():
    def getServiceDB(self):
        try:
            if self.SERVICE_DB is None:
                self.SERVICE_DB = sqlite3.connect(Tools().NODE_SERVICE_DB, isolation_level=None) #TODO ConfigMap
            #return SERVICE_DB
        except Exception as ex:
            err_msg = 'Exception on get serviceDbConnection to SqlLite NODE_SERVICE_DB: %s, %s' % (ex, Logger.exc_info())
            Logger.logp(err_msg, logging.ERROR)
            return None

    def queryServiceDB(sql):
        SERVICE_DB = None
        try:
            if SERVICE_DB is None:
                SERVICE_DB = sqlite3.connect(Tools().NODE_SERVICE_DB, isolation_level=None) #TODO ConfigMap
            return SERVICE_DB.execute(sql).fetchall()
        except Exception as ex:
            err_msg = 'Exception on Select (%s) from SqlLite NODE_SERVICE_DB: %s, %s' % (sql, ex, Logger.exc_info())
            Logger.logp(err_msg, logging.ERROR)
            return None


class Db():
    # def __init__(self):
    #     self.SERVICE_DB = None
    pass





class Node():
    pass

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
    def __init__(self):
        self.LOGGER = None
        self.ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
        self.NODE_DB = '%s/db/DATA' % self.ROOT_DIR
        self.NODE_SERVICE_DB = '%s/service_db/DATA/service.db' % self.ROOT_DIR
        self.DB = None
        self.SERVICE_DB = ServiceDb()

    def utc():
        return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')

    def b(str):
        try:
            return bytes(str, 'utf8')
        except:
            return str



    @staticmethod
    def p(s):
        print(s)

    def pp(self, s):
        print(s)







if __name__ == "__main__":
    Tools.p("v1.Tools running as a stand-alone script")
    #print('Tools version %s' % Tools().version)
    tools = Tools()
    SK, VK = tools.getKeysFromSeed('Bob')
    msg = b'msg'
    signed_msg = tools.sign(msg, SK)
    verified_sig = tools.verify(signed_msg, VK)
    pub_addr = tools.getPubAddr(VK)
    print("msg verified %s for publicKey: %s" % (verified_sig, pub_addr))  # VK == VerifyKey(VK._key)
    #persistKeysInServiceDB(SK._signing_key, SK.verify_key._key, SK._seed, pub_addr, 'Bob')
    rec = tools.getServiceDB("select * from v1_test_accounts where pub_addr='%s'" % pub_addr)
    assert VerifyKey(rec[0][1]) == VK