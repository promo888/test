import os, sys, re
import calendar
from datetime import *
from time import *
import logging
from logging.handlers import RotatingFileHandler
import configparser
import psutil, subprocess, re
import datetime, time
# from fastecdsa import curve, ecdsa, keys
# from fastecdsa.keys import export_key, import_key
# from fastecdsa.curve import P256
# from fastecdsa.point import Point
# from Crypto.Hash import SHA256, HMAC, RIPEMD, MD5
# from msgpack import packb, unpackb
# import pandas
# import leveldb
# import sqlite3
# from sqlobject import *
#import v
from v import *

from nacl.bindings import crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES
from nacl.public import Box, PrivateKey, PublicKey
from nacl.bindings.crypto_sign import crypto_sign_open as verify, crypto_sign as sign, \
    crypto_sign_seed_keypair as keys_from_seed
from nacl.signing import SigningKey, VerifyKey


#pip install --proxy http://lab:Welcome1@10.72.0.50:8080 matplotlib
#import msgpack #git clone msgpack && cd mspack && sudo python3 setup.py install /or Project Settings - Project -Project Interpreter - Available Packages - Install
#ps fax | grep python3 | grep -v grep |awk '{print $1}' | xargs -r kill -9


DEBUG = True
NODE_TYPE = "Node" or "Wallet"
PORT_REP_SERVER = 7777   # Receiving data from the world TXs, quiries ...etc
PORT_UDP_SERVER = 8888   # Receiving data from miners
MSG_TYPE_TX_ACCEPTED_AND_VALID = "TXQ"
MSG_TYPE_TX_VERIFIED_AND_PENDING = "TXP"
MSG_TYPE_SPEND_TX = "TX-" #spending TX
MSG_TYPE_UNSPENT_TX = "TX_" #unspent amounts/TX
MSG_TYPE_UNSPENT_SPENT_TX = "-TX" #mark unspent amounts/TX as spent
MSG_TYPE_MULTI_SIG = "MNS"
MSG_TYPE_VOTE = "VOT"
MSG_TYPE_CONTRACT = "CNT"
MSG_TYPE_BLOCK = "BLK"
MSG_TYPE_PENALTY = "PNL"
MSG_TYPE_REQUEST = "REQ"
REQUEST_TYPE_BLOCK = 'RBL'
REQUEST_TYPE_TX = 'RTX' #used to retrieve ALL type of messages by specifying MSG_TYPE param in request
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
NODE_DB = '%s/db/DATA' % ROOT_DIR
NODE_SERVICE_DB = '%s/service_db/DATA/service.db' % ROOT_DIR
#NODE_WALLET_DB = '%s/wallet_db/DATA/wallet.db' % ROOT_DIR


# TXS_DB = '%s/db/TXS' % ROOT_DIR
# UTXS_DB = '%s/db/UTXS' % ROOT_DIR
# VOTES_DB = '%s/db/VOTES' % ROOT_DIR
# BLOCKS_DB = '%s/db/BLOCKS' % ROOT_DIR
# CONTRACTS_DB = '%s/db/CONTRACTS' % ROOT_DIR
# SERVICE_DB = '%s/db/SERVICE' % ROOT_DIR
# PENDING_DB = '%s/db/PENDING' % ROOT_DIR
DB = None
SERVICE_DB = None #TODO disable node activities if not sync (when downloading)
RUNTIME_CONFIG = {'FileConfig': None, 'NodeType': NODE_TYPE, 'NodeId': None, 'NODE_DB': NODE_DB, 'SERVICE_DB': NODE_SERVICE_DB} #, 'PENDING_DB': PENDING_DB, 'TXS_DB': TXS_DB, 'UTXS_DB': UTXS_DB, 'VOTES_DB': VOTES_DB, 'BLOCKS_DB': BLOCKS_DB, 'CONTRACTS_DB': CONTRACTS_DB, 'SERVICE_DB': SERVICE_DB}



def setRuntimeConfig(key, value):
    try:
        RUNTIME_CONFIG[key] = value
    except:
        pass


def setNodeDb(pub_key):
    #RUNTIME_CONFIG['NODE_TYPE'] = getNodeId()
    dirs = [NODE_DB, NODE_SERVICE_DB, 'logs'] #[NODE_DB, TXS_DB, UTXS_DB, VOTES_DB, CONTRACTS_DB, SERVICE_DB, PENDING_DB]
    for folder in dirs:
        if not os.path.exists(folder):
            if folder == NODE_SERVICE_DB:
                folder = folder.replace('/service.db', '')
            os.makedirs(folder)
    initServiceDB(pub_key)
    RUNTIME_CONFIG['PUB_KEY'] = pub_key

def getNodeId():
    return NODE_ID

#TODO remove PUB_KEY ->used 4 testing + move to v1
def initServiceDB(pub_key=''):
    global SERVICE_DB
    sql_list = []
    #Node section
    sql_v1_node_spending_tx = '''
        CREATE TABLE `v1_pending_tx` (
        'id'	INTEGER,
        'ver_num'	TEXT NOT NULL,
        'msg_type'	TEXT NOT NULL,
        'input_txs'	TEXT NOT NULL,
        'output_txs'	TEXT NOT NULL,
        'from_addr'	TEXT NOT NULL,
        'to_addr'	TEXT,
        'asset_type'	TEXT NOT NULL,
        'amounts'	TEXT NOT NULL,
        'ts'	TEXT NOT NULL,
        'node_verified'	INTEGER DEFAULT 0,
        'node_date'	date NOT NULL,
        'tx_hash'	TEXT NOT NULL UNIQUE,
        'sigs'	TEXT NOT NULL,
        'sig_type'	TEXT NOT NULL,
        'pub_keys'	BLOB NOT NULL,
        PRIMARY KEY(tx_hash)
    );
    '''

    # sql_v1_test_accounts = '''CREATE TABLE if not exists v1_test_accounts
    #                            (id INTEGER PRIMARY KEY AUTOINCREMENT,
    #                             priv_key BLOB UNIQUE NOT NULL,
    #                             pub_key BLOB UNIQUE NOT NULL,
    #                             seed BLOB UNIQUE NOT NULL );'''
    sql_v1_test_accounts = '''CREATE TABLE if not exists v1_test_accounts
                                   (                     
                                    priv_key BLOB NOT NULL UNIQUE,
                                    pub_key BLOB NOT NULL UNIQUE,
                                    seed BLOB UNIQUE NOT NULL ,
                                    pub_addr TEXT NOT NULL UNIQUE,
                                    nick TEXT DEFAULT NULL UNIQUE,
                                   PRIMARY KEY(pub_addr) 
                                   );
    '''

    #Wallet section
    sql_wallet_spending_tx = '''CREATE TABLE if not exists spending_tx
                               (id INTEGER PRIMARY KEY AUTOINCREMENT,                       
                                sigs TEXT NOT NULL,
                                sig_type TEXT NOT NULL,
                                pub_keys TEXT NOT NULL,                        
                                ver_num  TEXT  NOT NULL,
                                msg_type TEXT NOT NULL,
                                input_txs TEXT NOT NULL,   
                                output_txs TEXT NOT NULL,
                                from_addr TEXT NOT NULL,                     
                                to_addr  TEXT NULL,
                                asset_type TEXT NOT NULL,
                                amount REAL NOT NULL,
                                ts TEXT NOT NULL,                        
                                tx_hash TEXT NOT NULL
                               );
             '''  #% pub_key

    # tx_type: 0 - Unspent, 1 - Spent ; tx_id = tx_hash + NodeSalt?
    sql_wallet_spent_unspent_txs = '''CREATE TABLE if not exists wallet
                                   (id INTEGER PRIMARY KEY AUTOINCREMENT,    
                                    ver_num  TEXT  NOT NULL,                   
                                    tx_type INTEGER NOT NULL,
                                    tx_hash TEXT NOT NULL,
                                    tx_id DEFAULT NULL,
                                    block_num INTEGER DEFAULT NULL,                        
                                    block_hash TEXT DEFAULT NULL                                   
                                   );
                 '''  #% pub_key
    sql_list.append(sql_v1_node_spending_tx) #ToDo add spent/unspent
    sql_list.append(sql_v1_test_accounts)

    sql_list.append(sql_wallet_spending_tx)
    sql_list.append(sql_wallet_spent_unspent_txs) #ToDo update from response/confirmations ?
    try:
        insertServiceDB(sql_list)
        logp('ServiceDB Init successfull', logging.INFO)
        return SERVICE_DB
    except Exception as ex:
        # err_msg = '%s Exception on init of SqlLite NODE_SERVICE_DB:  %s' % (utc(), ex)
        # LOGGER.error(err_msg)
        #print(err_msg)
        err_msg = 'Exception on Init (%s) of SqlLite NODE_SERVICE_DB: %s, %s' % (sql_list, ex, exc_info())
        logp(err_msg, logging.ERROR)
        return None


def insertServiceDB(sql_list):
    global SERVICE_DB, NODE_SERVICE_DB
    try:
        if SERVICE_DB is None:
            SERVICE_DB = sqlite3.connect(NODE_SERVICE_DB, isolation_level=None)
            #print(dir(SERVICE_DB))
            logp("Connected to ServiceDB", logging.INFO)
        SERVICE_DB.execute("BEGIN TRANSACTION;")
        for query in sql_list:
            #print('query', query)
            SERVICE_DB.execute(query)
        SERVICE_DB.commit()
        return True
    except Exception as ex:
        err_msg = 'Exception on Insert (%s) to SqlLite NODE_SERVICE_DB:  %s, %s' % (sql_list, ex, exc_info())
        # LOGGER.error(err_msg)
        # print(err_msg)
        SERVICE_DB.rollback()
        logp(err_msg, logging.ERROR)
        return None


def insertServiceDbPending(bin_msg_list):
    # global SERVICE_DB, NODE_SERVICE_DB
    # try:
    #     queries_list = ()
    #     keys_list = ()
    #     values_list = ()
    #     if SERVICE_DB is None:
    #         SERVICE_DB = sqlite3.connect(NODE_SERVICE_DB, isolation_level=None)
    #         logp("Connected to ServiceDB", logging.INFO)
    #     SERVICE_DB.execute('BEGIN;')
    #     for msg in bin_msg_list:
    #         version_msg = v(msg, 'msgo', msg)
    #         #print('version_msg', version_msg)
    #
    #         if version_msg is None: #Ommit the message if incorrect version or isNotValid version format
    #             continue
    #         ###TODO validations
    #
    #         ###
    #
    #         query = 'INSERT INTO pending_tx '
    #         keys = ()
    #         values = ()
    #         for k in version_msg.keys():
    #             keys += (k,)
    #             values += (version_msg[k],)
    #         keys += ('node_date',)
    #         dti = utc() #TODO to thinkk change for ts (time.time() ,9bytes instead 27 + clients_ts  = ~40 bytes per record, 16b in LevelDB time.time()
    #         values += (dti,)
    #         #print('kv', keys, values)
    #         query += ' (' + ",".join([k for k in keys]) + ') values (' + ('?,' * len(keys))[:-1] + ")"
    #         #print('query', query, values)
    #         SERVICE_DB.execute(query, [sqlite3.Binary(packb(v)) for v in values])
    #         queries_list += (query,)
    #         keys_list += (keys,)
    #         values_list += (([sqlite3.Binary(packb(v)) for v in values]),)
    #     SERVICE_DB.commit()
    #     return True
    # except Exception as ex:
    #     err_msg = 'Exception on Insert (%s) to SqlLite NODE_SERVICE_DB:  %s, %s' % (bin_msg_list, ex, exc_info())
    #     SERVICE_DB.rollback()
    #     logp(err_msg, logging.ERROR)
    #     return None
    return v_msg_list('insertServiceDbPending', bin_msg_list)

def getServiceDBconnection():
    global SERVICE_DB
    try:
        if SERVICE_DB is None:
            SERVICE_DB = sqlite3.connect(NODE_SERVICE_DB, isolation_level=None)
        return SERVICE_DB
    except Exception as ex:
        err_msg = 'Exception on connect to SqlLite SERVICE_DB: %s, %s' % (ex, exc_info())
        logp(err_msg, logging.ERROR)
        return None


def getServiceDB(sql):
    global SERVICE_DB
    try:
        if SERVICE_DB is None:
            SERVICE_DB = sqlite3.connect(NODE_SERVICE_DB, isolation_level=None)
        return SERVICE_DB.execute(sql).fetchall()
    except Exception as ex:
        err_msg = 'Exception on Select (%s) from SqlLite NODE_SERVICE_DB: %s, %s' % (sql, ex, exc_info())
        logp(err_msg, logging.ERROR)
        return None


def insertDB(bin_key, bin_value, db_path):
    global DB
    #print('Insert to DB %s with Closed connection %s, key: %s, value: %s ' % (db_path, DB is None, bin_key, bin_value))
    try:
        if DB is None:
            DB = leveldb.LevelDB(db_path)
        DB.Put(bin_key, bin_value)
    except Exception as ex:
        err_msg = 'Exception on insert (key %s) (value %s) to LevelDB NODE_DB: %s %s ' % (bin_key, bin_value, ex, exc_info())
        logp(err_msg, logging.ERROR)


def getDB(bin_key, db_path):
    global DB
    try:
        if DB is None:
            DB = leveldb.LevelDB(db_path)
        return DB.Get(bin_key)
    except:
        return None


def deleteDB(bin_key, db_path):
    global DB
    if DB is None:
        DB = leveldb.LevelDB(db_path)
    DB.Delete(bin_key)


def isDBvalue(bin_key, db_path, dbm='db'):
    global DB
    try:
        # if DB is None:
        #     DB = leveldb.LevelDB(db_path) #Once init held by the process
        # value = DB.Get(bin_key)
        dbm = DB if dbm == 'db' else DB2
        if dbm is None:
            dbm = leveldb.LevelDB(db_path) #Once init held by the process
        value = dbm.Get(bin_key)
        #print('isDBvalue value', value, type(value))
        return True
    except Exception as ex:
        #TODO logger
        #print('Exception isDbValue: ', ex)
        return False



def to_sha256(to_str):
    return SHA256.new(str(to_str).encode('utf8')).hexdigest()


def to_md5(to_str):
    m = hashlib.md5()
    m.update(b'hello') #(str(to_str).encode('utf8'))
    return m.hexdigest()


def utc():
    return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')



def b(str):
    try:
        return bytes(str, 'utf8')
    except:
        return str

def exc_info():
    exc_type, exc_value, exc_tb = sys.exc_info()
    return '%s %s' %(os.path.basename(exc_tb.tb_frame.f_code.co_filename), exc_tb.tb_lineno)


# def v(module, func, *params): #VerNum methods
#     try:
#         if params != None and len(params) == 1:
#             args = unpackb(params[0])
#             return getattr(globals()[module], func)(args)
#         elif params != None and len(params) > 1:
#             #print('params', *params)
#             args = [unpackb(a) for a in params if type(a) is bytearray]
#             return getattr(globals()[module], func)(args)
#         else:
#             return getattr(globals()[module], func)()
#     except Exception as ex:
#         err_msg = '%s Exception: %s , call func %s.%s(%s) failed , %s' %(utc(), ex, module, func, params, exc_info())
#         getLogger().error(err_msg)
#         print(err_msg)
#         return None

def to_s(o):
    try:
        return str(o, 'utf8')
    except:
        return None


def v(msg, func, *params): #VerNum methods
    module = None
    try:
        if type(msg) is bytearray:
            module = 'v' + to_s(unpackb(msg)[b'data'][0]) #ver_num index CONST in all messages
        elif type(msg) is str:
             module = msg
        else:
            module = 'v' + msg[0] #to_s(msg[0])
        if (module is None):
            logp('VerNum module is None', logging.ERROR)
        if params != None and len(params) == 1:
            #args = unpackb(params[0])
            return getattr(globals()[module], func)(msg, params[0])
        elif params != None and len(params) > 1:
            args = [unpackb(a) for a in params if type(a) is bytearray]
            return getattr(globals()[module], func)(msg, *params)
        else:
            return getattr(globals()[module], func)(msg)
    except Exception as ex:
        err_msg = '%s Exception: %s , call func %s.%s(%s) failed , %s' % (utc(), ex, module, func, params, exc_info())
        getLogger().error(err_msg)
        print(err_msg)
        return None


def v_msg_list(func, bin_msg_list):
    if func is None or bin_msg_list is None or type(bin_msg_list) is not list or len(bin_msg_list) < 1:
        return None
    else:
        try:
            #for m in bin_msg_list:
            #    return v(m, func, m)
            return v(bin_msg_list[0], func, bin_msg_list)
        except:
            return None



def vv(ver_num):
    return 'v%s' % str(ver_num)


def vvv(msg, version_number, msg_type, field):
    #field_index = v('v' + version_number, 'msgi', msg_type, field)
    field_index = v(msg, 'msgi', field)
    if field_index is None:
        return None
    else:
        return msg[-1][field_index] or None


#TODO move to v1 when ready

def setTX(ver_num, msg_type, input_txs, output_txs, from_addr, to_addrs, asset_type, amounts, ts, sig_type, sig, pub_keys):
    tx = ()
    #genesis_tx = ('1', MSG_TYPE_SPEND_TX, ['%s,%s' % (genesis_sig['r'], genesis_sig['s'])], '1/1', ['%s,%s' % (genesis_pub_key['x'], genesis_pub_key['y'])], ['TX-GENESIS'], ['TX_GENESIS'], 'GENESIS', genesis_to_addr, '1', 10000000000.12345, merkle_date)
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
    return validateTX(tx)




from nacl.bindings import crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES
from nacl.public import Box, PrivateKey, PublicKey
from nacl.bindings.crypto_sign import crypto_sign_open as verify, crypto_sign as sign, \
    crypto_sign_seed_keypair as keys_from_seed


def getKeysFromRandomSeed():
    '''Random Private/Signing and Public/Verify keys'''
    try:
        sk = SigningKey(nacl.utils.random(32))
        return sk
    except:
        return None


def getKeysFromSeed(seed):
    '''Return 25519 Curve pub_key, priv_key nacl objects'''
    try:
        if isinstance(seed, str):
            seed = bytes(seed.ljust(32), 'utf8')
        elif not isinstance(seed, bytes):
            seed = packb(seed)
        #pub, priv = keys_from_seed(bin_str)
        sk = priv_key = SigningKey(seed)
        vk = pub_key = VerifyKey(sk.verify_key._key)
        return sk, vk
    except:
        return None


def persistKeysInServiceDB(bin_priv, bin_pub, bin_seed, pub_addr_str, nick=''): #TODO 4test only - to remove
    ##sql = "INSERT INTO v1_test_accounts (priv_key,pub_key,seed) values (?,?,?)" #,seed,nick,%s,%s)" % (pub_addr_str, nick)
    sql = "INSERT INTO v1_test_accounts (priv_key,pub_key,seed,pub_addr,nick) values (?,?,?,?,?)"
    con = getServiceDBconnection()
    with con:
        cur = con.cursor()
        ##cur.execute(sql, (sqlite3.Binary(bin_priv), sqlite3.Binary(bin_pub), sqlite3.Binary(bin_seed)))
        cur.execute(sql, [sqlite3.Binary(bin_priv), sqlite3.Binary(bin_pub), sqlite3.Binary(bin_seed), pub_addr_str, nick])
        con.commit()


def getVkFromPubKey():
    '''Return verify_key from pub_key'''
    pass


def getSkFromPrivKey():
    '''Return  signing_key from priv_key'''
    pass


def sign(msg, SignKey):
    ''' Return Curve 25519 Signature - msg hexdigest'''
    try:
        signed_msg = SignKey.sign(msg)
        return signed_msg
    except:
        return None


def verify(signed_msg, VerifyingKey):
    '''Return True if msg verified, otherwise false'''
    try:
        verified = VerifyingKey.verifySig(signed_msg)
        return True #verified
    except:
        return False


def getPubAddr(VK):
    '''Return HMAC hash from pub_key/verify_key'''
    try:
        pub_addr = HMAC.new(VK._key).hexdigest()
        return pub_addr
    except:
        return None

###


def insertGenesis(): #TODO onStartNode

    SK, VK = getKeysFromSeed('Bob')
    msg = b'msg'
    signed_msg = sign(msg, SK)
    verified_sig = verify(signed_msg, VK)
    pub_addr = getPubAddr(VK)
    print("msg verified %s for publicKey: %s" % (verified_sig, pub_addr)) #VK == VerifyKey(VK._key)
    persistKeysInServiceDB(SK._signing_key, SK.verify_key._key, SK._seed, pub_addr, 'Bob')
    rec = getServiceDB("select * from v1_test_accounts where pub_addr='%s'" % pub_addr)
    assert VerifyKey(rec[0][1]) == VK


    if not isDBvalue(b(MSG_TYPE_SPEND_TX + 'GENESIS'), NODE_DB): # and not isDBvalue(b(MSG_TYPE_UNSPENT_TX + 'GENESIS'), NODE_DB):
        #txs_db = leveldb.LevelDB(TXS_DB)
        #utxs_db  = leveldb.LevelDB(UTXS_DB)
        merkle_date = '01-01-2018 00:00:00.000'
        genesis_pub_key = {'x': 26063413541153741795311009536578546636609555338262636333004632681873009397378,
                           'y': 72849517704928537413839627784171110912318787674252857837896776821469476844155}
        genesis_sig = {'r': 36406343224692063900833029031111854117178867930743205589528043357636889016454,
                       's': 6504559082621797771456835002966813839522833454231390100388342046748949207233}
        genesis_to_addr ='71a758746fc3eb4d3e1e7efb8522a8a13d08c80cbf4eb5cdd0e6e4b473f27b16'
        genesis_tx_hash = '3fade5b1991d6672440c303b346e63b1b57cdb3d5a96a20a56911223199a548b'
        genesis_msg_hash = genesis_tx_hash #'e8d104457de771c251af9cd31cd40fcd2b061a3f38e2937e0df74423d511b79f'

        #msg_fields_tx = v(vv('1'), 'txf')  #['ver_num', 'msg_type', 'sigs', 'sig_type', 'pub_keys', 'input_txs', 'output_txs', 'from_addr, 'to_addr', 'asset_type', 'amount', 'ts']  # order & fields are handled by ver_num

        #from_addr = to_sha256(genesis_pub_key)
        #output_txs = MSG_TYPE_UNSPENT_TX + to_sha256(tx_hash+to_addr) #if remainder +output_tx to from address; output_txs = unspent_txs -> Block->Tx->MarkInputs as Outputs/UTXO
        genesis_tx = ('1', MSG_TYPE_SPEND_TX, ['%s,%s' % (genesis_sig['r'], genesis_sig['s'])], '1/1', ['%s,%s' % (genesis_pub_key['x'], genesis_pub_key['y'])], ['TX-GENESIS'], ['TX_GENESIS'], 'GENESIS', genesis_to_addr, '1', 10000000000.12345, merkle_date)  # from_address=sha256(pub_key)
        genesis_msg = ('1', MSG_TYPE_SPEND_TX, genesis_tx_hash, genesis_tx) #ver_num, msg_type, tx_hash
        tx_hash = to_sha256(str(genesis_tx)) #[1:] 2nd value is MsgSig - extracted from msg
        print('Genesis TX Hash: ', tx_hash)  # TODO validation
        assert (tx_hash == genesis_tx_hash)
        print('Genesis Msg Hash - Output TX: ', to_sha256(str(genesis_msg))) #TODO validation

        #from v1 import setTX TOdo
        setTX(1, MSG_TYPE_SPEND_TX, ['TX_GENESIS'], ['TX_GENESIS'], from_addr, to_addrs, asset_type, amounts, ts, sig_type, sig, pub_key)

        #verifyTx(genesis_tx)
        unspent_tx = msg_hash = to_sha256(str(genesis_tx))
        #unspent_tx = msg_hash = to_sha256(str(genesis_msg))
        #assert (genesis_msg_hash == msg_hash)
        #print('GENESIS MSG', genesis_msg, '\nGENESIS MSG_TX', str(genesis_msg[3]))

        # msg_fields = ['%s' % t for t in msg_fields_tx]
        print("Insert GENESIS TX")

        ##genesis_packed_msg = packb(genesis_tx)
        genesis_packed_msg = packb({'tx_hash': tx_hash, 'data': genesis_tx})
        #ONLY TX is written to DB, while HASH is validated/calculated #todo

        ##insertDB(b(MSG_TYPE_TX + 'GENESIS'), genesis_packed_msg, NODE_DB)
        insertDB(b(MSG_TYPE_SPEND_TX + 'GENESIS'), genesis_packed_msg, NODE_DB)


        #unspent_tx_fields [prefix_type - (TX, Contract, Vote, Service, ...etc), key(txid: sha256(msg)),value([asset_type, amount])
        print('[TX_MSG_HASH = UNSPENT_TX_ID],input_tx, to_addr, asset_type, amount, input_tx - ', MSG_TYPE_UNSPENT_TX + unspent_tx, genesis_tx[-4], genesis_tx[-3], genesis_tx[-2], b(MSG_TYPE_SPEND_TX + 'GENESIS'))
        genesis_unspent_tx = [genesis_tx[-4], genesis_tx[-3], genesis_tx[-2], b(MSG_TYPE_SPEND_TX + 'GENESIS')] #MSG_TYPE_UNSPENT_TX + unspent_tx,
        print('genesis_unspent_tx', genesis_unspent_tx)
        insertDB(b(MSG_TYPE_UNSPENT_TX + 'GENESIS'), packb(genesis_unspent_tx), NODE_DB) #getIndexByFields + Constants for PREFIX_TYPE
        #insertDB(b(MSG_TYPE_UNSPENT_TX + tx_hash), packb(genesis_unspent_tx), NODE_DB)
        print('Unpacked GenesisTX type', type(unpackb(genesis_packed_msg)))
        #block fields: [BlockNumber, BlockHash(ToDoCalc), BlockMsg:[BlockNumber #, BlockTS, PrevBlockHash, TXS_HASH_LIST - (outputs_list), MINER_ADDR]] #ToDo Longest BlockList + validate voting
        #block hash = sha256(block_input_txs[])

        #BlockBody (verNumber, blockNumber, PreviousBlockHash, input_tx_list, output_tx_list)
        block_msg_fields  = ['1', MSG_TYPE_BLOCK + '1', 'GENESIS', [MSG_TYPE_SPEND_TX + 'GENESIS'], [MSG_TYPE_UNSPENT_TX + genesis_tx_hash]]
        block_msg_hash = to_sha256(str(block_msg_fields))
        #BlockMsg (block_hash, block_body)
        block_msg = {'block_hash': block_msg_hash, 'data': block_msg_fields}
        block_msgb = packb(block_msg)
        insertDB(packb(block_msg_fields[1]), block_msgb, NODE_DB)

        ##print('txi', v(vv('1'), 'txi', 'ts'))
        print('msgv', vvv(genesis_msg, genesis_msg[0], genesis_msg[1], 'ts')) #MSG_TYPE_TX=genesis_msg[1]

        #print('block_msg', block_msg)        # Save/upDATE Last BlockNUMBER AND hASH on writeNewBlock and onNodeStart
        #service [BlockNumber, MINER_VOTES_LIST, PENALTIED_MINERS_LIST]
        #miner_rewards tx [BlockNumber, REWARDS_TX[asset_type, asset_amount, MINER_ADDR]]
        #SELF_votes_tx [BlockNumber, Voted=True|False] #validate on block write + if BlockNumber not found -> voted=False

    #tests
    print('GENESIS- key in NODE_DB', getDB(b'KEY_NOT_EXIST', NODE_DB), 'KEY_NOT_EXIST')
    print('TX_GENESIS key in NODE_DB', getDB(b'TX_GENESIS', NODE_DB), 'TX_GENESIS')
    # deleteDB(b'GENESIS', NODE_DB)
    print('GENESIS key in NODE_DB', isDBvalue(b(MSG_TYPE_SPEND_TX + 'GENESIS'), NODE_DB)) # TXS_DB #'./../home/igorb/PycharmProjects/test/venv/db/71a758746fc3eb4d3e1e7efb8522a8a13d08c80cbf4eb5cdd0e6e4b473f27b16/TXS'
    print('GENESIS TX value in NODE_DB', unpackb(getDB(b(MSG_TYPE_UNSPENT_TX + 'GENESIS'), NODE_DB)) if isDBvalue(b(MSG_TYPE_UNSPENT_TX + "GENESIS"), NODE_DB) else 'NOT_FOUND') #unpackb(getDB(b'TX-GENESIS', if b'TX-GENESIS'NODE_DB))
    #print('GENESIS TX value in NODE_DB', unpackb(getDB(b(MSG_TYPE_UNSPENT_TX + tx_hash), NODE_DB)) if isDBvalue(b(MSG_TYPE_UNSPENT_TX + tx_hash), NODE_DB) else 'NOT_FOUND') #unpackb(getDB(b'TX-GENESIS', if b'TX-GENESIS'NODE_DB))
    print('GENESIS UNSPENT_TX value in NODE_DB', unpackb(getDB(b(MSG_TYPE_UNSPENT_TX + "GENESIS"), NODE_DB))) #unpackb(getDB(b'TX_GENESIS', NODE_DB)) if isDBvalue(b'TX_GENESIS', NODE_DB) else 'NOT_FOUND')
    print(os.listdir(ROOT_DIR+'/v'))
    print('Amount of v files', len([f for f in os.listdir(ROOT_DIR+'/v') if '_' not in f and os.path.isfile(ROOT_DIR+'/v/'+f)])) #Validation for v numbers + validate valid enumeration in v folder
    #v1.test('CALL')
    #v('v1', 'test', 'DYNAMIC')
    #print('v1 TX msg fields:', v(vv('1'), 'txf'))
    #func = getattr(globals()['v1'], 'test')
    #globals()['v1'].test('DYNAMIC-')
    #func('DYNAMIC+')
    gmsg = getDB(b'TX-GENESIS', NODE_DB)
    ##insertServiceDbPending([gmsg])
    #pmsg = getServiceDB("select * from pending_tx where id=1")[0]
    bmsg = unpackb(gmsg)[b'data']
    keys = v1.TX_MSG_FIELDS
    ##pmsg = getServiceDB("select %s from pending_tx where id=1" % (",".join(keys)))[0]

    msg_list = getServiceDB("select %s from pending_tx where tx_hash='%s'" % (",".join(keys), to_sha256(bmsg)))
    if len(msg_list) == 0:
        insertServiceDbPending([gmsg])
    else: #ToDo remove to validate
        pmsg = msg_list[0]
        msg = []
        for f in pmsg:
            msg.append(float(f), ) if type(f) is float else None
            msg.append(([b(f.replace("[", "").replace("]", ""))]),) if type(f) is str and re.search(r'^\[.*\]$', f) is not None else None
            msg.append(b(f), ) if type(f) is str and "[" not in f else None
        assert bmsg == msg
        assert to_sha256(bmsg) == to_sha256(msg)

def insertMsgService(msg): #TaskQ to validate msg and to delete if unvalid -> b/c of high traffic unable to calc/validate before persist ?

    if not isDBvalue(b'TX_GENESIS', NODE_DB):
        #txs_db = leveldb.LevelDB(TXS_DB)
        #utxs_db  = leveldb.LevelDB(UTXS_DB)
        merkle_date = '01-01-2018 00:00:00.000'
        genesis_pub_key = {'x': 26063413541153741795311009536578546636609555338262636333004632681873009397378,
                           'y': 72849517704928537413839627784171110912318787674252857837896776821469476844155}
        genesis_sig = {'r': 36406343224692063900833029031111854117178867930743205589528043357636889016454,
                       's': 6504559082621797771456835002966813839522833454231390100388342046748949207233}
        genesis_to_addr ='71a758746fc3eb4d3e1e7efb8522a8a13d08c80cbf4eb5cdd0e6e4b473f27b16'
        genesis_tx_hash = '3bbc8b608031e0c9444c293f7ed1031d6683c10869387a83fd8f8a264edba232'
        genesis_msg_hash = genesis_tx_hash #'e8d104457de771c251af9cd31cd40fcd2b061a3f38e2937e0df74423d511b79f'
        msg_fields_tx = ['ver_num', 'msg_type', 'msg_hash', 'msg', 'sig_type', 'sigs', 'pub_keys', 'input_txs', 'to_addr', 'asset_type', 'amounts', 'ts']  # order & fields are handled by ver_num
        genesis_tx = ['1', MSG_TYPE_SPEND_TX, '1/1', '[%s %s]' % (genesis_sig['r'], genesis_sig['s']), '[%s %s]' % (genesis_pub_key['x'], genesis_pub_key['y']), '[GENESIS]', genesis_to_addr, '1', 10000000000, merkle_date]  # from_address=sha256(pub_key)
        genesis_msg = ['1', MSG_TYPE_SPEND_TX, genesis_tx_hash, genesis_tx] #ver_num, msg_type, tx_hash
        tx_hash = to_sha256(str(genesis_tx))
        print('Genesis TX Hash: ', tx_hash)  # TODO validation
        assert (tx_hash == genesis_tx_hash)
        print('Genesis Msg Hash - Output TX: ', to_sha256(str(genesis_msg))) #TODO validation
        verifyTx(genesis_tx)
        unspent_tx = tx_hash #msg_hash = to_sha256(str(genesis_tx))
        #unspent_tx = msg_hash = to_sha256(str(genesis_msg))
        #assert (genesis_msg_hash == msg_hash)
        #print('GENESIS MSG', genesis_msg, '\nGENESIS MSG_TX', str(genesis_msg[3]))

        # msg_fields = ['%s' % t for t in msg_fields_tx]
        print("Insert GENESIS TX")
        genesis_packed_msg = packb(genesis_tx)
        #ONLY TX is written to DB, while HASH is validated/calculated #todo
        insertDB(b(MSG_TYPE_SPEND_TX + 'GENESIS'), genesis_packed_msg, NODE_DB)
        #unspent_tx_fields [prefix_type - (TX, Contract, Vote, Service, ...etc), key(txid: sha256(msg)),value([asset_type, amount])
        print('[TX_MSG_HASH = UNSPENT_TX_ID], input_tx, to_addr, asset_type, amount - ', MSG_TYPE_UNSPENT_TX + unspent_tx, genesis_tx[-4], genesis_tx[-4], genesis_tx[-3], genesis_tx[-2])
        genesis_unspent_tx = [genesis_tx[-4], genesis_tx[-3], genesis_tx[-2]] #MSG_TYPE_UNSPENT_TX + unspent_tx,
        insertDB(b(MSG_TYPE_UNSPENT_TX + 'GENESIS'), packb(genesis_unspent_tx), NODE_DB) #getIndexByFields + Constants for PREFIX_TYPE
        print('Unpacked GenesisTX type', type(unpackb(genesis_packed_msg)))
        #block fields: [BlockNumber, BlockHash(ToDoCalc), BlockMsg:[BlockNumber #, BlockTS, PrevBlockHash, TXS_HASH_LIST - (outputs_list), MINER_ADDR]] #ToDo Longest BlockList + validate voting
        #block hash = sha256(block_input_stxs[])
        block_hash = to_sha256(str(msg[input_txs]))
        block_msg = [1, msg['ts'], block_hash, b'GENESIS', b('[+tx_hash+]'), msg['to_addr']]
        print('block_msg', block_msg)
        # Save/upDATE Last BlockNUMBER AND hASH on writeNewBlock and onNodeStart
        #service [BlockNumber, MINER_VOTES_LIST, PENALTIED_MINERS_LIST]
        #miner_rewards tx [BlockNumber, REWARDS_TX[asset_type, asset_amount, MINER_ADDR]]
        #SELF_votes_tx [BlockNumber, Voted=True|False] #validate on block write + if BlockNumber not found -> voted=False




def validateMsg(msg):
    return v('v' + msg[3], 'test', 'DYNAMIC')



def verifyTx(tx_msg):
    #v1.test()
    #validateMsg(tx_msg)
    pass



# config utils
CONFIG = None
def load_config(path='config.ini'):
    try:
        config = configparser.ConfigParser()
        config.read(path)
        CONFIG = config
        return CONFIG
    except FileNotFoundError:
        raise FileNotFoundError


def get_config_value(section, key, path='config.ini'):
    if CONFIG is None: load_config(path)
    if CONFIG is None:
        raise Exception("No config found")
    else:
        try:
            value = CONFIG[section][key]
            return value
        except Exception:
            raise Exception('[%s][%] is not found in config' % (section, key))


def update_config_value(section, key, value, path='config.ini', update_only_inmem=False):
    """

    should be approved (voted) by nodes quorum
    """

    if CONFIG is None: load_config(path)
    if CONFIG is None:
        raise Exception("No config found")
    else:
        try:
            CONFIG[section][key] = value
            if (not update_only_inmem):
                with open(path, 'w') as configfile:
                    CONFIG.write(configfile)

            print("%s config updated with [%s][%] = %s" % (path, section, key, value))
            return load_config(path)
        except Exception:
            raise Exception('[%s][%] is not found in config %s' % (section, key, path))


def getConfig():
    if CONFIG is None: return load_config()
    else: return CONFIG
RUNTIME_CONFIG['FileConfig'] = getConfig()


NODE_ID = None
LOGGER = None
def getLogger():
    global LOGGER
    if LOGGER is None:
        log_file = "logs/node.log"
        LOGGER = create_rotating_log(log_file, "logger")
    return LOGGER

def setNode(pub_key):
    if not pub_key is None:
        global NODE_ID
        NODE_ID = pub_key
        RUNTIME_CONFIG['NodeId'] = pub_key
        setNodeDb(pub_key) #4 testing pub_key
        getLogger()


def run_version(func, params=None):
    func(params)


def logp(msg, mode, console=DEBUG):
    msg = '%s %s' % (utc(), msg)
    if mode == logging.ERROR:
        getLogger().error(msg)
    elif mode == logging.WARNING:
        getLogger().warning(msg)
    else:
        getLogger().info(msg)
    if console:
        print(msg)
#############

def add_config_key_value():  # should be approved by nodes quorum
    pass


def save_config_as_binary():
    pass



def load_config_as_binary():
    pass


def get_config_checksum():
    pass


def killByPort(*ports):
    lines = subprocess.check_output(["netstat", "-ano"], universal_newlines=True)
    rows = []
    pids = []
    for port in ports:
        for line in lines.splitlines()[4:]:
            # print (line)
            c = line.split()
            if port not in c[1]:
                continue
            rows.append(line)
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




def whoIsMaster():
    """

    :return: miner's turn index in config
    """

    # configuration = load_config()
    configuration = getConfig()
    start_time = datetime(2017, 1, 1)  # BlockChain start - TODO change to 2018 real start date
    current_time = datetime.utcnow()
    s = calendar.timegm(start_time.utctimetuple())
    e = calendar.timegm(current_time.utctimetuple())
    ellapsed_sec = (s - e)  # seconds ellapsed since genesis
    miners_amount = len(configuration['nodes'])
    # return (ellapsed_sec % miners_amount)  # miner's index in config
    master_index = (ellapsed_sec // int(configuration['settings']['block_time_sec'])) % miners_amount
    return (configuration['nodes'][list(configuration['nodes'])[master_index]])


def getNode(count, nodes={}):
    configuration = getConfig()
    if len(nodes) == 0: nodes = configuration['nodes']
    if count not in range(0, len(nodes)): return None
    node_key = list(nodes)[count]
    return nodes[node_key]

# log utils
# file utils
# crypto utils
# validation utils
# verification utils



#QQQ
# IncomingMsg - NoComputeSpeed -> Task Q -> Persist to  Pending [DBQ]-> Validate/Invalidate -> write to Pending DB ->SqlLite or Mongo
# ##########OnIncomingBlock -> write to TXS, Votes ... delete from temp DB
# BlockTime = MinerAddr + TShash




# ----------------------------------------------------------------------
def create_rotating_log(path, label="Rotating Log"):
    """
    Creates a rotating log
    """
    logger = logging.getLogger(label)
    logger.setLevel(logging.INFO)

    # add a rotating handler
    handler = RotatingFileHandler(path, maxBytes=10000000, backupCount=10000)
    logger.addHandler(handler)
    return logger


# ----------------------------------------------------------------------

##############
def setup_logger(logger_name, log_file, level=logging.INFO):
    log_setup = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    log_setup.setLevel(level)
    log_setup.addHandler(fileHandler)
    log_setup.addHandler(streamHandler)


def logger(msg, level, logfile):
    if logfile == 'logger2': log = logging.getLogger('logger2')
    if logfile == 'logger3': log = logging.getLogger('logger3')
    if level == 'info': log.info(msg)
    if level == 'warning': log.warning(msg)
    if level == 'error': log.error(msg)


##############

# if __name__ == "__main__":
#     log_file1 = "test.log"
#     logger1 = create_rotating_log(log_file1, "logger1")
#
#     log_file2 = "another_test.log"
#     logger2 = create_rotating_log(log_file2, "logger2")
#
#     logger1.info("Test5")
#     logger2.info("Test6")
##############

if __name__ == "__main__":
   project_dir =  os.path.dirname(os.path.abspath(__file__))
   imp = os.path.join(project_dir, "utils")
   print (imp)
   import imp
   initServiceDB()
