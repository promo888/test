import os, sys
import calendar
from datetime import *
from time import *
import configparser
import psutil, subprocess, re
import datetime, time
from fastecdsa import curve, ecdsa, keys
from fastecdsa.keys import export_key, import_key
from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto.Hash import SHA256
from msgpack import packb, unpackb
import pandas
import leveldb
import sqlite3
from sqlobject import *
#import v
from v import *


#pip install --proxy http://lab:Welcome1@10.72.0.50:8080 matplotlib
#import msgpack #git clone msgpack && cd mspack && sudo python3 setup.py install /or Project Settings - Project -Project Interpreter - Available Packages - Install
#ps fax | grep python3 | grep -v grep |awk '{print $1}' | xargs -r kill -9

NODE_TYPE = "Node" or "Wallet"
PORT_REP_SERVER = 7777   # Receiving data from the world TXs, quiries ...etc
PORT_UDP_SERVER = 8888   # Receiving data from miners
MSG_TYPE_TX = "TX-" #SPENT TX
MSG_TYPE_UNSPENT_TX = "TX_"
MSG_TYPE_TX_VALIDATED_AND_PENDING = "_T_"
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
NODE_SERVICE_DB = '%s/service_db/DATA' % ROOT_DIR

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



def setRuntimeConfig(key,value):
    try:
        RUNTIME_CONFIG[key] = value
    except:
        pass


def setNodeDb(pub_key):
    #global NODE_DB
    # global TXS_DB
    # global UTXS_DB
    # global VOTES_DB
    # global BLOCKS_DB
    # global CONTRACTS_DB
    # global SERVICE_DB
    # global PENDING_DB
    # global RUNTIME_CONFIG
    #NODE_DB = '%s/db/%s/DATA' % (ROOT_DIR, pub_key)
    # TXS_DB = '%s/db/%s/TXS' % (ROOT_DIR, pub_key)
    # UTXS_DB = '%s/db/%s/UTXS' % (ROOT_DIR, pub_key)
    # VOTES_DB = '%s/db/%s/VOTES' % (ROOT_DIR, pub_key)
    # BLOCKS_DB = '%s/db/%s/BLOCKS' % (ROOT_DIR, pub_key)
    # CONTRACTS_DB = '%s/db/%s/CONTRACTS' % (ROOT_DIR, pub_key)
    # SERVICE_DB = '%s/db/%s/SERVICE' % (ROOT_DIR, pub_key)
    # PENDING_DB = '%s/db/%s/PENDING' % (ROOT_DIR, pub_key)
    #RUNTIME_CONFIG['NODE_DB'] = NODE_DB
    # RUNTIME_CONFIG['TXS_DB'] = TXS_DB
    # RUNTIME_CONFIG['UTXS_DB'] = UTXS_DB
    # RUNTIME_CONFIG['VOTES_DB'] = VOTES_DB
    # RUNTIME_CONFIG['BLOCKS_DB'] = BLOCKS_DB
    # RUNTIME_CONFIG['CONTRACTS_DB'] = CONTRACTS_DB
    # RUNTIME_CONFIG['SERVICE_DB'] = SERVICE_DB
    #RUNTIME_CONFIG['SERVICE_DB'] = SERVICE_DB
    RUNTIME_CONFIG['NODE_TYPE'] = getNodeId()
    dirs = [NODE_DB, NODE_SERVICE_DB] #[NODE_DB, TXS_DB, UTXS_DB, VOTES_DB, CONTRACTS_DB, SERVICE_DB, PENDING_DB]
    for folder in dirs:
        if not os.path.exists(folder):
            os.makedirs(folder)
    initServiceDB()


def getNodeId():
    return NODE_ID


def initServiceDB():
    global SERVICE_DB
    try:
        if SERVICE_DB is None:
            SERVICE_DB = sqlite3.connect(NODE_SERVICE_DB)
            #Create Tables


        return True
    except Exception as ex:
        #TODO logger
        print('Exception on init of SqlLite NODE_SERVICE_DB:  %s %s' % (utc(), ex))
        return None


def insertServiceDB(str_insert_query):
    global SERVICE_DB
    #print('Insert to DB %s with Closed connection %s, key: %s, value: %s ' % (db_path, DB is None, bin_key, bin_value))
    try:
        if SERVICE_DB is None:
            SERVICE_DB = sqlite3.connect(NODE_SERVICE_DB)
        DB.Put(bin_key, bin_value)
        return True
    except Exception as ex:
        #TODO logger
        print('Exception on insert to SqlLite NODE_SERVICE_DB: %s %s' % (utc(), ex))
        return None


def insertDB(bin_key, bin_value, db_path):
    global DB
    #print('Insert to DB %s with Closed connection %s, key: %s, value: %s ' % (db_path, DB is None, bin_key, bin_value))
    try:
        if DB is None:
            DB = leveldb.LevelDB(db_path)
        DB.Put(bin_key, bin_value)
    except Exception as ex:
        #TODO logger
        print('Exception on insert to LevelDB NODE_DB: %s %s' % (utc(), ex))

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


def insertGenesis(): #TODO onStartNode

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
        msg_fields_tx = ['ver_num', 'msg_type', 'msg_hash', 'msg', 'sig_type', 'sigs', 'pub_keys', 'input_txs', 'to_addr', 'asset_type', 'amount', 'ts']  # order & fields are handled by ver_num
        genesis_tx = ['1', MSG_TYPE_TX, '1/1', '[%s %s]' % (genesis_sig['r'], genesis_sig['s']), '[%s %s]' % (genesis_pub_key['x'], genesis_pub_key['y']), '[GENESIS]', genesis_to_addr, '1', 10000000000, merkle_date]  # from_address=sha256(pub_key)
        genesis_msg = ['1', MSG_TYPE_TX, genesis_tx_hash, genesis_tx] #ver_num, msg_type, tx_hash
        tx_hash = to_sha256(str(genesis_tx))
        print('Genesis TX Hash: ', tx_hash)  # TODO validation
        assert (tx_hash == genesis_tx_hash)
        print('Genesis Msg Hash - Output TX: ', to_sha256(str(genesis_msg))) #TODO validation
        verifyTx(genesis_tx)
        unspent_tx = msg_hash = to_sha256(str(genesis_tx))
        #unspent_tx = msg_hash = to_sha256(str(genesis_msg))
        #assert (genesis_msg_hash == msg_hash)
        #print('GENESIS MSG', genesis_msg, '\nGENESIS MSG_TX', str(genesis_msg[3]))

        # msg_fields = ['%s' % t for t in msg_fields_tx]
        print("Insert GENESIS TX")
        genesis_packed_msg = packb(genesis_tx)
        #ONLY TX is written to DB, while HASH is validated/calculated #todo
        insertDB(b(MSG_TYPE_TX + 'GENESIS'), genesis_packed_msg, NODE_DB)
        #unspent_tx_fields [prefix_type - (TX, Contract, Vote, Service, ...etc), key(txid: sha256(msg)),value([asset_type, amount])
        print('[TX_MSG_HASH = UNSPENT_TX_ID],input_tx, to_addr, asset_type, amount - ', MSG_TYPE_UNSPENT_TX + unspent_tx, genesis_tx[-4], genesis_tx[-4], genesis_tx[-3], genesis_tx[-2])
        genesis_unspent_tx = [genesis_tx[-4], genesis_tx[-3], genesis_tx[-2]] #MSG_TYPE_UNSPENT_TX + unspent_tx,
        insertDB(b(MSG_TYPE_UNSPENT_TX + 'GENESIS'), packb(genesis_unspent_tx), NODE_DB) #getIndexByFields + Constants for PREFIX_TYPE
        print('Unpacked GenesisTX type', type(unpackb(genesis_packed_msg)))
        #block fields: [BlockNumber, BlockHash(ToDoCalc), BlockMsg:[BlockNumber #, BlockTS, PrevBlockHash, TXS_HASH_LIST, MINER_ADDR]] #ToDo Longest BlockList + validate voting
        # Save/upDATE Last BlockNUMBER AND hASH on writeNewBlock and onNodeStart
        #service [BlockNumber, MINER_VOTES_LIST, PENALTIED_MINERS_LIST]
        #miner_rewards tx [BlockNumber, REWARDS_TX[asset_type, asset_amount, MINER_ADDR]]
        #SELF_votes_tx [BlockNumber, Voted=True|False] #validate on block write + if BlockNumber not found -> voted=False

    #tests
    print('GENESIS- key in NODE_DB', getDB(b'NOT_EXIST_KEY', NODE_DB), 'NOT_EXIST_KEY')
    print('TX_GENESIS key in NODE_DB', getDB(b'TX_GENESIS', NODE_DB), 'TX_GENESIS')
    # deleteDB(b'GENESIS', NODE_DB)
    print('GENESIS key in NODE_DB', isDBvalue(b'TX-GENESIS', NODE_DB)) # TXS_DB #'./../home/igorb/PycharmProjects/test/venv/db/71a758746fc3eb4d3e1e7efb8522a8a13d08c80cbf4eb5cdd0e6e4b473f27b16/TXS'
    print('GENESIS TX value in NODE_DB', unpackb(getDB(b'TX-GENESIS', NODE_DB)) if isDBvalue(b'TX-GENESIS', NODE_DB) else 'NOT_FOUND')
    print('GENESIS UNSPENT_TX value in NODE_DB', unpackb(getDB(b'TX_GENESIS', NODE_DB)) if isDBvalue(b'TX_GENESIS', NODE_DB) else 'NOT_FOUND')
    print(os.listdir(ROOT_DIR+'/v'))
    print('Amount of v files', len([f for f in os.listdir(ROOT_DIR+'/v') if '_' not in f and os.path.isfile(ROOT_DIR+'/v/'+f)])) #Validation for v numbers + validate valid enumeration in v folder


def v(module, func, params=None): #VerNum methods
    try:
        if params != None:
            return module.func(params)
        else:
            return module.func()
    except Exception as ex:
        #ToDo logger
        print('Exception: %s , call func %s.%s(%s) failed' %(ex, module, func, params))
        return None

def validateMsg(msg):
    return v('v'+ msg[0], 'test')



def verifyTx(tx_msg):
    #v1.test()
    validateMsg(tx_msg)
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
def setNodeId(pub_key):
    if not pub_key is None:
        global NODE_ID
        NODE_ID = pub_key
        RUNTIME_CONFIG['NodeId'] = pub_key
        setNodeDb(pub_key)


def run_version(func, params=''):
    func(params)


#############
def add_config_key_value():  # should be approved by nodes quorum
    pass


def save_config_as_binary():
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