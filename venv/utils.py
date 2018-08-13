import os, sys
import calendar
from datetime import *
from time import *
import configparser
import psutil, subprocess, re
import leveldb
import datetime, time
from fastecdsa import curve, ecdsa, keys
from fastecdsa.keys import export_key, import_key
from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto.Hash import SHA256



NODE_TYPE = "Node" or "Wallet"
PORT_REP_SERVER = 7777   # Receiving data from the world TXs, quiries ...etc
PORT_UDP_SERVER = 8888   # Receiving data from miners
MSG_TYPE_TX = "_TX"
MSG_TYPE_MULTI_SIG = "MNS"
MSG_TYPE_VOTE = "VOT"
MSG_TYPE_CONTRACT = "CNT"
MSG_TYPE_BLOCK = "BLK"
MSG_TYPE_PENALTY = "PNL"
MSG_TYPE_REQUEST = "REQ"
REQUEST_TYPE_BLOCK = 'RBL'
REQUEST_TYPE_TX = 'RTX' #used to retrieve ALL type of messages by specifying MSG_TYPE param in request
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
TXS_DB = './..%s/db/TXS' % ROOT_DIR
UTXS_DB = './..%s/db/UTXS' % ROOT_DIR
VOTES_DB = './..%s/db/VOTES' % ROOT_DIR
BLOCKS_DB = './..%s/db/BLOCKS' % ROOT_DIR
CONTRACTS_DB = './..%s/db/CONTRACTS' % ROOT_DIR
SERVICE_DB = './..%s/db/SERVICE' % ROOT_DIR
PENDING_DB = './..%s/db/PENDING' % ROOT_DIR
DB = None
RUNTIME_CONFIG = {'FileConfig': None, 'NodeType': NODE_TYPE, 'NodeId': None, 'PENDING_DB': PENDING_DB, 'TXS_DB': TXS_DB, 'UTXS_DB': UTXS_DB, 'VOTES_DB': VOTES_DB, 'BLOCKS_DB': BLOCKS_DB, 'CONTRACTS_DB': CONTRACTS_DB, 'SERVICE_DB': SERVICE_DB}



def setRuntimeConfig(key,value):
    try:
        RUNTIME_CONFIG[key] = value
    except:
        pass


def setNodeDb(pub_key):
    global TXS_DB
    global UTXS_DB
    global VOTES_DB
    global BLOCKS_DB
    global CONTRACTS_DB
    global SERVICE_DB
    global PENDING_DB
    global RUNTIME_CONFIG
    TXS_DB = './..%s/db/%s/TXS' % (ROOT_DIR, pub_key)
    UTXS_DB = './..%s/db/%s/UTXS' % (ROOT_DIR, pub_key)
    VOTES_DB = './..%s/db/%s/VOTES' % (ROOT_DIR, pub_key)
    BLOCKS_DB = './..%s/db/%s/BLOCKS' % (ROOT_DIR, pub_key)
    CONTRACTS_DB = './..%s/db/%s/CONTRACTS' % (ROOT_DIR, pub_key)
    SERVICE_DB = './..%s/%s/SERVICE' % (ROOT_DIR, pub_key)
    PENDING_DB = './..%s/%s/PENDING' % (ROOT_DIR, pub_key)
    RUNTIME_CONFIG['TXS_DB'] = TXS_DB
    RUNTIME_CONFIG['UTXS_DB'] = UTXS_DB
    RUNTIME_CONFIG['VOTES_DB'] = VOTES_DB
    RUNTIME_CONFIG['BLOCKS_DB'] = BLOCKS_DB
    RUNTIME_CONFIG['CONTRACTS_DB'] = CONTRACTS_DB
    RUNTIME_CONFIG['SERVICE_DB'] = SERVICE_DB
    RUNTIME_CONFIG['PENDING_DB'] = PENDING_DB



def getNodeId():
    return NODE_ID


def insertDB(bin_key, bin_value, db_path):
    global DB
    DB = leveldb.LevelDB(db_path)
    DB.Put(bin_key, bin_value)


def isDBvalue(bin_key, db_path):
    global DB
    try:
        if DB is None:
            DB = leveldb.LevelDB(db_path) #Once init held by the process
        value = DB.Get(bin_key)
        #print('isDBvalue value', value, type(value))
        return True
    except Exception as e:
        #TODO logger
        #print('Exception isDbValue: ', e)
        return False



def to_sha256(to_str):
    return SHA256.new(str(to_str).encode('utf8')).hexdigest()


def to_md5(to_str):
    m = hashlib.md5()
    m.update(b'hello') #(str(to_str).encode('utf8'))
    return m.hexdigest()


def utc():
    return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')


def insertGenesis(): #TODO onStartNode
    if not isDBvalue(b'GENESIS', TXS_DB):
        #txs_db = leveldb.LevelDB(TXS_DB)
        #utxs_db  = leveldb.LevelDB(UTXS_DB)
        merkle_date = '01-01-2018 00:00:00.000'
        genesis_pub_key = {'x': 26063413541153741795311009536578546636609555338262636333004632681873009397378,
                           'y': 72849517704928537413839627784171110912318787674252857837896776821469476844155}
        genesis_sig = {'r': 36406343224692063900833029031111854117178867930743205589528043357636889016454,
                       's': 6504559082621797771456835002966813839522833454231390100388342046748949207233}
        genesis_to_addr ='71a758746fc3eb4d3e1e7efb8522a8a13d08c80cbf4eb5cdd0e6e4b473f27b16'
        genesis_msg_hash = 'fb40a6dc1a58ba0816967410ad2fda3febc14d82e673cabdcb077ef53d1b4b7b'
        msg_fields_tx = ['ver_num', 'msg_type', 'msg_hash', 'msg', 'sig_type', 'sigs', 'input_txs', 'pub_keys', 'to_addr', 'asset_type', 'amount', 'ts']  # order & fields are handled by ver_num
        genesis_tx = ['1', '_TX', '1/1', '[%s %s]' % (genesis_sig['r'], genesis_sig['s']), '[GENESIS]', '[%s %s]' % (genesis_pub_key['x'], genesis_pub_key['y']), genesis_to_addr, '1', 10000000000, merkle_date]  # from_address=sha256(pub_key)
        genesis_msg = ('1', '_TX', genesis_msg_hash, genesis_tx)
        print('GENESIS MSG', genesis_msg, '\nGENESIS MSG_TX', str(genesis_msg[3]))
        # msg_fields = ['%s' % t for t in msg_fields_tx]
        insertDB(b'GENESIS', bytes(str(msg_fields_tx).replace('[', '').replace(']', ''), 'utf8'), 'utf8')

    #TO UTXO DB


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
