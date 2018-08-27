import os
import datetime
import time
from collections import OrderedDict
import msgpack as mp, pandas as pd
import sqlite3

project_dir = os.path.dirname(os.path.abspath(__file__))
imp = os.path.join(project_dir, "utils")
import imp

TX_MSG_FIELDS_PENDING = ('ver_num', 'msg_type', 'msg_sig', 'msg')
TX_MSG_FIELDS = ('ver_num', 'sigs', 'sig_type', 'pub_keys', 'msg_type', 'input_txs', 'to_addr', 'asset_type', 'amount', 'ts')
#TX_MULTI_MSG_FIELDS = ('pub_keys', 'sigs', 'sigs_type', 'ver_num', 'msg_type', 'input_txs', 'to_addr', 'asset_type', 'amount', 'ts') #pub_keys & sigs are array in multi_tx
TX_SERVICE_MSG_FIELDS = TX_MSG_FIELDS + ("node_date",)
#TX_MSG_FIELDS += ("node_date") # Overriden by each node onMsgAccept #['ver_num', 'msg_type', 'msg_hash', 'msg', 'created_at date']
UNSPENT_TX_MSG_FIELDS = ()
BLOCK_MSG_FIELDS = ()
CONTRACT_MSG_FIELDS = ()
MSG_TYPES = {'TX_SINGLE': 1, 'TX_MULTI': 2, 'TX_CONTRACT': 3}

# def b(str):
#     return bytes(str, 'utf8')

def importUtils():
    project_dir = os.path.dirname(os.path.abspath(__file__))
    imp = os.path.join(project_dir, "utils")
    import imp

def utc2():
    return datetime.datetime.utcfromtimestamp(time.time()) #sqllite date -> datetime.datetime

def getTxMsgFieldIndex(field):
    try:
        res = [(i,v) for i,v in enumerate(TX_MSG_FIELDS) if v == field]
        if res.__len__() == 0:
            return None
        else:
            return res[0][0] #-1
    except:
        return None

def txi(field):
    return getTxMsgFieldIndex(field)


def msgi(msg_type, field):
    #if msg_type == MSG_TYPE_TX:
        #return getTxMsgFieldIndex(field)
    return txi(field)


def txf():
    return TX_MSG_FIELDS


def txfs():
    return TX_SERVICE_MSG_FIELDS


def msgo(msg):
    from utils import b, MSG_TYPE_TX, MSG_TYPE_UNSPENT_TX
    #importUtils()
    #print('MSG_TYPE_TX', MSG_TYPE_TX)
    msg_type_index = msgi(mp.unpackb(msg), "msg_type")
    try:
        if type(msg) is bytearray:
            msg = mp.unpackb(msg)
        if msg[msg_type_index] == b(MSG_TYPE_TX):
            msg_obj = {}
            keys = txf()
            #print('keys', keys)
            #print('len keys&values', len(keys) == len(msg), len(keys), len(msg))
            for i, v in enumerate(keys):
                #print(i, v, type(msg[i]))
                msg_obj[keys[i]] = msg[i]
            #print('msg_obj', msg_obj)
            return msg_obj
    except:
        return None


def msgf(msg):
    from utils import b, MSG_TYPE_TX, MSG_TYPE_UNSPENT_TX
    #importUtils()
    #print('MSG_TYPE_TX', MSG_TYPE_TX)
    try:
        if msg[4] == b(MSG_TYPE_TX):
            msg_obj = {}
            keys = txf()
            #print('keys', keys)
            print('len keys&values', len(keys) == len(msg), len(keys), len(msg))
            for i, v in enumerate(keys):
                print(i, v, type(msg[i]))
                msg_obj[keys[i]] = msg[i]
            print('msg_obj', msg_obj)
            return txf()
    except:
        return None


def msgv(msg, field):
    try:
        if msg[1] == MSG_TYPE_TX:
            return msg[-1][txi(field)], txf()
    except:
        return None
    #return msg[txi(field)]


def validateMsg(bin_msg):
    from utils import b, MSG_TYPE_TX, MSG_TYPE_UNSPENT_TX
    umsg = mp.unpackb(bin_msg)
    #print('umsg', umsg)
    fields = msgf(umsg)
    #print('fields', len(fields), fields)

    #df = pandas.read_csv(bin_msg, header=None, names=fields)
    #df = pd.DataFrame(umsg, columns=fields, index=) #, dtype=bytes)
    #print('df', df)
    pass



#TODO to remove later
def test(value=''):
    print('v1 test, value %s' % value)


def verifyTX(tx_msg):
      #if not isDBvalue(b'GENESIS', DEFAULT_DB)
      pass


def validateTX(bin_tx_msg):
    if not tx_msg['ver_num'].strip == '1' or tx[MSG_TYPE_TX]:
        return


if __name__ == "__main__":
    project_dir = os.path.dirname(os.path.abspath(__file__))
    imp = os.path.join(project_dir, "utils")
    print(imp)
    import imp
    print(txi('ts'))
    #print(msgv('TX-', 'ts'))
    print(MSG_TYPE_TX)