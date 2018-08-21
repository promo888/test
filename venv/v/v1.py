import os
import datetime
import time
from collections import OrderedDict
import msgpack as mp, pandas as pd

project_dir = os.path.dirname(os.path.abspath(__file__))
imp = os.path.join(project_dir, "utils")
import imp

TX_MSG_FIELDS_PENDING = ('ver_num', 'msg_type', 'msg_hash', 'msg')
TX_MSG_FIELDS = ('ver_num', 'msg_type', 'sig_type', 'sigs', 'pub_keys', 'input_txs', 'to_addr', 'asset_type', 'amount', 'ts')
TX_SERVICE_MSG_FIELDS = ['ver_num', 'msg_type', 'msg_hash', 'msg', 'created_at date']
UNSPENT_TX_MSG_FIELDS = ()
BLOCK_MSG_FIELDS = ()
CONTRACT_MSG_FIELDS = ()


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
            return res[0][0]-1
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


def msgf(msg):
    from utils import b, MSG_TYPE_TX, MSG_TYPE_UNSPENT_TX
    #importUtils()
    #print('MSG_TYPE_TX', MSG_TYPE_TX)
    try:
        if msg[1] == b(MSG_TYPE_TX):
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
    print('umsg', umsg)
    fields = msgf(umsg)
    print('fields', len(fields), fields)

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