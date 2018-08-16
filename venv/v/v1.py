import leveldb
import datetime, time
from fastecdsa import curve, ecdsa, keys
from fastecdsa.keys import export_key, import_key
from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto.Hash import SHA256

from utils import * #MSG_TYPE_TX

TX_MSG_FIELDS  = ['ver_num', 'msg_type', 'msg_hash', 'msg', 'sig_type', 'sigs', 'pub_keys', 'input_txs', 'to_addr', 'asset_type', 'amount', 'ts']
TX_SERVICE_MSG_FIELDS = [ 'ver_num', 'msg_type', 'msg_hash', 'msg', 'created_at date']

def utc2():
    return datetime.datetime.utcfromtimestamp(time.time()) #sqllite date -> datetime.datetime

def getTxMsgFieldIndex(field):
    res = [(i,v) for i,v in TX_MSG_FIELDS if v==field]
    if len[res] == 0:
        return None
    else:
        return res[0][0]

def txi(field):
    return getTxMsgFieldIndex(field)

def txf():
    return TX_MSG_FIELDS

def txfs():
    return TX_SERVICE_MSG_FIELDS


#TODO to remove later
def test(value=''):
    print('v1 test, value %s' % value)


def verifyTX(tx_msg):
      #if not isDBvalue(b'GENESIS', DEFAULT_DB)
      pass


def validateTX(bin_tx_msg):
    if not tx_msg['ver_num'].strip == '1' or tx[MSG_TYPE_TX]:
        return
