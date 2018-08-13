import leveldb
import datetime, time
from fastecdsa import curve, ecdsa, keys
from fastecdsa.keys import export_key, import_key
from fastecdsa.curve import P256
from fastecdsa.point import Point
from Crypto.Hash import SHA256




from utils import * #MSG_TYPE_TX



def test(value=''):
    print('v1 test, value %s' % value)


def verifyTX(tx_msg):
      #if not isDBvalue(b'GENESIS', DEFAULT_DB)
      pass


def validateTX(bin_tx_msg):
    if not tx_msg['ver_num'].strip == '1' or tx[MSG_TYPE_TX]:
        return
