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
            if validateTX(msg_obj) is None:
                return None
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
            #print('len keys&values', len(keys) == len(msg), len(keys), len(msg))
            for i, v in enumerate(keys):
                #print(i, v, type(msg[i]))
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
      from utils import getLogger, utc, logp, exc_info, SERVICE_DB, DB, getServiceDB, getDB

      pass

def validateDateFormat(str):
    try:
        datetime.datetime.strptime(str, '%d-%m-%Y %H:%M:%S.%f')

        return True
    except:
        return False


def validateTX(tx_msg):
    #if not tx_msg['ver_num'].strip == '1' or tx[MSG_TYPE_TX]:
    #    return
    keys_types = {'ver_num': str, 'sigs': list, 'sig_type': str, 'pub_keys': list, 'msg_type': str, 'input_txs': list,
                  'to_addr': str, 'asset_type': str, 'amount': int, 'ts': str}
    keys_amount = len(keys_types)
    #ToDo num/num and correct inside values
    # if len(keys_types) != len(tx_msg)
    #     return False
    #
    assert type(tx_msg is dict)
    assert len(keys_types) == len(tx_msg)
    assert len([k for k in keys_types.keys() if k not in tx_msg.keys()]) == 0
    assert len([k for k in tx_msg.keys() if k not in keys_types.keys()]) == 0
    for k in keys_types.keys():
        value_type = type(tx_msg[k].decode('utf8')) if type(tx_msg[k]) is bytes else type(tx_msg[k])
        #print(k, value_type == keys_types[k], keys_types[k], value_type)
        if (value_type != keys_types[k]):
            print(k, "VALIDATION Failed")
            return False
    if not validateDateFormat(tx_msg['ts']):
        return False
    return True

#from utils import SERVICE_DB, NODE_SERVICE_DB, exc_info, logging, logp, utc, packb, unpackb
def insertServiceDbPending(bin_msg_list):
    from utils import SERVICE_DB, exc_info, logging, logp, utc, packb, unpackb
    try:
        queries_list = ()
        keys_list = ()
        values_list = ()
        if SERVICE_DB is None:
            SERVICE_DB = sqlite3.connect(NODE_SERVICE_DB, isolation_level=None)
            logp("Connected to ServiceDB", logging.INFO)
        SERVICE_DB.execute('BEGIN;')
        for msg in bin_msg_list:
            version_msg = msgo(msg)
            #print('version_msg', version_msg)

            if version_msg is None: #Ommit the message if incorrect version or isNotValid version format
                continue
            ###TODO validations

            ###

            query = 'INSERT INTO pending_tx '
            keys = ()
            values = ()
            for k in version_msg.keys():
                keys += (k,)
                values += (version_msg[k],)
            keys += ('node_date',)
            dti = utc() #TODO to thinkk change for ts (time.time() ,9bytes instead 27 + clients_ts  = ~40 bytes per record, 16b in LevelDB time.time()
            values += (dti,)
            #print('kv', keys, values)
            query += ' (' + ",".join([k for k in keys]) + ') values (' + ('?,' * len(keys))[:-1] + ")"
            #print('query', query, values)
            SERVICE_DB.execute(query, [sqlite3.Binary(packb(v)) for v in values])
            queries_list += (query,)
            keys_list += (keys,)
            values_list += (([sqlite3.Binary(packb(v)) for v in values]),)
        SERVICE_DB.commit()
        return True
    except Exception as ex:
        err_msg = 'Exception on Insert (%s) to SqlLite NODE_SERVICE_DB:  %s, %s' % (bin_msg_list, ex, exc_info())
        SERVICE_DB.rollback()
        logp(err_msg, logging.ERROR)
        return None


if __name__ == "__main__":
    project_dir = os.path.dirname(os.path.abspath(__file__))
    imp = os.path.join(project_dir, "utils")
    print(imp)
    import imp
    print(txi('ts'))
    #print(msgv('TX-', 'ts'))
    print(MSG_TYPE_TX)