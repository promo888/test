import os
import datetime
import time
from collections import OrderedDict
import msgpack as mp, ast, pandas as pd
import sqlite3, json


project_dir = os.path.dirname(os.path.abspath(__file__))
imp = os.path.join(project_dir, "utils")
import imp

TX_MSG_FIELDS_PENDING = ('ver_num', 'msg_type', 'msg_sig', 'msg')
TX_MSG_FIELDS = ('ver_num', 'msg_type', 'sigs', 'sig_type', 'pub_keys', 'input_txs', 'output_txs', 'from_addr', 'to_addr', 'asset_type', 'amount', 'ts')
TX_MSG = ('tx_num', {'tx_hash': 'UPDATE', 'data': TX_MSG_FIELDS})
#TX_MULTI_MSG_FIELDS = ('pub_keys', 'sigs', 'sigs_type', 'ver_num', 'msg_type', 'input_txs', 'to_addr', 'asset_type', 'amount', 'ts') #pub_keys & sigs are array in multi_tx
TX_SERVICE_MSG_FIELDS = TX_MSG_FIELDS + ("node_date",)
#TX_MSG_FIELDS += ("node_date") # Overriden by each node onMsgAccept #['ver_num', 'msg_type', 'msg_hash', 'msg', 'created_at date']
UNSPENT_TX_MSG_FIELDS = ()
BLOCK_MSG_FIELDS = ('ver_num', 'block_num', 'prev_block_hash', 'input_tx_list')
BLOCK_MSG = ('block_num', {'block_hash': 'UPDATE', 'data': BLOCK_MSG_FIELDS})
CONTRACT_MSG_FIELDS = ()
MSG_TYPES = {'TX_SINGLE': 1, 'TX_MULTI': 2, 'TX_CONTRACT': 3}

# BlockMsgFields (verNum, blockNumber, PreviousBlockHash, input_tx_list)
# BlockMsg (blockNumber, block_hash, block_msg)

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
        res = [(i, v) for i, v in enumerate(TX_MSG_FIELDS) if v == field]
        #if res.__len__() == 0: #4 array
        if len(res) == 0:
            return None
        else:
            return res[0][0]
    except:
        return None

def txi(field):
    return getTxMsgFieldIndex(field)


def msgi(msg, field):
    from utils import MSG_TYPE_TX, MSG_TYPE_UNSPENT_TX, MSG_TYPE_CONTRACT, MSG_TYPE_BLOCK
    if type(msg) is dict or tuple and msg[-1][1] == MSG_TYPE_TX or msg[1] == MSG_TYPE_TX or msg[b'data'][txi("msg_type")] == b(MSG_TYPE_TX):
        return getTxMsgFieldIndex(field)
    else:
        return None
    #return txi(field)


def txf():
    return TX_MSG_FIELDS



def txfs():
    return TX_SERVICE_MSG_FIELDS


def msgo(bin_msg):
    from utils import b, MSG_TYPE_TX, MSG_TYPE_UNSPENT_TX
    #importUtils()
    #print('MSG_TYPE_TX', MSG_TYPE_TX)
    #msg_type_index = msgi(mp.unpackb(msg), "msg_type")
    try:
        msg_type = mp.unpackb(bin_msg)[b'data'][1] #msgi(mp.unpackb(msg), "msg_type")
        if type(bin_msg) is bytearray:
            msg = mp.unpackb(bin_msg)[b'data']
        if msg_type == b(MSG_TYPE_TX):
            msg_obj = {}
            keys = txf()
            #print('keys', keys)
            #print('len keys&values', len(keys) == len(msg), len(keys), len(msg))
            for i, v in enumerate(keys):
                #print(i, v, type(msg[i]))
                msg_obj[keys[i]] = msg[i]
            #print('msg_obj', msg_obj)
            if not validateTX(msg_obj) or validateTX(msg_obj) is None:
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
        datetime.datetime.strptime(str.decode('utf8'), '%d-%m-%Y %H:%M:%S.%f')

        return True
    except:
        return False


def validateTX(tx_msg):
    #if not tx_msg['ver_num'].strip == '1' or tx[MSG_TYPE_TX]:
    #    return
    keys_types = {'ver_num': str, 'sigs': list, 'sig_type': str, 'pub_keys': list, 'msg_type': str, 'input_txs': list,
                  'output_txs': list, 'from_addr': str, 'to_addr': str, 'asset_type': str, 'amount': float, 'ts': str}
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

    from utils import b, to_sha256, SERVICE_DB, getServiceDB, DB, getDB, isDBvalue, packb, unpackb, MSG_TYPE_TX, MSG_TYPE_UNSPENT_TX
    if isDBvalue(b(MSG_TYPE_TX + to_sha256(tx_msg)), DB) is None or \
        len(getServiceDB("select * from pending_tx where tx_hash='%s%s'" % (MSG_TYPE_TX, to_sha256(tx_msg)))) > 0:
        print('%s Exist in DB - Ignore...' % (MSG_TYPE_TX + to_sha256(tx_msg)))
        rmsg = getServiceDB("select %s from pending_tx where tx_hash='%s%s'" % (",".join(TX_MSG_FIELDS), MSG_TYPE_TX, to_sha256(tx_msg)))
        rd = dict(zip(TX_MSG_FIELDS, rmsg[0])) #
        for k in rd:  #
            if type(rd[k]) is str and '[' not in rd[k]:
                rd[k] = b(rd[k])
            if type(rd[k]) is str and '[' in rd[k]:
                lst = rd[k].strip('[]').split(' ') #replace(" ", ",").strip('[]').split(',')
                rd[k] = [b(e) for e in lst]
        return False
    return True
#rmsg = getServiceDB("select %s from pending_tx where tx_hash='%s%s'" % (",".join(TX_MSG_FIELDS), MSG_TYPE_TX, to_sha256(tx_msg)))
#rd = dict(zip(tx_msg.keys(), rmsg[0]))
# for k in rd:
#     if type(rd[k]) is str:
#         rd[k] = b(rd[k])

#from utils import SERVICE_DB, NODE_SERVICE_DB, exc_info, logging, logp, utc, packb, unpackb
def insertServiceDbPending(rec, bin_msg_list):
    from utils import SERVICE_DB, exc_info, logging, logp, to_s, utc, packb, unpackb, to_sha256, MSG_TYPE_TX, MSG_TYPE_UNSPENT_TX #, MSG_TYPE_TX_ACCEPTED_AND_VALID, MSG_TYPE_TX_VERIFIED_AND_PENDING, MSG_TYPE_MULTI_SIG
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
            keys += ('node_date', 'tx_hash')
            dti = utc() #TODO to thinkk change for ts (time.time() ,9bytes instead 27 + clients_ts  = ~40 bytes per record, 16b in LevelDB time.time()
            values += (dti, MSG_TYPE_TX + to_sha256(version_msg))
            #print('kv', keys, values)
            query += ' (' + ",".join([k for k in keys]) + ') values (' + ('?,' * len(keys))[:-1] + ")"

            print('query', query, values)
            ##SERVICE_DB.execute(query, [sqlite3.Binary(packb(v)) for v in values])
            vals = [v if type(v) is str else v.decode('utf8') if type(v) is bytes else str(v) if type(v) is not list else '[' + v[0].decode('utf8') + ']' for v in values]
            SERVICE_DB.execute(query, vals)

            #queries_list += (query,)
            #keys_list += (keys,)
            #values_list += (([sqlite3.Binary(packb(v)) for v in values]),)
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