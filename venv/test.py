#http://pypi.org/project/fastecdsa
# import hashlib
# import ecdsa
# import Crypto
# import fastecdsa

#import tensorflow
#import keras

#/home/igorb/PycharmProjects/test
import sys, os, multiprocessing, subprocess, asyncio, aiohttp
import leveldb
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
print('ROOT_DIR', ROOT_DIR)
TXS_DB = './../%s/TXS' % ROOT_DIR
UTXS_DB = './../%s/UTXS' % ROOT_DIR
VOTES_DB = './../%s/VOTES' % ROOT_DIR
BLOCKS_DB = './../%s/BLOCKS' % ROOT_DIR
CONTRACTS_DB = './../%s/CONTRACTS' % ROOT_DIR
print('CONTRACTS_DB', CONTRACTS_DB)

DEFAULT_DB = './../db'
leveldb.DestroyDB(DEFAULT_DB)
db = leveldb.LevelDB(DEFAULT_DB)
db.Put(b'key 1', b'value 2')
print(db.Get(b'key 1'))
#print(db.Get(b'key NOT_EXIST'))
print(dir(db))
print(dir(leveldb))


import datetime, time
from fastecdsa import curve, ecdsa, keys
from fastecdsa.keys import export_key, import_key
from fastecdsa.curve import P256
from fastecdsa.point import Point
#from hashlib import sha256
m = 'Message to sign with ECDSA'
private_key, public_key = keys.gen_keypair(curve.P256)


def isDBvalue(bin_key, db_path):
    try:
        if db is None:
            db = leveldb.LevelDB(db_path) #Once init held by the process
        value = db.Get(bin_key)
        #print('isDBvalue value', value, type(value))
        return True #value
    except Exception as e:
        #TODO logger
        #print('Exception isDbValue: ', e)
        return False

print(isDBvalue(b'key 1', DEFAULT_DB), isDBvalue(b'key 1', DEFAULT_DB) is True)
print(isDBvalue(b'GENESIS', DEFAULT_DB), isDBvalue(b'GENESIS', DEFAULT_DB) is False)

def insertGenesis(): #TODO onStartNode
    tx_db = leveldb.LevelDB(TXS_DB)

import time #todo change to utc time
from Crypto.Hash import SHA256
#import hashlib

def to_sha256(to_str):
    return SHA256.new(str(to_str).encode('utf8')).hexdigest()
    #m = hashlib.sha256()
    #m.update(str(to_str).encode('utf8'))
    #return m.hexdigest()

def to_md5(to_str):
    m = hashlib.md5()
    m.update(b'hello') #(str(to_str).encode('utf8'))
    return m.hexdigest()

def utc():
    return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')

##export_key(private_key, curve=P256, filepath='prk3')
##export_key(public_key, curve=P256, filepath='pbk3')
prk, pbk = import_key('prk1') #both keys are dervide from the private key
prk1, pbk1 = import_key('pbk1') # non prk derived from public key
r, s = ecdsa.sign(m, prk) #, curve=curve.P256, hashfunc=sha256) #default curve=P256
print('r, s: ', r, s, type(r), type(s))
valid = ecdsa.verify((r, s), m, pbk1, hashfunc=ecdsa.sha256) #default curve=P256
print('valid imported ecdsa sig', valid, pbk == pbk1, pbk1, 'addr', to_sha256(pbk1), type(pbk1))
merkle_date = '01-01-2018 00:00:00.000'
#genesis_tx = {'from_addr': 'GENESIS', 'to_addr': to_sha256(pbk1), 'asset_type': '1', 'amount': 10000000000, 'input_tx': 'GENESIS', 'ts': merkle_date}
msg_fields_tx = ['ver_num', 'msg_type', 'msg_hash', 'msg', 'sig_type', 'sigs', 'input_txs', 'pub_keys', 'to_addr', 'asset_type', 'amount', 'ts'] #order & fields are handled by ver_num
#genesis_tx = ('1', 'TX_', '1/1', '[%s %s]' % (r, s), ' [GENESIS]', 'GENESIS', to_sha256(pbk1), '1', 10000000000, merkle_date)
genesis_tx = ['1', 'TX_', '1/1', '[%s %s]' % (r, s), '[GENESIS]', '[%s %s]' % (pbk1.x, pbk.y), to_sha256(str(pbk1.x)+str(pbk1.y)), '1', 10000000000, merkle_date] #from_addre sha256(pubkey)
print('GENESIS TX', genesis_tx)
print('GENESIS hash', to_sha256(str(genesis_tx)), type(to_sha256(str(genesis_tx))))
#print((genesis_tx.values())) not ordered
msg_fields = ['%s' % t for t in msg_fields_tx]
print('msg_fields', len(msg_fields), str(msg_fields) == str(msg_fields_tx), msg_fields)
genesis_msg_tx = ('1/1', '[%s %s]' % (r, s), '[GENESIS]', '[%s %s]' % (pbk1.x, pbk.y), to_sha256(str(pbk1.x)+str(pbk1.y)), '1', 10000000000, merkle_date)
genesis_msg =  ('1', 'TX_', to_sha256(str(genesis_msg_tx)), genesis_msg_tx)
print('GENESIS MSG', genesis_msg, '\nGENESIS MSG_TX', str(genesis_msg[3]))
r, s = ecdsa.sign(str(genesis_msg[3]), prk)
#########TODO msg_hash -> output_tx




input_txs = genesis_tx[4].strip(' ').replace('[', '').replace(']', '').split(',')
print(input_txs)
x, y = genesis_tx[5].strip(' ').replace('[', '').replace(']', '').split(' ')
pb_k = Point(int(x), int(y))
print('pb_k', pb_k)

x, y = genesis_tx[3].strip(' ').replace('[', '').replace(']', '').split(' ')
print('x, y: ', x, y, type(x), type(y), int(x) == r, int(y) == s)
#msg_point = Point(int(x), int(y), curve=P256)
valid = ecdsa.verify((int(x), int(y)), m, pb_k, hashfunc=ecdsa.sha256) #default curve=P256
print('valid split ecdsa sig', valid)


r, s = ecdsa.sign(m, private_key) #, curve=curve.P256, hashfunc=sha256) #default curve=P256
valid = ecdsa.verify((r, s), m, public_key, hashfunc=ecdsa.sha256) #default curve=P256
print('valid ecdsa sig', valid)
print(len(str(private_key)), len(str(public_key)), len(str(r)), len(str(r)))
print('private_key', (str(private_key)))
print('public_key', (str(public_key)))

#timeit
import time
start = time.time()
duration_secs = 1
count = 0
while time.time() - start < duration_secs:
    valid = ecdsa.verify((r, s), m, public_key, hashfunc=ecdsa.sha256)
    count += 1
print('%s Fast ECDSA sigs verified within %s secs' % (count, duration_secs))


from ecdsa import SigningKey, NIST256p # Default NIST192p
sk = SigningKey.generate(curve=NIST256p, hashfunc=ecdsa.sha256) # Default NIST192p
vk = sk.get_verifying_key()
msg = "Message to sign with ECDSA".encode("ascii")
signature = sk.sign(msg)
print(len(str(sk)), len(str(vk)), len(str(signature)))
print((str(sk)), (str(vk)), (str(signature)))
assert vk.verify(signature, msg)

#timeit
import time
start = time.time()
duration_secs = 1
count = 0
while time.time() - start < duration_secs:
    valid = vk.verify(signature, msg)
    count += 1
print('%s Regular ECDSA sigs verified within %s secs' % (count, duration_secs))