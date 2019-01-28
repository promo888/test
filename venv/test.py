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


#from v.v1 import Version
# Version.p('static print')
from v import *
v1.Tools.p('static print')
v1.Tools().p('instance print')
getattr(v1.Tools, 'p')('PrintFromString')
cls = globals()['v1']
func = getattr(cls.Tools, 'p')
func('Class Static Print from String')
func = getattr(cls.Tools, 'pp')
func(func, 'Class Instance Print from String')
print(v1.Tools().TX_MSG_FIELDS)


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
msg_fields_tx = ['ver_num', 'msg_type', 'msg_hash', 'msg', 'sig_type', 'sigs', 'input_txs', 'pub_keys', 'to_addr', 'asset_type', 'amounts', 'ts'] #order & fields are handled by ver_num
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
assert vk.verifySig(signature, msg)

#timeit
import time
start = time.time()
duration_secs = 1
count = 0
while time.time() - start < duration_secs:
    valid = vk.verifySig(signature, msg)
    count += 1
print('%s Regular ECDSA sigs verified within %s secs' % (count, duration_secs))

print('#############################BEEM/STEEM############################')
# This Python file uses the following encoding: utf-8
# from __future__ import absolute_import
# from __future__ import division
# from __future__ import print_function
# from __future__ import unicode_literals
import hashlib
import ecdsa
from binascii import hexlify, unhexlify
from beemgraphenebase.account import PrivateKey, PublicKey, Address
import beemgraphenebase.ecdsasig as ecda
from beemgraphenebase.py23 import py23_bytes


class Benchmark(object):
    goal_time = 10


class ECDSA(Benchmark):
    def setup(self):
        ecda.SECP256K1_MODULE = "ecdsa"

    def time_sign(self):
        wif = "5J4KCbg1G3my9b9hCaQXnHSm6vrwW9xQTJS6ZciW2Kek7cCkCEk"
        message = '576b2c99564392ed50e36c80654224953fdf8b5259528a1a4342c19be2da9b133c44429ac2be4d5dd588ec28e97015c34db80b7e8d8915e023c2501acd3eafe0'
        signature = ecda.sign_message(message, wif)
        message = 'foo'
        signature = ecda.sign_message(message, wif)
        message = 'This is a short Message'
        signature = ecda.sign_message(message, wif)
        message = '1234567890'
        signature = ecda.sign_message(message, wif)

    def time_verify(self):
        message = '576b2c99564392ed50e36c80654224953fdf8b5259528a1a4342c19be2da9b133c44429ac2be4d5dd588ec28e97015c34db80b7e8d8915e023c2501acd3eafe0'
        signature = b' S\xef\x14x\x06\xeb\xba\xc5\xf9\x0e\xac\x02pL\xbeLO;\x1d"$\xd7\xfc\x07\xfb\x9c\x08\xc5b^\x1e\xec\x19\xb1y\x11\np\xec(\xc9\xf3\xfd\x1f~\xe3\x99\xe8\xc98]\xd3\x951m${\x82\x0f[(\xa9\x90#'
        pubkey = ecda.verify_message(message, signature)
        start = time.time()
        duration_secs = 1
        count = 0
        while time.time() - start < duration_secs:
            valid = ecda.verify_message(message, signature)
            count += 1
        print('%s ECDSA.time_verify sigs verified within %s secs' % (count, duration_secs))
        signature = b' W\x83\xe5w\x8f\x07\x19EV\xba\x9d\x90\x9f\xfd \x81&\x0f\xa1L\xa00zK0\x08\xf78/\x9d\x0c\x06JFx[*Z\xfe\xd1F\x8d\x9f \x19\xad\xd9\xc9\xbf\xd3\x1br\xdd\x8e\x8ei\xf8\xd2\xf40\xad\xc6\x9c\xe5'
        message = 'foo'
        pubkey = ecda.verify_message(message, signature)
        signature = b'\x1f9\xb6_\x85\xbdr7\\\xb2N\xfb~\x82\xb7E\x80\xf1M\xa4EP=\x8elJ\x1d[t\xab%v~a\xb7\xdbS\x86;~N\xd2!\xf1k=\xb6tMm-\xf1\xd9\xfc\xf3`\xbf\xd5)\x1b\xb3N\x92u/'
        message = 'This is a short Message'
        pubkey = ecda.verify_message(message, signature)
        message = '1234567890'
        signature = b' 7\x82\xe2\xad\xdc\xdb]~\xd6\xa8J\xdc\xa5\xf4\x13<i\xb9\xc0\xdcEc\x10\xd0)t\xc7^\xecw\x05 U\x91\x0f\xa2\xce\x04\xa1\xdb\xb0\nQ\xbd\xafP`\\\x8bb\x99\xcf\xe0;\x01*\xe9D]\xad\xd9l\x1f\x05'
        pubkey = ecda.verify_message(message, signature)
        #print('ECDSA.time_verify')


class Cryptography(Benchmark):
    def setup(self):
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.asymmetric.utils \
                import decode_dss_signature, encode_dss_signature
            from cryptography.exceptions import InvalidSignature
            ecda.SECP256K1_MODULE = "cryptography"
        except ImportError:
            raise NotImplementedError("cryptography not available")

    def time_sign(self):
        wif = "5J4KCbg1G3my9b9hCaQXnHSm6vrwW9xQTJS6ZciW2Kek7cCkCEk"
        message = '576b2c99564392ed50e36c80654224953fdf8b5259528a1a4342c19be2da9b133c44429ac2be4d5dd588ec28e97015c34db80b7e8d8915e023c2501acd3eafe0'
        signature = ecda.sign_message(message, wif)
        message = 'foo'
        signature = ecda.sign_message(message, wif)
        message = 'This is a short Message'
        signature = ecda.sign_message(message, wif)
        message = '1234567890'
        signature = ecda.sign_message(message, wif)

    def time_verify(self):
        message = '576b2c99564392ed50e36c80654224953fdf8b5259528a1a4342c19be2da9b133c44429ac2be4d5dd588ec28e97015c34db80b7e8d8915e023c2501acd3eafe0'
        signature = b' S\xef\x14x\x06\xeb\xba\xc5\xf9\x0e\xac\x02pL\xbeLO;\x1d"$\xd7\xfc\x07\xfb\x9c\x08\xc5b^\x1e\xec\x19\xb1y\x11\np\xec(\xc9\xf3\xfd\x1f~\xe3\x99\xe8\xc98]\xd3\x951m${\x82\x0f[(\xa9\x90#'
        pubkey = ecda.verify_message(message, signature)
        start = time.time()
        duration_secs = 1
        count = 0
        while time.time() - start < duration_secs:
            valid = ecda.verify_message(message, signature)
            count += 1
        print('%s Cryptography.time_verify sigs verified within %s secs' % (count, duration_secs))
        signature = b' W\x83\xe5w\x8f\x07\x19EV\xba\x9d\x90\x9f\xfd \x81&\x0f\xa1L\xa00zK0\x08\xf78/\x9d\x0c\x06JFx[*Z\xfe\xd1F\x8d\x9f \x19\xad\xd9\xc9\xbf\xd3\x1br\xdd\x8e\x8ei\xf8\xd2\xf40\xad\xc6\x9c\xe5'
        message = 'foo'
        pubkey = ecda.verify_message(message, signature)
        signature = b'\x1f9\xb6_\x85\xbdr7\\\xb2N\xfb~\x82\xb7E\x80\xf1M\xa4EP=\x8elJ\x1d[t\xab%v~a\xb7\xdbS\x86;~N\xd2!\xf1k=\xb6tMm-\xf1\xd9\xfc\xf3`\xbf\xd5)\x1b\xb3N\x92u/'
        message = 'This is a short Message'
        pubkey = ecda.verify_message(message, signature)
        message = '1234567890'
        signature = b' 7\x82\xe2\xad\xdc\xdb]~\xd6\xa8J\xdc\xa5\xf4\x13<i\xb9\xc0\xdcEc\x10\xd0)t\xc7^\xecw\x05 U\x91\x0f\xa2\xce\x04\xa1\xdb\xb0\nQ\xbd\xafP`\\\x8bb\x99\xcf\xe0;\x01*\xe9D]\xad\xd9l\x1f\x05'
        pubkey = ecda.verify_message(message, signature)


class Secp256k1(Benchmark):
    def setup(self):
        try:
            import secp256k1
            ecda.SECP256K1_MODULE = "secp256k1"
        except ImportError:
            raise NotImplementedError("secp256k1 not available")

    def time_sign(self):
        wif = "5J4KCbg1G3my9b9hCaQXnHSm6vrwW9xQTJS6ZciW2Kek7cCkCEk"
        message = '576b2c99564392ed50e36c80654224953fdf8b5259528a1a4342c19be2da9b133c44429ac2be4d5dd588ec28e97015c34db80b7e8d8915e023c2501acd3eafe0'
        signature = ecda.sign_message(message, wif)
        message = 'foo'
        signature = ecda.sign_message(message, wif)
        message = 'This is a short Message'
        signature = ecda.sign_message(message, wif)
        message = '1234567890'
        signature = ecda.sign_message(message, wif)

    def time_verify(self):
        message = '576b2c99564392ed50e36c80654224953fdf8b5259528a1a4342c19be2da9b133c44429ac2be4d5dd588ec28e97015c34db80b7e8d8915e023c2501acd3eafe0'
        signature = b' S\xef\x14x\x06\xeb\xba\xc5\xf9\x0e\xac\x02pL\xbeLO;\x1d"$\xd7\xfc\x07\xfb\x9c\x08\xc5b^\x1e\xec\x19\xb1y\x11\np\xec(\xc9\xf3\xfd\x1f~\xe3\x99\xe8\xc98]\xd3\x951m${\x82\x0f[(\xa9\x90#'
        pubkey = ecda.verify_message(message, signature)
        start = time.time()
        duration_secs = 1
        count = 0
        while time.time() - start < duration_secs:
            valid = ecda.verify_message(message, signature)
            count += 1
        print('%s Sec256k1.time_verify sigs verified within %s secs' % (count, duration_secs))
        signature = b' W\x83\xe5w\x8f\x07\x19EV\xba\x9d\x90\x9f\xfd \x81&\x0f\xa1L\xa00zK0\x08\xf78/\x9d\x0c\x06JFx[*Z\xfe\xd1F\x8d\x9f \x19\xad\xd9\xc9\xbf\xd3\x1br\xdd\x8e\x8ei\xf8\xd2\xf40\xad\xc6\x9c\xe5'
        message = 'foo'
        pubkey = ecda.verify_message(message, signature)
        signature = b'\x1f9\xb6_\x85\xbdr7\\\xb2N\xfb~\x82\xb7E\x80\xf1M\xa4EP=\x8elJ\x1d[t\xab%v~a\xb7\xdbS\x86;~N\xd2!\xf1k=\xb6tMm-\xf1\xd9\xfc\xf3`\xbf\xd5)\x1b\xb3N\x92u/'
        message = 'This is a short Message'
        pubkey = ecda.verify_message(message, signature)
        message = '1234567890'
        signature = b' 7\x82\xe2\xad\xdc\xdb]~\xd6\xa8J\xdc\xa5\xf4\x13<i\xb9\xc0\xdcEc\x10\xd0)t\xc7^\xecw\x05 U\x91\x0f\xa2\xce\x04\xa1\xdb\xb0\nQ\xbd\xafP`\\\x8bb\x99\xcf\xe0;\x01*\xe9D]\xad\xd9l\x1f\x05'
        pubkey = ecda.verify_message(message, signature)



ECDSA().time_verify()
Cryptography().time_verify()
Secp256k1().time_verify()

