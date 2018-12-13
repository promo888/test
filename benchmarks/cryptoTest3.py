#https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/RSA.py
#https://www.programcreek.com/python/example/87931/Crypto.PublicKey.RSA.importKey
#2DO - investigate eth blockchain projects with RSA
#https://www.pythonsheets.com/notes/python-crypto.html

#from hashlib import md5
import hashlib
# import rsa
import os, sys, time, datetime
# from base64 import b64encode, b64decode
# from Crypto import Random
# from Crypto.Cipher import AES  # python2 win10
# from cryptography import fernet.AESCipher as AES #python3
from hashlib import sha256
# from Crypto.Hash import SHA256
import binascii
from base64 import b64decode, b64encode
import zlib
from collections import OrderedDict
from itertools import groupby
import struct, base64
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
import json#, ujson
import msgpack

def dt():
  return datetime.datetime.utcfromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S.%f')


# random_generator = Random.new().read #os.urandom(100)
# print('len random_generator', len(str(random_generator)), str(random_generator), type(random_generator))
# key = RSA.generate(4096, random_generator) #2048 #TODO passphrase
# binPrivKey = key.exportKey('DER')
# binPubKey = key.publickey().exportKey('DER')
# with open('private_key_der', 'wb') as prk_file:
#     prk_file.write(binPrivKey)
# with open('public_key_der', 'wb') as prk_file:
#     prk_file.write(binPubKey)
# with open('public_key_n_der', 'w') as prk_file:
#     prk_file.write(str(key.publickey().n))
prk = None
pbk = None
pbk_n = None
pbk_n_str = None
full_path = os.path.realpath(__file__)
file_path = os.path.dirname(full_path)
with open('%s/private_key_pem' % file_path, 'rb') as prk_file:
    prk = prk_file.read()
    print(prk)
with open('%s/public_key_pem' % file_path, 'rb') as pbk_file:
    pbk = pbk_file.read()
    print(pbk)
with open('%s/public_key_n_der' % file_path, 'r') as pbkn_file:
    pbk_n_str = pbkn_file.read()
    pbk_n = int(pbk_n_str)
    print(pbk_n)
privKeyObj = RSA.importKey(prk)
pubKeyObj = privKeyObj.publickey() #RSA.importKey(pbk)
print('Len PRK', len(prk))
print('Len PBK', len(pbk))
print('RSA public_key', type(pubKeyObj.key.n), sys.getsizeof(pubKeyObj.key.n), pubKeyObj, pubKeyObj.key.n)
print('RSA public_key N', type(pbk_n), sys.getsizeof(pbk_n), pbk_n)
print('RSA public_key N str', type(pbk_n_str), sys.getsizeof(pbk_n_str), pbk_n_str)


TX_TYPE_1SIG = '1'
TX_TYPE_MULTISIG = '2'
TX_TYPE_CONTRACT = '3'
CONTRACT_TYPE_ICO = '10'
CONTRACT_TYPE_ICO_USE_BLOCKCHAIN = '11' #use blockchain, miners...


#TODO??? #TTL MultiSig Handled in Wallets ???
tx_type3 = {"ver_num": '1', "tx_type": '-', "tx_date": '-', "contract_type": '-', "asset_type": '-', "amount": '-', "to_addr": '-', "pub_key": 'x' * 800, "sigs": [{"pbk_addr": '-', "pbk_sig": '-'},], "tx_fee": '-'}
tx_type2 = {"ver_num": '1', "tx_type": '-', "tx_date": '-', "asset_type": '-', "amount": '-', "to_addr": '-', "pub_key": 'x' * 800, "sigs": [{"pbk_addr": '-', "pbk_sig": '-'},], "ttl_secs": '-', "tx_fee": '-'}
tx_type1 = {"ver_num": '1', "tx_type": '-', "tx_date": '-', "asset_type": '-', "amount": '-', "to_addr": 'x' * 64, "tx_fee": 'x' * 10 }
tx_msg = tx_type1
tx = {"msg": tx_msg, "msg_hash": 'x' * 64, "pub_key": 'x' * 600, "sig": 'x' * 1300}
print('tx_blank size', sys.getsizeof(tx))
tx['pub_key'] = pbk
print('tx', tx)
#tx_hash = SHA256.new(str(tx).encode('utf-8')).hexdigest()
tx['msg']['tx_type'] = TX_TYPE_1SIG
#tx['msg']['tx_date'] = time.time() #timestamped by server
tx['msg']['asset_type'] = '1'
tx['msg']['amount'] = 1000.123456789
tx['msg']['to_addr'] = '66e978fdad2ce922e700ccc851a51c36'
#tx['msg']['pub_key'] = pbk_n
tx_hash = SHA256.new(str(tx['msg']).encode('utf8')).hexdigest() #hashlib.sha256(str(tx['msg']).encode('utf8')) #TODO md5 or sha1 or sha256 -> collisions, speed,? https://automationrhapsody.com/md5-sha-1-sha-256-sha-512-speed-performance/
#hex_dig = tx_hash.hexdigest() #.hexdigest() digest()
#print('tx_hash', hex_dig)
#tx['msg']['tx_id'] = tx_hash #hex_dig #tx['msg_hash']
tx['msg_hash'] = tx_hash #tx_hash.digest() #hex_dig tx_id

#print('privKeyObj.publickey()', privKeyObj.publickey().key.n)


#https://www.pythonsheets.com/notes/python-crypto.html
def signer(privkey, data):
    rsakey = privkey #RSA.importKey(privkey)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(data)
    return signer.sign(digest) #.hex()

#signature = privKeyObj.sign('test', privKeyObj.publickey().key.n) #pubKeyObj.key.n
##signature = signer(privKeyObj, str(tx['msg']).encode('utf8')) #tx_hash b'test' str(tx[b'msg']).encode('utf8')
##print(sys.getsizeof(signature), len(signature), signature)
##tx['sig'] = signature
##print('Wallet Addr',  hashlib.md5(pbk_n_str.encode('utf8')).hexdigest())

print(json.__file__)
#json_tx = json.dumps(tx)

class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (bytes, bytearray)):
            return obj.decode("UTF8") #ASCII <- or any other encoding of your choice
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, obj)

s = str(tx_hash).encode('utf8')
#signature = signer(privKeyObj, s) #tx_packed str(tx['msg']).encode('utf8')
signature = privKeyObj.sign(s, privKeyObj.publickey().key.n) #pbk_n pubKeyObj.key.n
tx['sig'] = signature
pubKeyObj = RSA.importKey(tx['pub_key'])
print('Verified Signature', pubKeyObj.publickey().verifySig(s, signature), signature) #tx['msg']
print('Verified MsgHash', tx['msg_hash'] == SHA256.new(str(tx['msg']).encode('utf8')).hexdigest())
print('PubKey Wallet Address1', SHA256.new(str(pubKeyObj.publickey()).encode('utf8')).hexdigest())
#print('PubKey Wallet Address2', SHA256.new(str(pubKeyObj.publickey().key.n).encode('utf8')).hexdigest())
print('bytes(tx)', type(str(tx).encode('utf8')), type(str(tx)), sys.getsizeof(str(tx).encode('utf8')), len(str(tx).encode('utf8')))
btx = str(tx).encode('utf8')
print(type((btx)), bytes(btx).decode('utf8') == tx)

tx_msg_json = json.dumps(tx['msg'], cls=JsonEncoder)
print('jsonified', len(str(tx_msg_json)), type(tx_msg_json), tx_msg_json)
tx_msg_jsonb = tx_msg_json.encode('utf8')
print('jsonb', type(tx_msg_jsonb), type(tx_msg_json), tx_msg_jsonb ) #, len(tx_msg_jsonb), type(json.loads(tx_msg_jsonb)['msg']), sys.getsizeof(type(json.loads(tx_msg_jsonb))), json.loads(tx_msg_jsonb)['msg']['ver_num'] == tx['msg']['ver_num'], tx_msg_jsonb)
signature = privKeyObj.sign(tx_msg_jsonb, privKeyObj.publickey().key.n) #pbk_n pubKeyObj.key.n tx_msg_jsonb
tx['sig'] = signature
print('signature', type(signature), sys.getsizeof(signature), signature)
#tx_msg_from_bytes = json.loads(tx_msg_jsonb)
#print('tx_msg_from_bytes', tx_msg_from_bytes)
tx_json = json.dumps(tx, cls=JsonEncoder)
tx_jsonb = tx_json.encode('utf8')
#tx_from_bytes = json.loads(tx_jsonb)
#tx_msg = tx_from_bytes['msg']
print('tx_msg_from_bytes2', type(tx_msg), tx_msg)
#print('tx_jsonb', sys.getsizeof(tx_jsonb), type(tx_msg), type(tx_msg_jsonb), tx_msg == json.loads(tx_msg_jsonb))
signature = privKeyObj.sign(tx_msg_jsonb, privKeyObj.publickey().key.n)
pubKeyObj = RSA.importKey(tx['pub_key']) #tx_msg_from_bytes['pub_key']
print('PubKeys equal', pubKeyObj.publickey() == privKeyObj.publickey(), pubKeyObj.publickey().key.n)
#print('SigFromBytes', type(tx_from_bytes['sig']), tuple(tx_from_bytes['sig']))
#print('Verified Signature', tuple(tx_from_bytes['sig']) == signature, pubKeyObj.publickey().verify(tx_msg_jsonb, tuple(tx_from_bytes['sig'])) ) #tuple(tx_from_bytes['sig'])

#https://stackoverflow.com/questions/20936993/how-can-i-create-a-random-number-that-is-cryptographically-secure-in-python
#https://blog.gisspan.com/2016/04/making-sense-of-ssl-rsa-x509-and-csr.html

#https://gist.github.com/lkdocs/6519372
def verify_sign(public_key_loc, signature, data):
    '''
    Verifies with a public key from whom the data came that it was indeed
    signed by their private key
    param: public_key_loc Path to public key
    param: signature String signature to be verified
    return: Boolean. True if the signature is valid; False otherwise.
    '''
    from Crypto.PublicKey import RSA
    from Crypto.Signature import PKCS1_v1_5
    from Crypto.Hash import SHA256
    from base64 import b64decode
    pub_key = open(public_key_loc, "r").read()
    rsakey = RSA.importKey(pub_key)
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    # Assumes the data is base64 encoded to begin with
    digest.update(b64decode(data))
    if signer.verifySig(digest, b64decode(signature)):
        return True
    return False

#https://github.com/warner/python-ecdsa
# from fastecdsa import curve, ecdsa, keys
# from hashlib import sha3_256
# private_key, public_key = keys.gen_keypair(curve.P256)
# r, s = ecdsa.sign(m, private_key, hashfunc=sha3_256)
# valid = ecdsa.verify((r, s), m, public_key, hashfunc=sha3_256)

#https://github.com/warner/python-ecdsa
# NIST192p: siglen= 48, keygen=0.160s, sign=0.058s, verify=0.116s
# NIST224p: siglen= 56, keygen=0.230s, sign=0.086s, verify=0.165s
# NIST256p: siglen= 64, keygen=0.305s, sign=0.112s, verify=0.220s
# NIST384p: siglen= 96, keygen=0.801s, sign=0.289s, verify=0.558s
# NIST521p: siglen=132, keygen=1.582s, sign=0.584s, verify=1.152s
#For comparison, a quality C++ implementation of ECDSA (Crypto++) typically computes a NIST256p signature in 2.88ms and a verification in 8.53ms

#https://pypi.org/project/fastecdsa/ #1000 sigGen+sigVerify in 6secs

import sqlite3
conn = sqlite3.connect('test.db')
print ("Opened sqlite3 database successfully")

import ecdsa
print(dir(ecdsa))
# print(help(ecdsa.Private_key))
# print(help(ecdsa.Public_key))
# print(help(ecdsa.Signature))

#https://github.com/AntonKueltz/fastecdsa/issues/3

#https://jeremykun.com/tag/rsa/ #ecdsa

#bitcoin
#https://medium.com/verifyas/the-process-of-bitcoins-transactions-38cda18a2a83
#https://en.bitcoin.it/wiki/Transaction
#https://bitcoin.stackexchange.com/questions/37397/where-is-the-utxo-data-stored
#https://coinsutra.com/unspent-transaction-outputs-utxos/
#https://gist.github.com/gavinandresen/3966071 #multisig
#https://en.bitcoin.it/wiki/Multisignature
#https://medium.com/@lopp/the-challenges-of-optimizing-unspent-output-selection-a3e5d05d13ef
#
#
#
#


##################
from fastecdsa import curve, ecdsa
from hashlib import sha256,sha384, sha512
m = "a message to sign via ECDSA"  # some message

''' use default curve and hash function (P256 and SHA2) '''
# private_key, public_key = ecdsa.gen_keypair()
# # standard signature, returns two integers
# r, s = ecdsa.sign(m, private_key)
# # should return True as the signature we just generated is valid.
# valid = ecdsa.verify((r, s), m, public_key)

# ''' specify a different curve to use with ECDSA '''
# private_key, public_key = ecdsa.gen_keypair(curve=curve.P224)
# r, s = ecdsa.sign(m, private_key, curve=curve.P224)
# valid = ecdsa.verify((r, s), m, public_key, curve=curve.P224)

''' specify a different hash function to use with ECDSA '''
# private_key, public_key = ecdsa.gen_keypair()
# r, s = ecdsa.sign(m, private_key, hashfunc=sha256)
# valid = ecdsa.verify((r, s), m, public_key, hashfunc=sha256)

# ''' specify a different hash function to use with ECDSA '''
# private_key, public_key = ecdsa.gen_keypair()
# r, s = ecdsa.sign(m, private_key, hashfunc=sha384)
# valid = ecdsa.verify((r, s), m, public_key, hashfunc=sha384)
#################

#from ecdsa import SigningKey #* #SigningKey
# # SECP256k1 is the Bitcoin elliptic curve
# sk = SigningKey.generate(curve=ecdsa.SECP256k1)
# vk = sk.get_verifying_key()
# sig = sk.sign(b"message")
# vk.verify(sig, b"message") # True
#
# from ecdsa import VerifyingKey
# message = b"message"
# public_key = '98cedbb266d9fc38e41a169362708e0509e06b3040a5dfff6e08196f8d9e49cebfb4f4cb12aa7ac34b19f3b29a17f4e5464873f151fd699c2524e0b7843eb383'
# sig = '740894121e1c7f33b174153a7349f6899d0a1d2730e9cc59f674921d8aef73532f63edb9c5dba4877074a937448a37c5c485e0d53419297967e95e9b1bef630d'
#
# vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=ecdsa.SECP256k1)
# vk.verify(bytes.fromhex(sig), message) # True

#DSA Random RNG is vulnerable
#https://www.cryptologie.net/article/315/how-to-check-if-a-binary-contains-the-dual-ec-backdoor-for-the-nsa/
# from cryptography.hazmat.primitives import hashes
# signature2 = privKeyObj.sign(tx_msg_jsonb, hashes.SHA256())
# print('signature2', len(str(signature2)), signature == signature2, signature2)


#dsa
#https://www.pythonsheets.com/notes/python-crypto.html
# import socket
#
# from cryptography.exceptions import InvalidSignature
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import dsa
#
# alice, bob = socket.socketpair()
# from cryptography.hazmat.backends.openssl import rsa, x509
# def gen_dsa_key():
#     private_key = dsa.generate_private_key(
#         key_size=3072, backend=default_backend())
#     return private_key, private_key.public_key()
#
# from Crypto.Random import random
# def sign_data_secure(data, private_key):
#     h = SHA256.new(data).digest()
#     k = random.StrongRandom().randint(111111, 111111111111111111111) # os.urandom(111111111) #
#     sig = private_key.sign(h, k)
#     return sig
#
# def sign_data(data, private_key):
#     signature = private_key.sign(data, hashes.SHA256())
#     print('DSA Signature', len(str(signature)))
#     return signature
#
#
# def verify_data(data, signature, public_key):
#     try:
#         public_key.verify(signature, data, hashes.SHA256())
#     except InvalidSignature:
#         print("recv msg: {} not trust!".format(data))
#     else:
#         print("check msg: {} success!".format(data))
#
# def verify_dsa_secure(pub_key, h, sig):
#     if pub_key.verify(h, sig):
#         return True
#     else:
#         return False
#
# # generate alice private & public key
# alice_private_key, alice_public_key = gen_dsa_key()
# # alice send message to bob, then bob recv
# alice_msg = b"Hello Bob" * 1000
# b = alice.send(alice_msg)
# bob_recv_msg = bob.recv(1024)
# # alice send signature to bob, then bob recv
# signature = sign_data(alice_msg, alice_private_key)
# b = alice.send(signature)
# bob_recv_signature = bob.recv(1024)
# # bob check message recv from alice
# verify_data(bob_recv_msg, bob_recv_signature, alice_public_key)
# # attacker modify the msg will make the msg check fail
# verify_data(b"I'm attacker!", bob_recv_signature, alice_public_key)
# print('DSA pubkey len', len(str(alice_public_key)))

# signature2 = sign_data_secure(alice_msg, alice_private_key)
# h = SHA256.new(alice_msg).digest()
# print('Sig2 verified', verify_dsa_secure(alice_public_key, h, signature2))


#https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/PublicKey/DSA.py
from Crypto import Random as dsa_rand
# from Crypto.PublicKey.DSA import generate as dsa_gen
# dsa_key = dsa_gen(256) #bits=128, randfunc=dsa_rand)

# Timeit
# print(dt(), 'Start SHA256 tx1000 hash')
# tx1000_hash = SHA256.new(str(tx['msg']).encode('utf8') * 1000).hexdigest()
# print(dt(), 'End SHA256 tx1000 hash', tx1000_hash)
#
# print(dt(), 'Start MD5 tx1000 hash')
# tx1000_hash = hashlib.md5(str(tx['msg']).encode('utf8') * 1000).hexdigest()
# print(dt(), 'End MD5 tx1000 hash', tx1000_hash)
#
# print(dt(), 'Start RSA4096 sigVerify')
# start = time.time()
# count = 0
# while (time.time() - start < 1):
#     pubKeyObj.publickey().verify(tx_msg_jsonb, tuple(tx_from_bytes['sig']))
#     count += 1
# print(dt(), 'END 1sec RSA4096 sigVerify, count %s ' % count)
#
# print(dt(), 'Start SHA256 hash')
# start = time.time()
# count = 0
# while (time.time() - start < 1):
#     #SHA256.new(str(tx['msg']).encode('utf8') * 1000).hexdigest()
#     hashlib.sha256(str(tx['msg']).encode('utf8') * 1000).hexdigest()
#     count += 1
# print(dt(), 'END 1sec SHA256 hash, count %s ' % count)
#
# print(dt(), 'Start MD5 hash')
# start = time.time()
# count = 0
# while (time.time() - start < 1):
#     hashlib.md5(str(tx['msg']).encode('utf8') * 1000).hexdigest()
#     count += 1
# print(dt(), 'END 1sec MD5 hash, count %s ' % count)
#
#
# print(dt(), 'Start json dumps')
# start = time.time()
# count = 0
# while (time.time() - start < 1):
#     json.dumps(tx, cls=JsonEncoder)
#     count += 1
# print(dt(), 'END 1sec json dumps, count %s ' % count)
#
#
# print(dt(), 'Start json loads')
# start = time.time()
# count = 0
# while (time.time() - start < 1):
#     json.loads(tx_msg_jsonb)
#     count += 1
# print(dt(), 'END 1sec json loads, count %s ' % count)

# import ecdsa
# print(dir(ecdsa))
# #from ecdsa import SigningKey
# sk = ecdsa.SigningKey.generate() # uses NIST192p
# vk = sk.get_verifying_key()
# signature = sk.sign("message")
# assert vk.verify(signature, "message")


#msg_packed = msgpack.packb({u'tx': tx}) #, use_bin_type=False) #({u"pbk": pbk}) tx
# tx_packed = msgpack.packb({u'tx': str(tx).encode('utf8')})
# print('tx packed size', type(tx_packed), sys.getsizeof(tx_packed))
# tx_unpacked = msgpack.unpackb(tx_packed) #, raw=False)
# print('unpacked size', type(tx_unpacked), sys.getsizeof(tx_unpacked[b'tx']), tx_unpacked[b'tx'] ) #msg_unpacked[b'pbk']
# print('Verified MsgHash', tx_unpacked[b'tx'])
# print('Unpacked tx verified', (tx_unpacked[b'tx'][b'msg'] == tx['msg'])) #msg_unpacked[b'pbk'] == pbk
# print('ver_num verified', tx_unpacked[b'tx'][b'msg'][b'ver_num'] == 1, tx_unpacked[b'tx'][b'msg'][b'ver_num'])
# print('tx_type verified', tx_unpacked[b'tx'][b'msg'][b'tx_type'] == b'1')

# print(eval(str(tx).encode('utf8')) == tx, type((tx_unpacked[b'tx'][b'msg'])))


# # import key via rsa module
# pubkey = RSA.importKey(key_text)
#
# # create a cipher via PKCS1.5
# cipher = PKCS1_v1_5.new(pubkey)
#
# # encrypt
# cipher_text = cipher.encrypt(b"Hello RSA!")
#
# # do base64 encode
# cipher_text = base64.b64encode(cipher_text)
# print(cipher_text.decode('utf-8'))

#TODO to continue later
# bpacked_pubkey = struct.pack("Q", pbk_n)
# print(sys.getsizeof(bpacked_pubkey), bpacked_pubkey)
# unpacked_bpubkey = struct.unpack("Q", bpacked_pubkey)
# print('bpacked unpacked type %s pubkey  verified %s  %s' % (type(unpacked_bpubkey[0]), ((unpacked_bpubkey[0])) == (pbk_n), unpacked_bpubkey) )
# p = "%s.%s" % (pbk_n_str[0], pbk_n_str[1:300])
# pp = "%s%s" % (p[0], p[1:300])


# print(sys.getsizeof(float(pbk_n_str[0:300])))
# pbk_n_list = []
# pbk_n_str_len = len(pbk_n_str)
# print('pbk_n_str_len', pbk_n_str_len)
# cut_size = 300
# pbk_n_str_parts = pbk_n_str_len // cut_size + (0 if pbk_n_str_len % cut_size == 0 else 1)
# index = 0
# print(pbk_n_str_parts)
# for i in range(pbk_n_str_parts):
#     cut_from = index
#     cut_to = index+cut_size if index+cut_size <= pbk_n_str_len else index+pbk_n_str_len-index
#     print(cut_from, cut_to)
#     pbk_n_list.append(float(pbk_n_str[cut_from:cut_to]))
#     index += 300
# print(sys.getsizeof(pbk_n_list), 'bytes', pbk_n_list)
#
# restored_pbk_n = [int(float(x)) for x in pbk_n_list]
# print('Restored PBK verified' , restored_pbk_n[0] == pbk_n_str, restored_pbk_n[0])
#
# #compressed_pubkey = zlib.compress(struct.pack("d", (float(str(pbk_n)[0:300]))))
# bpacked_pubkey = struct.pack("d", (float(str(pbk_n)[0:cut_size])))
# unpacked_bpubkey = struct.unpack("d", bpacked_pubkey)
# print('bpacked unpacked type %s pubkey  verified %s ' % (type(unpacked_bpubkey), int(unpacked_bpubkey[0]) == int(float(pbk_n_str[0:cut_size]))), unpacked_bpubkey, int(float(pbk_n_str[0:cut_size])) )
# #


# start = time.time()
# count = 0
# while time.time() - start < 1:
#     hashlib.md5(str(tx_msg).encode('utf8'))
#     count += 1
# print('%s MD5 tx within 1sec' % count)
#
# start = time.time()
# count = 0
# while time.time() - start < 1:
#     hashlib.sha1(str(tx_msg).encode('utf8'))
#     count += 1
# print('%s SHA1 tx within 1sec' % count)
#
#
# start = time.time()
# count = 0
# while time.time() - start < 1:
#     hashlib.sha256(str(tx_msg).encode('utf8'))
#     count += 1
# print('%s sha256 tx within 1sec' % count)
#
# start = time.time()
# count = 0
# while time.time() - start < 1:
#     hashlib.sha3_256(str(tx_msg).encode('utf8'))
#     count += 1
# print('%s sha3_256 tx within 1sec' % count)
#
#
# start = time.time()
# count = 0
# while time.time() - start < 1:
#     hashlib.sha512(str(tx_msg).encode('utf8'))
#     count += 1
# print('%s SHA512 tx within 1sec' % count)
#
# start = time.time()
# count = 0
# while time.time() - start < 1:
#     hashlib.sha3_512(str(tx_msg).encode('utf8'))
#     count += 1
# print('%s SHA3_512 tx within 1sec' % count)

# 343768 MD5 tx within 1sec
# 372307 SHA1 tx within 1sec
# 327671 sha256 tx within 1sec
# 339581 sha3_256 tx within 1sec
# 358666 SHA512 tx within 1sec
# 263285 SHA3_512 tx within 1sec