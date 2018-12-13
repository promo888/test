# https://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/
# https://en.wikipedia.org/wiki/Salt_%28cryptography%29
# https://docs.python.org/3/library/hashlib.html
# https://ashishpython.blogspot.co.il/2014/06/how-to-encrypt-and-decrypt-data-in.html
# https://github.com/seperman/deepdiff

from hashlib import md5
# import rsa
import os, sys, time
from base64 import b64encode, b64decode
from Crypto import Random
from Crypto.Cipher import AES  # python2 win10
# from cryptography import fernet.AESCipher as AES #python3
from hashlib import sha256
from Crypto.Hash import SHA256
import binascii
from base64 import b64decode, b64encode
import zlib
from collections import OrderedDict
from itertools import groupby
import struct, base64

def runLengthEncode(plainText):
    res = []
    for k, i in groupby(plainText):
        run = list(i)
        if(len(run) > 4):
            res.append("/{:02}{}".format(len(run), k))
        else:
            res.extend(run)
    return "".join(res)

from re import sub

def encode(text):
    '''
    Doctest:
        >>> encode('WWWWWWWWWWWWBWWWWWWWWWWWWBBBWWWWWWWWWWWWWWWWWWWWWWWWBWWWWWWWWWWWWWW')
        '12W1B12W3B24W1B14W'
    '''
    return sub(r'(.)\1*', lambda m: str(len(m.group(0))) + m.group(1),
               text)

def decode(text):
    '''
    Doctest:
        >>> decode('12W1B12W3B24W1B14W')
        'WWWWWWWWWWWWBWWWWWWWWWWWWBBBWWWWWWWWWWWWWWWWWWWWWWWWBWWWWWWWWWWWWWW'
    '''
    return sub(r'(\d+)(\D)', lambda m: m.group(2) * int(m.group(1)),
               text)

textin = "WWWWWWWWWWWWBWWWWWWWWWWWWBBBWWWWWWWWWWWWWWWWWWWWWWWWBWWWWWWWWWWWWWW"
assert decode(encode(textin)) == textin


def bin2hex(binStr):
    return binascii.hexlify(binStr)

def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)


def dump(obj):
    for attr in dir(obj):
        print("obj.%s = %r" % (attr, getattr(obj, attr)))


# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


class AESCipher:
    """
    Usage: pycrypto lib is required
    Tested under python 2.7 on windows 10
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    Tested under Python 3 and PyCrypto 2.6.1. on Ubuntu16
    """

    def __init__(self, key):
        self.key = sha256(key.encode('utf-8')).hexdigest()[0:32]  # md return 32, sha 64bytes
        # self.key2 = sha256(key.encode('utf-8')).hexdigest()[32:]
        # self.key3 = hashlib.new('ripemd160').update(sha256(key.encode('utf-8')).hexdigest()).hexdigest()[0:32]

        print(self.key)
        # print(self.key2)

    def encrypt(self, raw):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:])).decode('utf-8')

    def get_key(self):
        return self.key


##
# MAIN
# Just a test.
# msg = input('Message: ')
# pwd = input('Password: ')
# print('Ciphertext:', AESCipher(pwd).encrypt(msg))

# c = AESCipher('password').encrypt('message')
# m = AESCipher('password').decrypt(c)
# print(c)
# print(m)

c = AESCipher('password')
k = c.get_key()
print('k', k)
e = c.encrypt('msgd')
d = c.decrypt(e)
print('e', e)
print('d: %s' % d)

c2 = AESCipher('password2')
# print('d2', c2.decrypt(e)) #todo try catch fails sometimes on byte 0


# from Crypto.Cipher import AES
# from pkcs7 import PKCS7Encoder
# import pkcs7,threading, base64
#
#
# text = 'my secret data'
# key = 'secret#456!23key'
# iv = 'Key@123Key@123fd'
# aes = AES.new(key, AES.MODE_CBC, iv)
# encoder = PKCS7Encoder()
# pad_text = encoder.encode(text)
# cipher = aes.encrypt(pad_text)
# enc_cipher = base64.b64encode(cipher)
# print (enc_cipher)
#
# decodetext =  base64.b64decode(enc_cipher)
# aes = AES.new(key, AES.MODE_CBC, iv)
# cipher = aes.decrypt(decodetext)
# pad_text = encoder.decode(cipher)
# print (pad_text)


from Crypto.PublicKey import RSA
from Crypto import Random

random_generator = Random.new().read #os.urandom(100)
from uuid import * #uuid4
print('len random_generator', len(str(random_generator)), str(random_generator), type(random_generator))
key = RSA.generate(4096, random_generator) #2048
binPrivKey = key.exportKey('PEM')
binPubKey = key.publickey().exportKey('PEM')
# with open('private_key_pem', 'wb') as prk_file:
#     prk_file.write(binPrivKey)
# with open('public_key_pem', 'wb') as prk_file:
#     prk_file.write(binPubKey)
prk = None
pbk = None
# with open('private_key_pem', 'rb') as prk_file:
#     print(prk_file)
#     prk = str(prk_file)
# with open('public_key_pem', 'rb') as prk_file:
#     pbk = prk_file
#privKeyObj = RSA.importKey(prk) #TODO passphrase
#pubKeyObj = RSA.importKey(pbk)

# from uuid import getnode as get_mac
# mac = get_mac()
# uid4 = uuid4()
# print('uuid4', uid4, uid4.time)
# print('mac addr', mac, str(mac))
# random_seed = "%s%s%s" % (str(uid4), str(mac), str(uid4.time))
# print('random_seed', random_seed)
# key = RSA.generate(4096,  random_seed) #

# import hashlib
# plaintext = "12 or 24 words as sha password"
# mysha256 = hashlib.sha256()
# mysha256.update(plaintext.encode('UTF-32'))
# myhash_sha256 = mysha256.digest()
# #print('bits length of sha256:%s sha256_digest:%s' % ((mysha256), (myhash_sha256)))
# key = RSA.generate(2048, myhash_sha256)

# print('RSA keys:\n %s \n' % (inspect(key)))
print('RSA private key', key)
public_key = key.publickey()
print('RSA public_key', type(public_key.key.n), sys.getsizeof(public_key.key.n), public_key.key.n)
text = 'x' * 1000  # 'secret data!:*-+&'

# enc_data = public_key.encrypt(text, 32)
# print('RSA encrypted data', (enc_data))
# print('RSA decrypted data', key.decrypt(enc_data))

tx_msg = {"ver_num": 1, "msg_type": 1, "msg_date": None, "asset_type": None, "amount": None, "to_addr": None}
tx = {"msg_hash": None, "msg": tx_msg, "pub_key": None, "sig": None}



hash = SHA256.new(text.encode('utf-8')).digest()
print('SHA256 hash', hash)
print('public_key.key.n', type(public_key.key.n))
compressed_pubkey = zlib.compress(struct.pack("d", (float(str(public_key.key.n)[0:300]))))
bpacked_pubkey = struct.pack("d", (float(str(public_key.key.n)[0:300])))
unpacked_bpubkey = struct.unpack("d", bpacked_pubkey)
print('bpacked unpacked type %s pubkey  verified %s ' % (type(unpacked_bpubkey), unpacked_bpubkey[0] == float(str(public_key.key.n)[0:300])) )
print('public_key.key.n compressed 300', type(compressed_pubkey), sys.getsizeof(compressed_pubkey), compressed_pubkey)
print('public_key.key.n struct_packed 300', type(bpacked_pubkey), sys.getsizeof(bpacked_pubkey), bpacked_pubkey)
signature = key.sign(hash, public_key.key.n)  # '')
print('Sig: %s' % signature)
print('SigLen: %s, Type: %s' % (sys.getsizeof(signature[0]), type(signature[0])) )
print('SigLenPart: %s, Type: %s' % (sys.getsizeof(float(str(signature[0])[0:300])), type(float(str(signature[0])[0:300]))) )
print('SigLen2: %s' % len(str(signature[0]).encode('utf-8')))
# print('SigDump: \n%s' % dump(signature))

print('public_key', repr(public_key.publickey))
print('signature', sys.getsizeof(signature[0]), signature)
print('Verified Signature', public_key.verifySig(hash, signature))
print('Signature', signature)

test_key = RSA.generate(4096, random_generator)
test_public_key = test_key.publickey()
test_public_key.n = public_key.key.n #public_key.e
print('Test1 Verified Signature', test_public_key.verifySig(hash, signature))  # False
print('Test1 Verified Signature size', sys.getsizeof(signature[0]))

derPubKey = key.publickey().exportKey('DER')
# print('derPubKey', type(derPubKey), len(derPubKey), '\n', derPubKey, '\n', b64decode(derPubKey[1:]) ) #, '\n', binascii.unhexlify(derPubKey[1:]))
# temp
pk = str(public_key.key.n).encode('utf-8')
# print('pk len: %s' % (len(pk)))
# print('test', sys.getsizeof(1234567890))
# print('test', sys.getsizeof(1))
# print('test', sys.getsizeof('1234567890'))
# print('test', sys.getsizeof('1'))


print('pk rle len', len(runLengthEncode(str(derPubKey))))
print('sig rle len', len(runLengthEncode(str(signature))))

compressed_pubkey = zlib.compress(derPubKey)  # str(derPubKey).encode('utf-8')
print('derPubKey', type(derPubKey), sys.getsizeof(derPubKey), derPubKey)
compressed_sig = zlib.compress(str(signature).encode('utf-8'))  # signature[0] str(signature).encode('utf-8')
print('compressed_sig', type(compressed_sig),
      sys.getsizeof(compressed_sig))  # len(binascii.b2a_base64(compressed_sig)))
print('Compressed/Uncompressed len pk: %s %s,Compressed/Uncompressed len sig: %s %s' % (
sys.getsizeof(compressed_pubkey), sys.getsizeof(derPubKey), sys.getsizeof(compressed_sig), sys.getsizeof(signature)))
assert derPubKey == zlib.decompress(compressed_pubkey), 'pk compress issue'  # binascii.hexlify(compressed_pubkey)
# assert signature[0] == zlib.decompress(compressed_sig)
# assert signature == zlib.decompress(compressed_sig)
#print('encode(derPubKey)', encode(str(derPubKey)))
#assert decode(encode(str(derPubKey))) == derPubKey
print("len(binascii.hexlify(derPubKey))", len(binascii.hexlify(derPubKey)))

start = time.time()
count = 0
duration = 1
derPubKey = key.publickey().exportKey('DER')
test_public_key = RSA.importKey(derPubKey)
while (time.time() - start < duration):
    ##derPubKey = key.publickey().exportKey('DER')
    # print('derPubKey', type(derPubKey), len(derPubKey))
    test_public_key = RSA.importKey(derPubKey)
    # print('Test2 Verified Signature', test_public_key.verify(hash, signature))
    if test_public_key.verifySig(hash, signature): count += 1
print('%s SigVerified in %s secs' % (count, duration))

pub_addr = SHA256.new(str(public_key.key.n).encode('utf-8')).hexdigest()  # n-priv_key or e-pub_key
print("pub_addr: ", pub_addr)

start = time.time()
prks = []
pbks = []
sigs = []
data = []
data2 = []
count = 1
for x in range(count):
    random_generator = Random.new().read  # TODO stronger
    private_key = RSA.generate(2048, random_generator)
    text = "x" * 1000  # 128
    public_key = private_key.publickey()
    # print(public_key)
    # print(len(str(public_key.key.n)))
    enc_data2 = public_key.encrypt(text, 32)
    # hash = SHA256.new(enc_data[0]).digest()

    ##hash = SHA256.new(text).digest()
    ##signature = private_key.sign(hash, '')

    prks.append(private_key)
    pbks.append(public_key)
    # sigs.append(signature)
    # data2.append(enc_data2)
    # data.append(hash)
end = time.time() - start
print("%s/sec for RSA GENERATION & ENCRYPTION of %s keys with %s bytes of encrypted data" % (
    (end / count), count, len(text)))

# start = time.time()
# count = 1000
# for x in range(count):
#     #dec = prks[0].decrypt(data2[0])
#     #print(dec)
#
#     # dec = key.decrypt(enc_data)
#     # print(dec)
#
#     #print('RSA decrypted data', key.decrypt(enc_data))
#     key.decrypt(enc_data)
# print("%s/sec for RSA DECRYPTION of %s keys with 1k of encrypted data" % ( count // (time.time() - start), count))

start = time.time()
count = 1000
for x in range(count):
    public_key.verifySig(hash, signature)
print("%s/sec for RSA SIGNATURE VERIFICATION" % (count // (time.time() - start)))
print("RSA SIGNATURE VERIFICATION: %s secs ellapsed for len of %s bytes and count of %s msgs" % (
time.time() - start, len(hash), count))

aes = AESCipher('password' * 17)
aes_cipher = aes.encrypt('x' * 1000)  # 4096)
print('AES cipher size %s' % len(aes_cipher))
start = time.time()
count = 1000
for x in range(count):
    # aes = AESCipher('password' * 17)
    aes.encrypt('x' * 1000)  # 4096)
print("%s/sec for AES ENCRYPTION" % (count // (time.time() - start)))

start = time.time()
count = 1000
for x in range(count):
    aes.decrypt(aes_cipher)
print("%s/sec for AES DECRYPTION" % (count // (time.time() - start)))

binPrivKey = key.exportKey('PEM')
binPubKey = key.publickey().exportKey('PEM')
privKeyObj = RSA.importKey(binPrivKey)
pubKeyObj = RSA.importKey(binPubKey)
# print('binPrivKey', binPrivKey)
# print(len(binPrivKey))
print('binPubKey', binPubKey)
print(len(binPubKey))
wallet_addr = SHA256.new(binPubKey).hexdigest()  # add nettype, spendable, exchange, trus
print('wallet_addr', wallet_addr)
print(len(wallet_addr))
# new_tx = {'from' : binPubKey, 'to' : 'x' * 64, 'last_tx' : 'y' * 64 } #to validate
new_tx = "from:{},to={},last_tx={}".format(binPubKey, 'x' * 64, 'y' * 64)  # to validate
tx_digest = SHA256.new(new_tx.encode('utf-8'))
print('new_tx, tx_digest')
print(new_tx, tx_digest)
# print(dir(tx_digest))
# from pprint import pprint
# pprint(vars(tx_digest))
# dump(tx_digest)
# obj.__dict__
# print repr(obj)

import hashlib

h = hashlib.new('sha256')
h.update(binPubKey)
# print('h.hexdigest')
print(h.hexdigest())
# print(h.digest())


h2 = hashlib.new('sha256')
h2.update(new_tx.encode('utf-8'))
print(h2.hexdigest())

hash_object = hashlib.sha256(binPubKey)  # (b'Hello World')
hex_dig = hash_object.hexdigest()
print('hex_dig', hex_dig)
# assert(h2.hexdigest == tx_digest) #, 'sha256 different impl')
hash_object = SHA256.new(new_tx.encode('utf-8')).digest()

# tx_bin =
# print(dump(SHA256.new(binPubKey)))
# signature = key.sign(SHA256.new(binPubKey).hexdigest(), '')
# signature2 = key.sign(SHA256.new(new_tx.encode('utf-8')).hexdigest(), '')
# signature3 = key.sign(SHA256.new('text'.encode('utf-8')).hexdigest(), '')
signature = h.hexdigest
signature2 = h2.hexdigest
# print('signature', signature[0])
# print(len(str(signature[0])))
# print('signature3', signature3[0])
# print(len(str(signature3[0])))
# print('Verified Signature', pubKeyObj.verify(SHA256.new(binPubKey.encode('utf-8')).hexdigest(), signature))
# print('Verified Signature2', pubKeyObj.verify(SHA256.new(new_tx.encode('utf-8')).hexdigest(), signature2))
# print('Verified Signature3', new_tx[6:70] == wallet_addr)

# print('Verified Signature', pubKeyObj.verify(hashlib.sha256(binPubKey.encode('utf-8')), signature)) #TODO hashlib.3_256 or 3_512
# print('Verified Signature', pubKeyObj.verify(hashlib.sha256(new_tx.encode('utf-8')), signature2))
##print('Verified Signature', pubKeyObj.verify(new_tx.encode('utf-8'), signature2))
print('Verified Signature', pubKeyObj.verifySig(hash_object, signature2))

# aes = AESCipher(wallet_addr)
# enc_pubkey = aes.encrypt(binPubKey)
# enc_sig = aes.encrypt(str(signature[0]))
# print('Encrypted pubkey: ', enc_pubkey)
# print('Encrypted pubkey len: ', len(enc_pubkey))
# print('Verified Signature',
#       RSA.importKey(aes.decrypt(enc_pubkey)).verify(SHA256.new(aes.decrypt(enc_pubkey)).hexdigest(), signature))


# import asyncio
#
# loop = asyncio.get_event_loop()
#
#
# # an instance of EchoProtocol will be created for each client connection.
# class EchoProtocol(asyncio.Protocol):
#     def connection_made(self, transport):
#         self.transport = transport
#         print('connection_made')
#
#     counter = 0
#
#     def data_received(self, data):
#         self.transport.write(data)
#         print(data)
#         # counter += 1
#         # print('msg # ', counter)
#
#     def connection_lost(self, exc):
#         server.close()
#         print('connection_lost')
#
#
# # run the coroutine to establish the server connection, then keep running
# # the event loop until the server is stopped.
# server = loop.run_until_complete(loop.create_server(EchoProtocol, '', 4444))
# server = loop.run_until_complete(loop.create_server(EchoProtocol, '', 5555))
# ## loop.run_until_complete(server.wait_closed())
# loop.run_forever()


# https://www.blog.pythonlibrary.org/2014/02/11/python-how-to-create-rotating-logs/
# https://fangpenlin.com/posts/2012/08/26/good-logging-practice-in-python/
import logging
import time

from logging.handlers import RotatingFileHandler


# ----------------------------------------------------------------------
def create_rotating_log(path, label="Rotating Log"):
    """
    Creates a rotating log
    """
    logger = logging.getLogger(label)
    logger.setLevel(logging.INFO)

    # add a rotating handler
    handler = RotatingFileHandler(path, maxBytes=20, backupCount=10000)
    logger.addHandler(handler)
    return logger
    # for i in range(10):
    #     logger.info("This is test log line %s" % i)
    #     time.sleep(1.5)


# ----------------------------------------------------------------------

# https://oliverleach.wordpress.com/2016/06/15/creating-multiple-log-files-using-python-logging-library/
##############
def setup_logger(logger_name, log_file, level=logging.INFO):
    log_setup = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    log_setup.setLevel(level)
    log_setup.addHandler(fileHandler)
    log_setup.addHandler(streamHandler)


def logger(msg, level, logfile):
    if logfile == 'one': log = logging.getLogger('log_one')
    if logfile == 'two': log = logging.getLogger('log_two')
    if level == 'info': log.info(msg)
    if level == 'warning': log.warning(msg)
    if level == 'error': log.error(msg)


##############

if __name__ == "__main__":
    log_file1 = "test.log"
    logger1 = create_rotating_log(log_file1, "logger1")

    log_file2 = "another_test.log"
    logger2 = create_rotating_log(log_file2, "logger2")

    logger1.info("Test5")
    logger2.info("Test6")
##############

# LOG_FILE_ONE = "/var/log/one.log"
# LOG_FILE_TWO = "/var/log/two.log"
#
# setup_logger('log_one', LOG_FILE_ONE)
# setup_logger('log_two', LOG_FILE_TWO)
#
# logger('Logging out to log one...', 'info', 'one')
# logger('Logging out to log two...', 'warning', 'two')
