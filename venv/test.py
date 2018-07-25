# import hashlib
# import ecdsa
# import Crypto
# import fastecdsa

#import tensorflow
#import keras

#/home/igorb/PycharmProjects/test
import leveldb
leveldb.DestroyDB('./../db')
db = leveldb.LevelDB('./../db')
db.Put(b'key 1', b'value 1')
print(db.Get(b'key 1'))
print(dir(db))
print(dir(leveldb))

from fastecdsa import curve, ecdsa, keys
#from hashlib import sha256
m = 'Message to sign with ECDSA'
private_key, public_key = keys.gen_keypair(curve.P256)
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