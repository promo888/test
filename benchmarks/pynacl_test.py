#import pytest
from nacl.bindings import crypto_sign_PUBLICKEYBYTES, crypto_sign_SEEDBYTES
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SignedMessage, SigningKey, VerifyKey
#from utils import assert_equal, assert_not_equal, read_crypto_test_vectors
#from nacl import *
import nacl

print(dir(nacl))


# from __future__ import absolute_import, division, print_function
#
# import binascii
#
# import pytest
#
# #from utils import assert_equal, assert_not_equal, read_crypto_test_vectors
# import read_crypto_test_vectors
#
# from nacl.bindings import crypto_sign_PUBLICKEYBYTES, crypto_sign_SEEDBYTES
# from nacl.encoding import HexEncoder
# from nacl.exceptions import BadSignatureError
# from nacl.signing import SignedMessage, SigningKey, VerifyKey
#
#
# def tohex(b):
#     return binascii.hexlify(b).decode('ascii')
#
#
# def ed25519_known_answers():
#     # Known answers taken from: http://ed25519.cr.yp.to/python/sign.input
#     # hex-encoded fields on each input line: sk||pk, pk, msg, signature||msg
#     # known answer fields: sk, pk, msg, signature, signed
#     DATA = "ed25519"
#     lines = read_crypto_test_vectors(DATA, delimiter=b':')
#     return [(x[0][:64],   # secret key
#              x[1],        # public key
#              x[2],        # message
#              x[3][:128],  # signature
#              x[3],        # signed message
#              )
#             for x in lines]
#
#
# class TestSigningKey:
#     def test_initialize_with_generate(self):
#         SigningKey.generate()
#
#     def test_wrong_length(self):
#         with pytest.raises(ValueError):
#             SigningKey(b"")
#
#     def test_bytes(self):
#         k = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         assert bytes(k) == b"\x00" * crypto_sign_SEEDBYTES
#
#     def test_equal_keys_are_equal(self):
#         k1 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         k2 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         assert_equal(k1, k1)
#         assert_equal(k1, k2)
#
#     def test_equal_keys_have_equal_hashes(self):
#         k1 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         k2 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         assert hash(k1) == hash(k2)
#         assert id(k1) != id(k2)
#
#     @pytest.mark.parametrize('k2', [
#         b"\x00" * crypto_sign_SEEDBYTES,
#         SigningKey(b"\x01" * crypto_sign_SEEDBYTES),
#         SigningKey(b"\x00" * (crypto_sign_SEEDBYTES - 1) + b"\x01"),
#     ])
#     def test_different_keys_are_not_equal(self, k2):
#         k1 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         assert_not_equal(k1, k2)
#
#     @pytest.mark.parametrize("seed", [
#         b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
#     ])
#     def test_initialization_with_seed(self, seed):
#         SigningKey(seed, encoder=HexEncoder)
#
#     @pytest.mark.parametrize(
#         ("seed", "_public_key", "message", "signature", "expected"),
#         ed25519_known_answers()
#     )
#     def test_message_signing(self, seed, _public_key,
#                              message, signature, expected):
#         signing_key = SigningKey(
#             seed,
#             encoder=HexEncoder,
#         )
#         signed = signing_key.sign(
#             binascii.unhexlify(message),
#             encoder=HexEncoder,
#         )
#
#         assert signed == expected
#         assert signed.message == message
#         assert signed.signature == signature
#
#

# class TestVerifyKey:
#     def test_wrong_length(self):
#         with pytest.raises(ValueError):
#             VerifyKey(b"")
#
#     def test_bytes(self):
#         k = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
#         assert bytes(k) == b"\x00" * crypto_sign_PUBLICKEYBYTES
#
#     def test_equal_keys_are_equal(self):
#         k1 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
#         k2 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
#         #assert_equal(k1, k1)
#         #assert_equal(k1, k2)
#
#     def test_equal_keys_have_equal_hashes(self):
#         k1 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
#         k2 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
#         #assert hash(k1) == hash(k2)
#         #assert id(k1) != id(k2)
#
#     @pytest.mark.parametrize('k2', [
#         b"\x00" * crypto_sign_PUBLICKEYBYTES,
#         VerifyKey(b"\x01" * crypto_sign_PUBLICKEYBYTES),
#         VerifyKey(b"\x00" * (crypto_sign_PUBLICKEYBYTES - 1) + b"\x01"),
#     ])
#     def test_different_keys_are_not_equal(self, k2):
#         k1 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
#         #assert_not_equal(k1, k2)
#
#     @pytest.mark.parametrize(
#         ("_seed", "public_key", "message", "signature", "signed"),
# #        ed25519_known_answers()
#     )
#     def test_valid_signed_message(
#             self, _seed, public_key, message, signature, signed):
#         key = VerifyKey(
#             public_key,
#             encoder=HexEncoder,
#         )
#
#         assert binascii.hexlify(
#             key.verify(signed, encoder=HexEncoder),
#         ) == message
#         assert binascii.hexlify(
#             key.verify(message, signature, encoder=HexEncoder),
#         ) == message
#
#     def test_invalid_signed_message(self):
#         skey = SigningKey.generate()
#         smessage = skey.sign(b"A Test Message!")
#         signature, message = smessage.signature, b"A Forged Test Message!"
#
#         # Small sanity check
#         assert skey.verify_key.verify(smessage)
#
#         with pytest.raises(BadSignatureError):
#             skey.verify_key.verify(message, signature)
#
#         with pytest.raises(BadSignatureError):
#             forged = SignedMessage(signature + message)
#             skey.verify_key.verify(forged)
#
#     def test_key_conversion(self):
#         keypair_seed = (b"421151a459faeade3d247115f94aedae"
#                         b"42318124095afabe4d1451a559faedee")
#         signing_key = SigningKey(binascii.unhexlify(keypair_seed))
#         verify_key = signing_key.verify_key
#
#         private_key = bytes(signing_key.to_curve25519_private_key())
#         public_key = bytes(verify_key.to_curve25519_public_key())
#
#         assert tohex(private_key) == ("8052030376d47112be7f73ed7a019293"
#                                       "dd12ad910b654455798b4667d73de166")
#
#         assert tohex(public_key) == ("f1814f0e8ff1043d8a44d25babff3ced"
#                                      "cae6c22c3edaa48f857ae70de2baae50")


# def check_type_error(expected, f, *args):
#     with pytest.raises(TypeError) as e:
#         f(*args)
#     assert expected in str(e)
#
#
# def test_wrong_types():
#     sk = SigningKey.generate()
#
#     check_type_error("SigningKey must be created from a 32 byte seed",
#                      SigningKey, 12)
#     check_type_error("SigningKey must be created from a 32 byte seed",
#                      SigningKey, sk)
#     check_type_error("SigningKey must be created from a 32 byte seed",
#                      SigningKey, sk.verify_key)
#
#     check_type_error("VerifyKey must be created from 32 bytes",
#                      VerifyKey, 13)
#     check_type_error("VerifyKey must be created from 32 bytes",
#                      VerifyKey, sk)
#     check_type_error("VerifyKey must be created from 32 bytes",
# VerifyKey, sk.verify_key)


skey = SigningKey.generate()
skey2 = SigningKey.generate()
assert skey != skey2
smessage = skey.sign(b"A Test Message!" * 1000)
smessage2 = skey2.sign(b"A Test Message!" * 1000)
signature, message = smessage.signature, b"A Forged Test Message!"


import time
start = time.time()
duration_secs = 1
count = 0
while time.time() - start < duration_secs:
    assert skey.verify_key.verifySig(smessage)
    count += 1
print('%s NACL.time_verify sigs verified within %s secs' % (count, duration_secs))
##assert skey.verify_key.verify(smessage2)
sig_key = skey._signing_key
ver_key = skey.verify_key._key
prv_key = skey.to_curve25519_private_key()._private_key
pub_key = skey.to_curve25519_private_key().public_key._public_key
##print("Len: Sig %s, Ver %s, prk %s, pbk %s" % len(sig_key), len(ver_key), len(prv_key), len(pub_key))

from nacl.bindings import crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES
from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random
pbk = PublicKey(b"\x00" * crypto_box_PUBLICKEYBYTES)
prk = PrivateKey(b"\x00" * crypto_box_SECRETKEYBYTES)
#print(prk, prk.public_key, pbk)
prk1 = PrivateKey(b"\x01" * crypto_box_SECRETKEYBYTES),
prk2 = PrivateKey(b"\x01" * crypto_box_SECRETKEYBYTES),
#print(b"\x01", b"\x01".decode())
assert prk1 == prk2
prk3 = PrivateKey(b"\x00" * (crypto_box_SECRETKEYBYTES - 1) + b"\x01")
print(prk1[0]._private_key, prk3._private_key)

alices = PrivateKey.generate()
alice_pbk = alices.public_key
bobes = PrivateKey.generate()
bob_pbk = bobes.public_key
#print(alice_pbk, bob_pbk)
assert alice_pbk != bob_pbk #TODO negative

#key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
#hexed_key = key.hex()

import ed25519
import binascii
spendkey_hex = prv_key #b'77fadbe52830d30438ff68036374c0e3fb755d0d983743bcbfb6a45962f50a09'
#sk = binascii.unhexlify(spendkey_hex)

def sc_reduce32(n):
    n = int.from_bytes(n, byteorder='little')
    l = (2**252 + 27742317777372353535851937790883648493)
    reduced = n % l
    newbytes = reduced.to_bytes(32, 'little')
    return newbytes


#reduced_sk = sc_reduce32(sk)
#sec = ed25519.SigningKey(reduced_sk)
#pub = sekey = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)c.get_verifying_key()


from nacl.bindings.crypto_sign import crypto_sign_open as verify, crypto_sign as sign, \
    crypto_sign_seed_keypair as keys_from_seed
pbk, prk = keys_from_seed(alices._private_key) # (b"\x00" * * crypto_sign_SEEDBYTES)
msg = b'a' * 1000
# smsg = sign(msg, alices._private_key)
# verify(smsg, alice_pbk._public_key)

smsg = sign(msg, prk)
verify(smsg, pbk)
pbk2, prk2 = keys_from_seed(alices._private_key)
assert prk == prk2

name = "Bob"
bname = bytes(name.ljust(32), 'utf8')
named_pbk, named_prk =  keys_from_seed(bname)
npbk = PublicKey(named_pbk)
nprk = SigningKey(bname)
nvk = PublicKey(nprk.verify_key._key)
assert nvk == npbk
assert nprk._seed == bname

# Generate a new random signing key
signing_key = skey #nacl.signing.SigningKey.generate()
#print('signing_key', type(signing_key.to_curve25519_private_key()._private_key), signing_key.to_curve25519_private_key()._private_key)
# Sign a message with the signing key
signed_msg = signing_key.sign(msg)
#print('signed_msg', type(signed_msg), signed_msg)
# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key
#print('verify_key', type(verify_key), verify_key)
# Serialize the verify key to send it to a third party
verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
#print('verify_key_hex', type(verify_key_hex), verify_key_hex)


#sk = skey
#hvk = vk._key.hex() #vk str
#vk._key == bytes.fromhex(hvk)
#hprk = prk.hex()
#prk == bytes.fromhex(hprk)
#smsg2 = sign(msg, sk._signing_key)
#verify(smsg2, vk._key)
#csk = SigningKey(sk._seed) #construct SecretKey from seed bytes
#sk ==  csk
# assert bytes.fromhex(vk.hex()) == vk #(int.from_bytes(vk, 'little'))


# Create a VerifyKey object from a hex serialized public key
verify_key = nacl.signing.VerifyKey(verify_key_hex,
                                    encoder=nacl.encoding.HexEncoder)
# Check the validity of a message's signature
# The message and the signature can either be passed separately or
# concatenated together.  These are equivalent:
verify_key.verify(signed_msg)
verify_key.verify(signed_msg.message, signed_msg.signature)

# Alter the signed message text
#forged = signed_msg[:-1] + bytes([int(signed[-1]) ^ 1])
# Will raise nacl.exceptions.BadSignatureError, since the signature check
# is failing
#verify_key.verify(forged)
#verify_key.verify(forged)


ed25519pbk, prk = keys_from_seed(alice_pbk._public_key)
#smsg = sign(msg, pbk)
#verify(smsg, binascii.hexlify(alice_pbk._public_key))
#print('alice_pbk', alice_pbk._public_key)
#print('pbk from alice seed', pbk)