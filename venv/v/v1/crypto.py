import sys
from logging.handlers import RotatingFileHandler
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from Crypto.Hash import SHA256, HMAC
import libnacl.sign
from msgpack import packb, unpackb
from decimal import Decimal
#from . import tools
from v.v1 import logger, config, db, wallets

class Crypto():

    # def __init__(self):
    #     self.logger = L.Logger() #('Crypto')
    #     self.Config = C.Config()
    #     self.Db = DB.Db()



    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Crypto, cls).__new__(cls)
        return cls.instance


    def getKeysFromSeed(self, seed=""):
        try:
            if seed != "":
                seed = seed.ljust(32) if len(seed) < 32 else seed[:32]
                return libnacl.sign.Signer(seed.encode()) #SignerObj seed, sk, vk
            else: #Random seed
                return libnacl.sign.Signer()
        except:
            return None


    @staticmethod #miner, wallet use
    def signMsg(msg, signer):
        try:
            if not isinstance(msg, bytes):
                msg = packb(msg)
            if not isinstance(signer, libnacl.sign.Signer):
                signer = libnacl.sign.Signer(signer.seed)
            signed_msg = signer.sign(msg)
            return signed_msg
        except Exception as ex:
            err_msg = 'Exception crypto signMsg: line %s \n ex: %s' % (ex.__traceback__.tb_lineno,  ex)
            print(err_msg)
            ##self.logger.logp(err_msg, logging.ERROR)
            return None

    @staticmethod
    def verifyMsgSig(signed_msg, pub_key, print_verified=True):
        print("Caller ", sys._getframe(1).f_code.co_name)
        '''Return True if msg verified, otherwise false'''
        try:
            if not db.Db.getDbKey(Crypto.getWalletAddr(pub_key)):
                return False,None
            verified_msg = libnacl.sign.Verifier(pub_key.hex()).verify(signed_msg)
            if print_verified:
                print('MsgSigVerified: ', type(unpackb(verified_msg)), unpackb(verified_msg))
            return True, verified_msg
        except Exception as ex:
            print('Exception crypto verifyMsgSig ErrorLine: %s %s' % (ex.__traceback__.tb_lineno, ex)) #TODO log?
            return False, None

    @staticmethod
    def getWalletAddr(vk):
        try:
            wallet_addr = config.Config.MsgType.WALLET.decode() + HMAC.new(vk).hexdigest() #VK._key
            return wallet_addr
        except Exception as ex:
            print("Exception crypto getWalletAddr ", ex)
            return None

    
    @staticmethod
    def to_HMAC(bytes_msg):
        '''Return HMAC hash from bytes'''
        try:
            if isinstance(bytes_msg, str):
                bytes_msg = bytes_msg.encode()
            if not isinstance(bytes_msg, bytes):
                bytes_msg = packb(bytes_msg)
            return HMAC.new(bytes_msg).hexdigest()
        except:
            return None
