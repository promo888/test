import os, sys, logging
from msgpack import packb, unpackb
import sqlite3, plyvel, json
from queue import PriorityQueue
# from . import tools
from v.v1 import logger, config, utils, node, crypto, network, web, \
                 sdb, db, wallets, message, block, contract, ico, exchange

class Transaction():
    def __init__(self):
        #self.logger = logger.Logger() #('Transaction')
        self.Config = config.Config
        self.VERSION = self.Config.VERSION
        self.Utils = utils.Utils()
        self.Crypto = crypto.Crypto()
        self.Net = network.Network()
        self.DB = db.Db() #tools.config.NODE_DB
        self.SDB = sdb.ServiceDb()
        self.Wallets = wallets.Wallet()
        self.TX_FEE = self.Config.TX_FEE
        self.TX_MSG_FIELD_TYPE = {'version': str, 'msg_type': str, 'input_txs': list,  #'output_txs': list, # 'from_addr': str,->Multisig
                              'to_addrs': list, 'asset_type': str, 'amounts': list, 'output_txs': list,
                              'tx_utc_time': bytes, 'pub_keys': bytes}
        self.TX_MSG_INDEX_FIELD = {0: 'version', 1: 'msg_type', 2: 'input_txs', 3: 'to_addrs',
                                   4: 'asset_type', 5: 'amounts', 6: 'output_txs',
                                   7: 'tx_utc_time', 8: 'pub_keys'}
        self.TX_MSG_FIELD_INDEX = {'version': 0, 'msg_type': 1, 'input_txs': 2, 'to_addrs': 3,
                                    'asset_type': 4, 'amounts': 5, 'output_txs': 6,
                                   'tx_utc_time': 7, 'pub_keys': 8}

    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Transaction, cls).__new__(cls)
        return cls.instance



    def getTxFieldValue(self, tx_msg, field_name):
        if not field_name in self.TX_MSG_FIELD_INDEX:
            return None
        return tx_msg[self.TX_MSG_FIELD_INDEX.get(field_name)]


    def setTX(self, version, msg_type, input_txs, to_addrs, asset_type, amounts, tx_fee, pub_keys): #output_txs,
        tx = ()
        tx += (version,)
        tx += (msg_type,)
        tx += (input_txs,)
#        tx += (output_txs,)
        tx += (to_addrs,)
        tx += (asset_type,)
        tx += (amounts,) # = Decimal('100000000000.1234567890') #TODO from decimal import Decimal; type(d) is Decimal #len('100000000000.1234567890'.encode()) MAX_LEN 21 + .8n
        #TODO continue len(str(amounts[0]).split('.')[1]) , '100000000000.12345678' 21chars + < b108 MAX_SUPPLY
        return tx #validateTX(tx)


    def validateMsgSize(self, msgType, bin_msg):
        msg_max_size = {self.MsgType.PARENT_TX_MSG: self.MsgType.MAX_MSG_SIZE_BYTES} #32678} #TODO config
        if msgType not in msg_max_size.keys() or len(bin_msg) > msg_max_size[msgType]:
            return False
        return True


    def decodeMsg(self, msg_with_bin_values):
        try:
            decoded_msg = ()
            for f in msg_with_bin_values:
                if type(f) is bytes:
                    t = self.dec(f)
                    decoded_msg += (t,)
                elif type(f) is list:
                    l = [self.dec(v) if type(v) is bytes else v for v in f]
                    decoded_msg += (l,)
                else:
                    decoded_msg += (f,)
            return decoded_msg
        except Exception as ex:
            print("Exception decodeMsg: %s %s" % (ex.__traceback__.tb_lineno, ex))
            return None
       #tuple(unpackb(packb(msg_with_bin_values))) == msg_with_bin_values
       #((packb(str(decoded_msg[5][0]))))

    # con = sqlite3.connect(":memory:")
    # cur = con.cursor()
    # l = [b'1.1', b'2.2', b'3.3']
    # print(packb(l))
    # cur.execute("drop table if exists test")
    # cur.execute("create table if not exists test(b BLOB, b1 BLOB, b2 BLOB, b3 BLOB, b4 BLOB,b5 BLOB,b6 BLOB)")
    # b = packb(l)
    # # print(sqlite3.Binary(b))
    # cur.execute("insert into test (b, b1, b2 ,b3, b4, b5 ,b6) values(?,?,?,?,?,?,?)",
    #             [sqlite3.Binary(b), sqlite3.Binary(b), sqlite3.Binary(b), sqlite3.Binary(b), sqlite3.Binary(b),
    #              sqlite3.Binary(b), sqlite3.Binary(b)])
    # con.commit()
    # print(cur.execute("select * from test").fetchall())
    #
    # unpackb(packb(999999999.88888888)) == 999999999.88888888
    #len(packb(999999999.8888888890))  == 9 #decimal #999999999 ==5 999999999012 ==9 999999999012.12345678 ==9
    # Decimal(unpackb(packb(999999999012.12345678)))
    #len((('999999999012.12345678'.encode())))
    #Decimal((b'999999999012.12345678').decode())

    def unpackPtx(self, ptx):
        try:
            uptx = []
            tptx = []
            print("tptx", type(ptx))
            if isinstance(ptx, tuple):
                tptx = list(ptx)
            for f in tptx:
                if isinstance(f, list):
                    #print("f", f)
                    uptx.append([self.Utils.unpackv(ff) if isinstance(ff, bytes) else ff for ff in f])
                else:
                    #print("f str", self.Utils.unpackv(f))
                    uptx.append(self.Utils.unpackv(f))
            return tptx
        except Exception as ex:
            print("Exception transaction unpackPtx", ex.__traceback__.tb_lineno, ex)
            return None
        return None if len(uptx) > 0 else uptx

    #todo to change verfySig, lenght, childs not exist in DB
    def verifyMsg(self, signed_msg_hash, decoded_msg):
        try:
            valid = False #to validate that from2nd char not exist in db [1:] allMsgType check
            ##msg_hash = self.Crypto.to_HMAC(packb(decoded_msg))
            ##print("Transaction verifyMsg msg", msg_hash, unpackb(decoded_msg))
            print("decoded_ptx", self.unpackPtx(decoded_msg))
            if decoded_msg[1] == self.Config.MsgType.PARENT_TX_MSG:
                 ptx_inputs =  self.arePtxInputsValid(signed_msg_hash, decoded_msg)
                 res = not self.DB.isDBkey(signed_msg_hash) and ptx_inputs
                 valid = True if res else False
                 if valid:
                     print("Ptx %s inputs valid - TODO verify amounts of \n%s\n" % (signed_msg_hash, ptx_inputs))
                 else:
                     print("Ptx %s inputs INVALID" % (signed_msg_hash))
                 return valid
            elif decoded_msg[1] == self.Config.MsgType.BLOCK_MSG:
                print("%s New Block Request -TODO" % self.Utils.utc_timestamp())
                pass
            elif decoded_msg[1] == self.Config.MsgType.CONTRACT_TX:
                pass #todo continue
            else:
                return False
        except Exception as ex:
            print('Exception Transaction ErrorLine: ', ex.__traceback__.tb_lineno, ex)
            return False



    def isMsgValid(self, bin_msg):
        if len(bin_msg) > self.Config.MAX_MSG_SIZE_BYTES:
            return False
        try:
            pk = unpackb(bin_msg)[1] #validate correct packaging
            wlt = self.Utils.getWalletAddr(pk)
            return self.DB.isDbWalletExist(wlt)
        except:
            print('transaction.py isMsgValid ERROR: Failed to unpack Public/Verifying Key')
            return False


    def validateMsg(self, bin_msg): #used for tmp persistance handled by tasks
        #print('ValidateMsg...')
        #TODO verifyWalletSenderExist
        # isinstance(VerifyKey(unpackb(bin_msg)[1]), VerifyKey) #pub_k hash
        #and
        #self.DB.isDBvalue( VerifyKey((unpackb(bin_msg)[1]))._key ) #pub_k hash
        #or?
        # self.DB.isDBvalue(tools.to_HMAC(unpackb(bin_msg)[1])) #pub_k hash

        #check that wallet exist and msg(duplicate) not exist
        #msg__db_wallet = tools.b(tools.to_HMAC(VerifyKey(bin_msg[-32:])._key))
        #msg_db_hash = tools.b(tools.to_HMAC( bin_msg[:-32])) #msg_hash


        try:
            if len(bin_msg) > tools.MsgType.MAX_MSG_SIZE_BYTES:
                return False
            # if self.DB.isDBvalue(tools.to_HMAC(bin_msg)): # double spent check -> verifiedByNode onAcceptMsg
            #     return False
            #TODO if msg is list -> type(unpackb(bin_msg)) is list -> elem unpackb is Tuple
            unpacked_msg = unpackb(bin_msg) #if not isinstance(bin_msg, tuple) else bin_msg
            if not len(unpacked_msg) == 2 or not isinstance(unpacked_msg[1], bytes) or not isinstance(unpacked_msg[1], bytes):
                return False
            addr_exist = tools.getDbKey("W" + tools.to_HMAC(unpacked_msg[1]))
            if addr_exist is None:
                return False
            return True

            # msg = tuple(unpackb(unpacked_msg[0]))
            # decoded_msg = tools.decodeMsg(msg)
            # if decoded_msg is None:
            #     return False
            # if not self.validateMsgSize(decoded_msg[1], bin_msg):
            #     return False

            # if type(unpacked_msg[1]) is not VerifyKey:
            #     vk = VerifyKey(unpacked_msg[1])
            # if decoded_msg[1] == tools.MsgType.PARENT_TX_MSG:
            #    return tools.validateTX(decoded_msg) #, unpacked_msg[1], vk): #self.to_HMAC(bin_msg)
            # elif msg[1] == tools.MsgType.BLOCK_MSG: #tools #TODO add decoderByMsgType
            #     print('################## NEW BLOCK TODO ##################')
            #     return tools.validateBlock(msg)
            #     #TODO insert SDB block
            #     #return msg #, unpacked_msg[-2], unpacked_msg[-1]
            # else:
            #     return False
        except Exception as ex:
            #print(tools.logger.exc_info())
            print('ErrorLine: ',ex.__traceback__.tb_lineno)
            return False


    def validateTX(self, tx_msg, pub_key=None, verifyTX=False): #TODO
        #print('ValidateTX...')
        try:
            if type(self) is Tools:
                tx_msg_fields = self.TX_MSG_FIELDS
                tx_msg_fields_index = self.TX_MSG_FIELDS_INDEX
            else:
                tx_msg_fields = self.TX_MSG_FIELD_TYPE
                tx_msg_fields_index = self.TX_MSG_INDEX_FIELD
            tx_field_names = list(tx_msg_fields_index.values())[:-2] #fields amount
            for i in range(len(tx_field_names)):
                field_value = tx_msg[i]
                if type(field_value) is not tx_msg_fields[tx_field_names[i]]: #fields type
                    print('ERROR: field type %s, expected %s' % (type(field_value), tx_msg_fields[tx_field_names[i]]))
                    return False
                if (type(field_value) is list):
                    restricted_list_types = [v for v in field_value if type(v) not in (bytes, str)] #list_fields type
                    if len(restricted_list_types) > 0:
                        print('ERROR: restricted_list_types %s', restricted_list_types)
                        return False
            return tx_msg
        except Exception as ex:
            return False


#tools
    def signTX(self, version, msg_type, input_txs, to_addrs, asset_type, amounts, tx_fee, pub_keys=[b"*" * 32], seed=b"*" * 32):
        try:
            tx = self.setTX(version, msg_type, input_txs, to_addrs, asset_type, amounts, tx_fee, pub_keys)
            if tx is not None and self.validateTX(tx):
                sk = self.Crypto.getKeysFromSeed(seed)
                signed_msg = self.Crypto.signMsg(packb(tx[:-2]), sk)
                return signed_msg
        except Exception as ex:
            return None

    #
    # def signTX(self, tx_msg, pub_keys=b"*" * 32, seed=b"*" * 32):
    #     try:
    #         tx = self.setTX(version, msg_type, input_txs, to_addrs, asset_type, amounts, pub_keys)
    #         if tx is not None and self.validateTX(tx):
    #             sk, vk = tools.getKeysFromSeed(seed)
    #             signed_msg = self.Utils.signMsg(packb(tx[0]), sk)
    #             bin_signed_msg = (signed_msg.message, signed_msg.signature, vk._key)
    #             return bin_signed_msg
    #     except Exception as ex:
    #         return None

    def sendMsg(self, bin_signed_msg, host='localhost', port=7777):
        #TODO to continue with NewBlock ->New Wallet
        #sk = msg[1] if type(msg[1]) is SigningKey else SigningKey(msg[1])
        #vk = msg[2] if type(msg[2]) is VerifyKey else VerifyKey(msg[2])
        #signed_msg = self.Utils.signMsg(packb(msg[0]), sk)
        #bin_signed_msg = (signed_msg.message, vk._key)if
        if bin_signed_msg is not None:
            return self.Net.sendMsgZmqReq(bin_signed_msg, host, port)

    def sendTX(self, version, msg_type, input_txs, to_addrs, asset_type, amounts, seed=None, host=None, port=None, sendTx=True):
        bin_signed_msg = self.signTX(version, msg_type, input_txs, to_addrs, asset_type, amounts, seed=seed)
        if bin_signed_msg is not None and host is not None and port is not None:
            if sendTx and bin_signed_msg is not None:
                self.Net.sendMsgZmqReq(packb(bin_signed_msg), host, port)
        return bin_signed_msg


    def submitTX(self, tx, seed=None, host=None, port=None, submitTx=True):
        bin_signed_msg = self.signTX(tx[0], tx[1], tx[2], tx[3], tx[4], tx[5], tx[6], seed=seed)
        if bin_signed_msg is not None and host is not None and port is not None:
            if submitTx:
                self.Net.sendMsgZmqReq(packb(bin_signed_msg), host, port)
        return bin_signed_msg


    def decodeDbMsg(self, bin_msg):
        try:
            return self.decodeMsg(unpackb(unpackb(bin_msg)[0]))
        except:
            return None


    #tools methods
    def insertDbTx(self, bin_signed_msg, msg_type='*', override=False):
        print('version', self.Utils.s(unpackb(bin_signed_msg[0])[0]))
        print('msgType', self.Utils.s(unpackb(bin_signed_msg[0])[1]))
        print('txType', self.Utils.s(unpackb(bin_signed_msg[0])[2][0])[0:1])
        print('inputTx', self.Utils.s(unpackb(bin_signed_msg[0])[2][0])[1:])
        tx_hash = self.Crypto.to_HMAC(packb(bin_signed_msg))
        tx_bytes = packb(bin_signed_msg)
        valid_msg = self.validateMsg(tx_bytes)
        #for itx in (unpackb(bin_signed_msg[0])[2]:
        #    if tools.is
        if valid_msg:
            return self.DB.insertDbKv(tools.b(tx_hash), tx_bytes, tools.NODE_DB, override) #tools.b(msg_type + tx_hash)
        else:
            return None


    def stx2btx(self, stx):
        try:
            list_fields_names = [k for k in self.TX_MSG_FIELD_TYPE
                                 if self.TX_MSG_FIELD_TYPE[k] is list]
            list_field_indexes = [k for (k, v) in self.TX_MSG_INDEX_FIELD.items() if
                                  v in list_fields_names and v in self.TX_MSG_INDEX_FIELD.values()]
            list_stx = list(stx)
            for i in list_field_indexes:
                list_stx[i] = list_stx[i][1:-1].split(",")
            tx_fields_len = len(self.TX_MSG_INDEX_FIELD.keys())
            sdb_tx = tuple(list_stx[:tx_fields_len])
            btx = (packb(sdb_tx[0]), sdb_tx[-2], sdb_tx[-1])
            btx_hash = self.Crypto.to_HMAC(packb((packb(sdb_tx[:-2]), sdb_tx[-2], sdb_tx[-1])))
            return packb(btx), btx_hash
        except Exception as ex:
            err_msg = 'Exception Transaction.stx2btx Failed to convert TX from sqlDb into levelDB format(b): %s, %s' % (
            Logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            print(err_msg)
            return None


    def btx2stx(self, bmsg):
        try:
            stx = self.decodeDbMsg(bmsg)
            sig = unpackb(bmsg)[1]
            pubk = unpackb(bmsg)[2]
            sdb_tx = stx
            sdb_tx += (sig,)
            sdb_tx += (pubk,)
            btx = packb(stx), sig, pubk
            btxp = packb(btx)
            stx_hash = self.Crypto.to_HMAC(btxp) #TODO cryptoPubK
            return sdb_tx, stx_hash
        except Exception as ex:
            return None


    def sdbtx2btx(self, sdb_msg_hash):
        try:
            stx = self.SDB.queryServiceDB("select * from v1_pending_tx where msg_hash='%s'" % sdb_msg_hash)
            if len(stx) != 1:
                return None
            stx = stx[0]

            return self.Utils.stx2btx(stx)
        except Exception as ex:
            err_msg = 'Exception Transaction.sdbtx2btx Failed to convert TX from sqlDb into levelDB format(b): %s, %s' % (
            Logger.exc_info(), ex)
            #self.logger.logp(err_msg, logging.ERROR)
            print(err_msg)
            return None


    def dbtx2stx(self, db_msg_hash):
        try:
            bmsg = self.DB.getDbRec(db_msg_hash)
            if bmsg is None:
                return None
            return self.btx2stx(bmsg)
        except Exception as ex:
            err_msg = 'Exception Transaction.dbtx2sdbbtx Failed to convert TX from LevelDB to sqlDb format(b): %s, %s' % (
            Logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            print(err_msg)
            return None



    def getServiceDbTx(self, msg_hash, unique=True):
        try:
            records = self.SDB.queryServiceDB("select * from v1_pending_msg where signed_msg_hash='%s'" % msg_hash)
            print('%s Records Found' % len(records))
            if len(records) == 0:
                return None
            else:
                res = records[0] if unique else records
                return res
        except: pass
        # except Exception as ex:
        #     print("SDB Error: %s" % ex)
        #     return None



    def getTxAmount(self, stx):
        try:
            asset_field_index = list(self.TX_MSG_INDEX_FIELD.values()).index('asset_type')
            asset_type = stx[asset_field_index]
            amounts_field_index = list(self.TX_MSG_INDEX_FIELD.values()).index('amounts')
            list_amounts = (stx[amounts_field_index][1:-1].split(","))
            decimal_list_amounts = [Decimal(x) for x in list_amounts]
            total_outputs_amount = (format(sum(decimal_list_amounts), '.8f'))
            #assert sum(decimal_list_amounts) == Decimal(format(sum(decimal_list_amounts), '.8f'))

            return asset_type, total_outputs_amount
        except Exception as ex:
            #TODO logger
            return None



    def verifyTX(self, ptx_msg):
        pass


    #TODO verifyBlock or sdb_msg_limit
    def isPtxExist(self, ptx_msg):
        ptx_hash = self.Crypto.to_HMAC(packb(ptx_msg))
        return self.DB.isDBkey(ptx_hash, print_caller='verifyPTX')


    def arePtxInputsValid(self, ptx_hash, ptx_msg, itxs_list = []):
        try:
            print("Transaction arePtxInputsValid msg", ptx_msg, "\n", itxs_list)
            invalid = False
            if len(itxs_list) > 0:
                msg_inputs = itxs_list
            else:
                #ptx_hash = self.Config.MsgType.PARENT_TX_MSG.decode() + self.Crypto.to_HMAC(packb(unpacked_ptx_msg))
                inputs_idx = self.TX_MSG_FIELD_INDEX["input_txs"]
                msg_inputs = list(set([utxi.decode() for utxi in [unpackb(inp)[2] for inp in ptx_msg[2]] for utxi in utxi]))
                    #list(set([j.decode() for j in [i[inputs_idx] for i in ptx_msg[inputs_idx]] for j in j]))
            for inp in msg_inputs:

                #print("self.DB.isDBvalue? [inp[1:]] %s - %s" % ((inp[1:], self.DB.isDBvalue(inp[1:]))))
                # print("self.DB.isDBvalue? ['*' + inp[1:]] %s - %s" % (("*" + inp[1:], self.DB.isDBkey("*" + inp[1:]))))
                # print("self.DB.isDBvalue? ['-' + inp[1:]] %s - %s" % (("-" + inp[1:], self.DB.isDBkey("-" + inp[1:]))))
                # print("self.DB.isDBvalue? ['+' + inp[1:]] %s - %s" % (("+" + inp[1:], self.DB.isDBkey("+" + inp[1:]))))

                #todo range query[1:] + configMsgType + delPrintCaller
                if self.DB.isDBkey("*" + inp[1:], print_caller='arePtxInputsValid') and \
                   self.DB.isDBkey("-" + inp[1:], print_caller='arePtxInputsValid') and \
                   not self.DB.isDBkey("+" + inp[1:], print_caller='arePtxInputsValid'):

                    print("CTX %s of PTX %s is invalid - exist in DB" % (inp[1:], ptx_hash))
                    invalid = True
                    return False
                    #raise Exception("CTX %s of PTX %s is invalid - exist in DB" % (inp[1:], ptx_hash))

                #if invalid: return False #break
            res = msg_inputs if not invalid else False
            print("PTX %s is valid=%s, \ninputs: %s\n" % (ptx_hash, ('True' if not invalid else 'False'), msg_inputs))
            return res
        except Exception as ex:
            print("Exception Transaction arePtxInputsValid: %s %s" % (ex.__traceback__.tb_lineno, ex))
            #tools.printStackTrace(ex)
            return False

    # @staticmethod
    def persistTX4verify():
        pass

    def ptx2btx(self):
        pass

    # @staticmethod
    def persistTX(): #from pending sqlLite to LevelDB + insertUnspentTx after blockVoted & verified
        pass

    def deletePtx(self): #delete from pending DB after block & TXs have been persisted
        pass

    def relayTX(self, tx_list): #relay to MasterNode if not is Master myself
        pass

    def getTX(self, tx_hash): # query if TX exist in DB used for confirmations, verifications and DoubleSpent check
        pass
