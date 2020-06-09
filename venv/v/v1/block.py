import os, sys, json
from msgpack import packb, unpackb
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from Crypto.Hash import SHA256, HMAC
from decimal import Decimal
from v1 import logger, config, node, crypto, network, web, \
                 sdb, db, wallets, transaction, message, \
                 contract, ico, exchange, utils

class Block():
    _batch_data = []

    # def get_batch_data(self):
    #     return type(self)._batch_data
    #
    # def set_batch_data(self, val):
    #     type(self)._batch_data = val
    #
    # def reset_batch_data(self, val):
    #     type(self)._batch_data = val
    #
    # batch_data = property(get_batch_data, set_batch_data)

    def __init__(self, block=None):
        #self.logger = L.Logger() #('Transaction')
        self.Config = config.Config
        self.version = self.Config.VERSION
        self.Utils = utils.Utils()
        self.Crypto = crypto.Crypto()
        self.Net = network.Network()
        self.DB = db.Db() #tools.config.NODE_DB
        self.SDB = sdb.ServiceDb()
        self.Wallets = wallets.Wallet()
        self.Ico = ico.Ico()
        self.Tx = transaction.Transaction()
        self.BLOCK_MSG_FIELD_TYPE = {'version': bytes, 'msg_type': bytes, 'block_num': int, 'prev_block_hash': bytes, 'input_msgs': list,
                                 'miners_votes': list, 'block_utc_time': bytes, 'miner_pub_key': bytes} #'prev_block' hash used to generate current blockhash
        self.BLOCK_MSG_INDEX_FIELD = {0: 'version', 1: 'msg_type', 2: 'block_num', 3: 'prev_block_hash', 4: 'input_msgs',
                                      5: 'miners_votes', 6: 'block_utc_time',  7: 'miner_pub_key'} #minerPubK is ALWAYS last field in msg or msgList
        self.BLOCK_MSG_FIELD_INDEX = {'version': 0, 'msg_type': 1, 'block_num': 2, 'prev_block_hash': 3,
                                       'input_msgs': 4, 'miners_votes': 5, 'block_utc_time': 6,
                                       'miner_pub_key': 7}  # minerPubK is ALWAYS last field in msg or msgList
        self.verified_block = {"block_id": None, "msg_list": set(), "inputs_list": set()}
        self.last_block_number = self.getLastBlockNumber()



        bk = [v for v in self.BLOCK_MSG_INDEX_FIELD if v not in self.BLOCK_MSG_FIELD_TYPE]
        assert len(bk) > 0#todo disable
        if len(bk) > 0:
            return None
        if block is not None:
            f_i = [v for v in self.BLOCK_MSG_INDEX_FIELD]
            b_k = block.keys()
            f_k = [v for v in b_k if v not in f_i]
            assert len(f_k) == 0 #todo disable
            if len(f_k) > 0:
                return None


    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Block, cls).__new__(cls)
        return cls.instance


    def getBlockFieldIndex(self, field_name):
        if not field_name in self.BLOCK_MSG_INDEX_FIELD.values():
            return None
        return self.BLOCK_MSG_FIELD_INDEX(field_name)



    def getBlockFieldValue(self, block_obj, field_name):
        fields_index = self.getBlockFieldIndex(field_name) #[v for v in self.BLOCK_MSG_INDEX_FIELD if v == field_name]
        if not fields_index is None: #len(fields_index) == 1:
            return block_obj[fields_index] #
        else:
            return None


    def getLastBlockNumber(self):
        try:
            with open("last_saved_block", "r") as last_block:
                blk_obj = json.loads(last_block.read())
                self.last_block_number =  blk_obj[blk_obj.keys()[0]]
        except:
            self.last_block_number = 0
        return self.last_block_number


    def saveLastBlockState(self, block_id):
        if len(block_id) !=33:
            return None
        with open("last_saved_block", "w") as last_block_id:
            #last_block_id.write(db_last_saved_block_hash)
             last_block_id.write(json.dumps({"block_hash": block_id, "block_id": self.getLastBlockNumber() + 1}))
             return True
        return False


    def getBlockId(self, block_msg_hash):
        return config.Config.MsgType.BLOCK_MSG + block_msg_hash.encode()

    def getLastBlockId(self, hash_id=True):
        try:
            with open("last_saved_block", "r") as last_block_id:
                block = json.loads(last_block_id.read())
                block_hash_id = block["block_hash"]
                block_id = block["block_id"]
                if len(block_hash_id) == 33:
                    return block_hash_id
                return None
        except:
            return None


    def saveBlockMissingMsgs(self, msg_hash):
        if not os.path.exists("missing_msgs"):
            with open("missing_msgs", "w") as complete_missing_first:
                complete_missing_first.write(msg_hash)
        else:
            with open("missing_msgs", "a") as complete_missing_first:
                complete_missing_first.write(msg_hash)


    def insertBlock(self, block_hash, block_msg_bin):
        try:
            block_id = self.Config.MsgType.BLOCK_MSG.decode() + block_hash
            self.DB.insertDbKv(block_id, block_msg_bin)  # saveBlockInDb
            self.saveLastBlockState(block_id)
            return block_id
        except Exception as ex:
            print("INSERT BLOCK EXCEPTION: %s line %s" % (ex, ex.__traceback__.tb_lineno))
            return None


    def sendBlock(self): #by MasterMiner
        pass

    def voteBlock(self):#to MasterMiner or NextOnDutyMiner
        pass


    @staticmethod
    def validateBlock(block_msg):
        #print('ValidateBlock...')
        try:
            if len(block_msg) > config.Config.BLOCK_MSG_MAX_SIZE:
                return False
            if utils.Utils.isVersionCompatible(block_msg) is False:
                return False
            block_umsg = block_msg
            if isinstance(block_umsg, bytes):
                block_umsg = unpackb(block_msg)
            if not block_umsg[1] == config.Config.MsgType.BLOCK_MSG:
                return False

            block_msg_fields = Block().BLOCK_MSG_FIELD_TYPE  # TODO getMsgFields(msgType) + msgLimit
            block_msg_fields_index = Block().BLOCK_MSG_FIELD_INDEX
            block_field_names = list(block_msg_fields_index.keys())  # [0] #fields amount
            for i in range(len(block_field_names) - 1): #-1 is MsgSig, verified prev
                field_value = block_umsg[i]
                ##if type(field_value) is not block_msg_fields[block_field_names[i]]:  # fields type
                ##    return False
                if (type(field_value) is list):
                    for field in field_value:
                        # restricted_list_types = [v for v in list_value if type(v) not in (bytes, str, list)] #list_fields type
                        # if len(restricted_list_types) > 0:
                        # return False
                        if len(field) != 33: # or type(field) is not bytes:  # 1b msgType + 32b hashId
                            return False #TODO fieldType in MsgTypes

                return block_umsg
            else:
                return False
        except Exception as ex:
            print('block.py validateBlock ErrorLine: ', ex.__traceback__.tb_lineno, ex)
            return False


#todo to continue #tools.isDBvalue(msg_list[4][0]) + verifyTXs/msgs/other types
    def verifyBlock(self, msg_list, block_hash):
        if not isinstance(msg_list, list) or not msg_list:
            return False

        if db.Db.getDbKey(packb(block_hash)) or \
                db.Db.getDbKey(packb(tools.MsgType.BLOCK_MSG + block_hash)) or \
                db.Db.getDbKey(packb(msg_list[1] + packb(block_hash))):
            return False #TODO verify miner sig/turn + prevBlockExist + PTX exist and not Spent

        ptx_list = [db.Db.getDbKey(ptx[transaction.Transaction().TX_MSG_INDEX_FIELD["input_txs"]]) for ptx in msg_list]
        if len(ptx_list) < len(ptx[transaction.Transaction().TX_MSG_INDEX_FIELD["input_txs"]]):
            pass #TODO getFromMinersMissingPTXs + wait 5sec for response? (withPriorityQ)
            ptx_list = [db.Db.getDbKey(ptx[transaction.Transaction().TX_MSG_INDEX_FIELD["input_txs"]]) for ptx in msg_list]

        if len(ptx_list) <= 0 or len(ptx_list) < len(ptx[transaction.Transaction().TX_MSG_INDEX_FIELD["input_txs"]]):
            return False # reject Block

        return True
        msg_list_persist = []
        msg_hash = crypto.Crypto.to_HMAC(packb(msg_list))
        # block_hash = tools.MsgType.BLOCK_MSG + hash_list
        # if tools.isDBvalue(hash_list) or tools.isDBvalue(block_hash):
        #     return False
        # for msgtype in msg_list:
        #     valid_msg = tools.validateMsg(msgtype)
        #     if not valid_msg:
        #         return False
        #     if not tools.verifyMsg(valid_msg):
        #         return False
        #     #TODO get/add additional recs to persist byType -> tx + spent- unspent...
        # return msg_list_persist


    def getBlock(self, block_hash_or_num): #get block msg
        pass

    #@staticmethod
    def persistBlock(self, msgtype_arr):
        verified_block = self.verifyBlock(msgtype_arr)
        if verified_block and type(verified_block) is list:
            print('TO_IMPLEMENT PERSIST TXs -> RM SDB')
            pass

    def block2db(self, verified_decoded_block):
        #validateVerifyEachMsg
        #ignore/return  ifNotAssertedValidatedVerified
        #persistTx -> createOrUpdateWallet
        #persistBlock
        # persistUnspentTxs | Msgs ... other types
        pass


    # def saveBlock(self, msg): #test
    #     signed_msg_hash = self.Crypto.to_HMAC(msg[1])
    #     signed_msg = msg[1]
    #     # signed_msg_hash = self.Crypto.to_HMAC(signed_msg)
    #     print('transport_hash: %s, signed_msg_hash: %s' % (self.Crypto.to_HMAC(m), signed_msg_hash))
    #     pubk = msg[1][-32:]
    #     if True: #node.isNodeValid("W" + self.Crypto.to_HMAC(pubk)):
    #         if msg[0] == self.Config.MsgType.BLOCK_MSG:
    #             msg_list = set()
    #             block_persist_msgs = {}
    #             # todo change in block write ->bin msg
    #             smsg = msg[1]
    #             ##assert signed_msg_hash == self.Crypto.to_HMAC(block_bin[1])  # DON'T REMOVE [msg,sig] correct hmac validation
    #             nodeSig, blockMsg = self.Crypto.verifyMsgSig(smsg, pubk)
    #             ublock = unpackb(blockMsg)
    #             prev_block_hash = ublock[3]
    #             msg_type = m[3]
    #             msg_priority = m[-2]
    #             # print("ublock: %s\n%s\n" % (ublock, [unpackb(inp[2][2])[2] for inp in [m for m in ublock[4]]])) #[unpackb(inp[2][2])[2] for inp in [m for m in ublock[4]]] [inp[2] for inp in [m for m in ublock[4]]]
    #             ##print("Duplicates found in Block = %s" % len(ublock[4]) == len(set(ublock[4])))
    #             print("self.DB.getDbRec(prev_block_hash)", prev_block_hash, self.DB.getDbRec(prev_block_hash))
    #             if not self.DB.getDbRec(prev_block_hash) or \
    #                     self.DB.getDbRec(config.Config.MsgType.BLOCK_MSG + signed_msg_hash.encode()) \
    #                     or len(ublock) < 6 or not nodeSig:  # none or duplicate check
    #                 err_msg = "BLOCK (%s) IS INVALID" % signed_msg_hash
    #                 print(err_msg)
    #                 #self.TASKS.deleteSdbInvalidMsqQ.add(signed_msg_hash)
    #                 #continue
    #                 # todo supposed to ignore irrelevant block or block with missing msgs
    #
    #             block_msg_hashes = [m.decode() for m in [msg for msg in ublock[4]]]
    #             verified_sql = "select signed_msg_hash from v1_verified_msg where signed_msg_hash in (%s)" % (
    #                 ",".join(["'%s'" % m for m in block_msg_hashes]))
    #             print("verified_sql", verified_sql)
    #             verified_msgs = self.SDB.queryServiceDB(verified_sql)
    #             verified_msg_hashes = [m[0] for m in verified_msgs]
    #             if len(verified_msg_hashes) != len(block_msg_hashes):  # TODO compare set of hashes
    #                 missing_msgs = list(set(block_msg_hashes) - set(verified_msg_hashes))
    #                 print(
    #                     "Error: Not Enough verified msgs -> If not in pending -> get missing - else verify/update priority")
    #                 # print("Missing Block msgs: ", block_msg_hashes & verified_msg_hashes)
    #                ## continue
    #
    #             print("All Block msgs are exist in SDB", block_msg_hashes)
    #             verified_sql = "select * from v1_verified_msg where signed_msg_hash in (%s)" % (
    #                 ",".join(["'%s'" % m for m in block_msg_hashes]))
    #             print(verified_sql)
    #             verified_msgs = self.SDB.queryServiceDB(verified_sql)
    #
    #             block_senders_wallets = []
    #             block_recievers_wallets = []
    #             ptxs_count = len(block_msg_hashes)  # (ublock[4])
    #             print(verified_msgs)
    #             for i in range(ptxs_count):
    #                 msg_sender_wallet = "W" + self.Crypto.to_HMAC(verified_msgs[i][3])  # .encode()
    #                 if not msg_sender_wallet in block_persist_msgs.keys():  # block_senders_wallets.keys():
    #                     msg_sender_wallet_data = self.Wallets.getDbWalletDefault(msg_sender_wallet)
    #                     block_senders_wallets.append \
    #                         (msg_sender_wallet)  # [msg_sender_wallet] = msg_sender_wallet_data
    #                     block_persist_msgs[msg_sender_wallet] = msg_sender_wallet_data
    #                 else:
    #                     raise Exception("Only 1 PTX permitted per block")  # todo msgType
    #                 # TODO msg=PTX?
    #                 msg_inputs_ids = list(set([inp.decode() for inp in [itx[2]
    #                                                                     for itx in [unpackb(m) for m in unpackb(
    #                         verified_msgs[i][2])[2]]] for inp in
    #                                            inp]))  # todo validate calc vs submitted or ignore? in-msg ctx hashes
    #                 print('Msg inputs hashes: ', len(msg_inputs_ids), msg_inputs_ids)
    #                 marked_spent_itxs, updated_wallet, db_updates = self.Wallets.markSpentTxRecordsInTheWallet \
    #                     (msg_inputs_ids, block_persist_msgs[msg_sender_wallet], "B" + signed_msg_hash)
    #                 if not marked_spent_itxs or db_updates is None:
    #                     raise Exception("All/Some inputs \n%s\n are missing in the Wallet %s" %
    #                                     (msg_inputs_ids, msg_sender_wallet))
    #
    #                 # block_senders_wallets[msg_sender_wallet] = updated_wallet
    #                 block_persist_msgs[msg_sender_wallet] = updated_wallet
    #                 block_persist_msgs = {**block_persist_msgs, **db_updates}
    #                 ##for k, v in db_updates.items():
    #                 ##    block_persist_msgs[k] = v
    #
    #                 msg_ctxs = [unpackb(m) for m in unpackb(verified_msgs[i][2])[2]]
    #                 ctx_receivers_wallets = [r_w[3] for r_w in msg_ctxs]
    #                 ctx_assets = [r_w[4] for r_w in msg_ctxs]
    #                 ctx_assets_u = set(ctx_assets)
    #                 ctx_receivers_wallets = [w.decode() if isinstance(w, bytes) else w for w in
    #                                          ctx_receivers_wallets]
    #                 for wallet in ctx_receivers_wallets:
    #                     if not wallet in block_persist_msgs:  # block_recievers_wallets.keys():
    #                         ##wallet = wallet.encode() if isinstance(wallet, str) else wallet
    #                         ##block_recievers_wallets[wallet] = (tools.getDbWalletDefault(wallet))
    #                         block_persist_msgs[wallet] = self.Wallets.getDbWalletDefault(wallet)
    #                         block_recievers_wallets.append(wallet)
    #
    #                 msg_ctxs_pubkeys = [m[2] for m in verified_msgs]
    #                 ptx_hash = block_msg_hashes[i]
    #                 for m in range(len(msg_ctxs)):
    #                     ctx_hash = self.Crypto.to_HMAC(packb((msg_ctxs[m], msg_ctxs_pubkeys[0])))
    #                     ctx_msg = packb((msg_ctxs[m], msg_ctxs_pubkeys[0]))
    #                     ctx_reciever = msg_ctxs[m][3].decode() if isinstance(msg_ctxs[m][3], bytes) else \
    #                         msg_ctxs[m][3]
    #                     ctx_asset = msg_ctxs[m][4]
    #                     ctx_asset_amount = Decimal(msg_ctxs[m][
    #                                                    5].decode())  # todo to_miner_pool fee + Decimal(msg_ctxs[m][6].decode())
    #                     ##block_recievers_wallets = [b.decode() if isinstance(b, bytes) else b for b in block_recievers_wallets]
    #                     if not ctx_reciever in block_persist_msgs:  # block_recievers_wallets:
    #                         raise Exception(
    #                             "CTX reciever %s doesnt exist in block_recievers_wallets" % ctx_reciever)
    #                         block_persist_msgs[ctx_reciever]["assets"][ctx_asset]["inputs"].append(
    #                             ["+" + ctx_hash, str(ctx_asset_amount).encode(), "+" + ptx_hash])
    #                     # block_persist_msgs["*" + ctx_hash] = ctx_msgblock_recievers_wallets
    #                     block_persist_msgs["+" + ctx_hash] = "+" + ptx_hash
    #                     ##block_persist_msgs[ctx_reciever] = block_recievers_wallets[ctx_reciever]
    #                     print("Block %s PTX: %s \nInputs: %s \nCTX: %s \nMsg: %s " % (
    #                         "B" + signed_msg_hash, ptx_hash, msg_inputs_ids, ctx_hash, msg_ctxs[m]))
    #                 # todo 1outer level +bin-msg
    #                 block_persist_msgs["+" + ptx_hash] = "B" + signed_msg_hash
    #                 block_persist_msgs["*" + ptx_hash] = verified_msgs[i][1]
    #
    #             print("Block %s msg_hashes: %s %s" % (
    #                 signed_msg_hash, len(block_msg_hashes), block_msg_hashes))
    #             print("%s (msg/ptx) inputs: %s" % (ptxs_count, msg_ctxs))
    #
    #             # Todo add to blockBatch
    #             # Block is valid and msgs already verified!!!
    #             self.SDB.saveSdbVerifiedMsg(signed_msg_hash, msg[1][0], blockMsg, pubk, msg_type,
    #                                         msg_priority)
    #             # TODO
    #             print("TODO######Update Wallets#####wallets state+ block_hash######")
    #             #self.TASKS.deleteSdbVerifiedMsqQ.add(signed_msg_hash)
    #             # TODO raise exception/ignore if there are missing transactions, invalid...
    #
    #             block_msg_hashes.append(signed_msg_hash)
    #             # todo? change saving blockchain verified_msg into signed_msg -> Sig 1000request/sec WebLoad
    #             # todo currently ptxs only
    #             verified_sql = "select * from v1_verified_msg where signed_msg_hash in (%s)" % (
    #                 ",".join(["'%s'" % m for m in block_msg_hashes]))
    #
    #             block_ptx_inputs = set()
    #             block_senders = set()
    #             try:
    #                 for msg in verified_msgs:  # todo redo validation hash(msg,pubk)
    #                     umsg = unpackb(msg[2])
    #                     # msg_sender_wallet = b"W" + self.Crypto.to_HMAC(umsg[-1]).encode()
    #                     # msg_sender_wallet_data = tools.getDbWalletDefault(msg_sender_wallet)
    #                     # block_senders_wallets[msg_sender_wallet] = msg_sender_wallet_data
    #                     # if msg_sender_wallet in block_senders_wallets.keys(): #block_senders:
    #                     #    raise Exception("Only 1 PTX permitted pre block")
    #                     # block_senders.add(msg_sender_wallet.encode())
    #
    #                     msg_receivers_wallets = umsg[3]
    #                     for wallet in msg_receivers_wallets:
    #                         if not wallet in block_persist_msgs.keys():
    #                             msg_receiver_wallet_data = self.Wallets.getDbWalletDefault(wallet)
    #                             block_recievers_wallets.append(
    #                                 wallet)  # [wallet] = msg_receiver_wallet_data
    #                             block_persist_msgs[wallet] = msg_receiver_wallet_data
    #
    #                     # block_senders_amounts[msg_sender_wallet] = tools.WALLET.getDbWalletUnspentAmounts(msg_sender_wallet)
    #                     # print("msg_sender_wallet", msg_sender_wallet, tools.WALLET.getDbWalletUnspentAmounts(msg_sender_wallet))
    #                     itx_list_u = set(
    #                         [item for item in [unpackb(itx)[2] for itx in umsg[2]] for item in item])
    #                     ##ptx_assets = [unpackb(itx)[4] for itx in umsg[2]]
    #                     print("PTX itx_list_u", itx_list_u)
    #                     for itx in itx_list_u:
    #                         if itx in block_ptx_inputs:  # duplicate
    #                             raise Exception("PTX Duplicate Inputs/Spendings")
    #                         block_ptx_inputs.add(itx)
    #                         if len(block_ptx_inputs) == 0:
    #                             raise Exception("PTX Missing Inputs")
    #                         print('itx[1:]', itx[1:])
    #                         block_persist_msgs["-" + itx[1:]] = "B" + signed_msg_hash
    #                         # todo to continue last
    #
    #                     print("block_ptx_inputs", block_ptx_inputs)
    #                     msg_bin = packb((msg[1], msg[2]))
    #                     msg_hash = msg[0]  # todo recalc hash validation
    #                     block_persist_msgs["*" + msg_hash] = msg_bin
    #                 if len(block_persist_msgs) == 0:
    #                     raise Exception('Block missing PTXs/msgs?')
    #                 if len(set(block_senders_wallets)) != ptxs_count:
    #                     raise Exception("Block Permits 1 PTX per Wallet")
    #                 block_persist_msgs["B" + signed_msg_hash] = blockMsg  # add blockMsg itself
    #                 # block_persist_wallets = {}
    #                 print("DB_Batch: ", block_persist_msgs)  # .keys())
    #                 print("#####TODO -outer in start BlockCalcPtxHash #1",
    #                       self.Crypto.to_HMAC(packb((verified_msgs[0][1], (verified_msgs[0][3])))))
    #                 self.DB.insertDbBatchFromDict(block_persist_msgs)
    #                 # tools.SERVICE_DB.deleteBlockSdbVerifiedMsgs(block_persist_msgs.keys())
    #                 # block_persist_msgs = {}
    #                 # verify_q = []
    #                 print("%s Block deleteSdb Pending and Verified Msgs" % now)
    #                 self.SDB.deleteSdbPendingMsgsIfVerified()
    #                 self.SDB.deleteBlockSdbVerifiedMsgs(block_persist_msgs.keys())
    #                 self.SDB.deleteBlockSdbVerifiedMsgs([signed_msg_hash])  # del verified block
    #             except Exception as ex:
    #                 self.SDB.deleteSdbPendingMsgsIfVerified()
    #                 print("Block Exception: ", ex.__traceback__.tb_lineno, ex)
    #                 # continue #proceed to next msg
    #                 block_persist_msgs = {}
    #                 block_senders_wallets = []
    #                 block_recievers_wallets = []
    #                 raise Exception("Block Exception: ", ex)
    #                 # todo time<=blockchain time for each msg
