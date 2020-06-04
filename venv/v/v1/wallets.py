import os, sys
from decimal import Decimal
from msgpack import packb, unpackb
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
from v.v1 import logger, config, node, crypto, network, web, \
                 sdb, db, transaction, message, block, \
                 contract, ico, exchange, utils


class Wallet():
    wallets_path =  os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "WALLETS/")

    def __init__(self, version='1', pub_addr=None, sig_type='1/1', multi_sig_pubkeys=[], assets=[], msgs=[], contracts=[]):
        self.Config = config.Config
        self.VERSION = self.Config.VERSION
        self.Utils = utils.Utils()
        self.Net = network.Network()
        self.Crypto = crypto.Crypto()
        self.Db = db.Db()
        # self.Sdb = SDB.ServiceDb()
        self.pub_addr = pub_addr
        self.path = os.path.join(ROOT_DIR, "../../wallets")

        self.data = {}
        self.data['version'] = version  #pub_keys for multiSig, for 1sig is not required
        self.data['sig_type'] = sig_type
        self.data['multi_sig_pubkeys'] = multi_sig_pubkeys
        self.data['wallet_id'] = None #hash(pub_key._key)
        self.data['asset_msgs'] = {'asset_id': None, 'inputs': [], 'outputs': []}
        self.data['assets'] = assets #TODO create asset /later assets FX,Popular, ...etc
        self.data['msgs'] = msgs
        self.data['contracts'] = contracts
        self.WLT_DATA_FIELDS = {'version': str, 'sig_type': str, 'multi_sig_pubkeys': list, \
                                'wallet_id': str, 'assets': list, 'msgs': list, \
                                'contracts': list}
        self.WLT_DATA_FIELDS_INDEX = {0: 'version', 1: 'sig_type', 3: 'multi_sig_pubkeys', \
                                      4: 'wallet_id', 5: 'assets', 6: 'msgs', 7: 'contracts'}

    # TODO 4multisig, 4 1sig it's 1/1 + wallet generated from TX with fee deduction
    # TODo 4multisig wallets TX doesnt create wallet,
    #  but creationWithExistingPKaddrs required + WalletID_Hash = ALL_PKs_Hash
    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Wallet, cls).__new__(cls)
        return cls.instance

    # def func_wrapper(*args, **kwargs):
    #     try:
    #         return func(*args, **kwargs)
    #     except Exception as e:
    #         print("ExceptionDebug: %s\n%s " % (e, e.__traceback__.tb_lineno))
    #         return None
    #     return func_wrapper
    #
    #
    # def mkdir(self, dir):
    #     if not os.path.exists(dir):
    #         os.makedirs(dir)

    def isDbWalletExist(self, bin_msg):
        try:
            pk = unpackb(bin_msg)[1]
            if not self.Db.getDbRec(crypto.Crypto.to_HMAC(pk)):
                return False
            else:
                return True
        except:
            return False

    def getWalletId(self, pub_key):
        if not isinstance(pub_key, str):
            pub_key = crypto.Crypto.to_HMAC(pub_key)
        return self.Config.MsgType.WALLET.decode() + pub_key

    def getWalletchecksum(self):
        pass #used for updates

    def isPrevDataExist(self):
        pass  # used


    #TODO sync db&local wallets
    def createWallet(self, pubkey_hash, local=False):
        #print("CreateWallet pubkey_hash_id: ", pubkey_hash_id)
        wallet_id = self.Config.MsgType.WALLET.decode() + pubkey_hash
        print("Wallet ID: ", wallet_id)
        wallet_data = {'inputs': [], 'outputs': [], 'outputs_pending': []} if local else \
                      {'inputs': [], 'outputs': []}
        wallet = self.Db.getDbKey(wallet_id)
        if wallet is None:
            wallet_value = {'version': self.Config.MsgType.VERSION, \
                            'assets': {self.Config.MAIN_COIN: wallet_data}}
            self.Db.insertDbKv(wallet_id, packb(wallet_value), self.Config.NODE_DB_FOLDER)
        wallet = self.Db.getDbKey(wallet_id)
        if wallet is None:
            return False
        return wallet


    def getWalletUnspentAssets(self, wallet_id, asset_type=None):
        try:
            wallet_data = self.getDbWallet(wallet_id)
            if asset_type is None:
                unspent_assets = {}
                for a in wallet_data[b"assets"]:
                    utxis_total = sum([Decimal(inps[1].decode()) for inps in wallet_data[b"assets"][a][b"inputs"]])
                    utxos_total = sum([Decimal(outps[1].decode()) for outps in wallet_data[b"assets"][a][b"outputs"]])
                    # TODO total_otput+fees ?
                    print("wallet_id: %s - inputs: %s, outputs: %s" % (wallet_id, utxis_total, utxos_total))
                    if utxos_total > utxis_total or utxos_total == utxis_total or utxis_total == 0:
                        return None
                    else:
                        utxis_amounts = [(inps[0], inps[1]) for inps in wallet_data[b"assets"][a][b"inputs"]]
                        unspent_assets[a] = (utxis_total - utxos_total), utxis_amounts
                    print("unspent_assets: ", unspent_assets)
                    return unspent_assets
            else:
                utxis_total = sum([Decimal(inps[1].decode()) for inps in wallet_data[b"assets"][asset_type][b"inputs"]])
                utxos_total = sum([Decimal(outps[1].decode()) for outps in wallet_data[b"assets"][asset_type][b"outputs"]])
                if utxos_total > utxis_total or utxos_total == utxis_total or utxis_total == 0:
                    return None
                else:
                    utxis_amounts = [(inps[0], inps[1]) for inps in wallet_data[b"assets"][a][b"inputs"]]
                    return (utxis_total - utxos_total - utxos_pending_total), utxis_amounts
        except Exception as ex:
            print('Exception getWalletUnspentAssets: %s %s' % (ex.__traceback__.tb_lineno, ex))
            #raise Exception(ex)
            return None


    # def updateDbWallet(self, wallet_id, kv_list_updates):
    #     try:
    #         db_wallet = selfgetDbWallet(wallet_id)
    #         if db_wallet is None:
    #             raise Exception("Wallet %s NOT Exist in DB" % wallet_id)
    #         for msg in kv_list_updates:
    #                 msg_key = msg.keys()[0]
    #                 msg_value = msg.values()[0]
    #                 msg_hash = msg_key[1:]
    #     except:
    #         return False


    # def updateDbWallets(self, blk_msg): #block_msg = unpackb(block_msg_bin)
    #     insert_q = Queue.queue(-1)
    #     block_num = blk_msg[self.Block.BLOCK_MSG_FIELD_INDEX.get("block_hash")]
    #     inputs_idx = self.Block.BLOCK_MSG_FIELD_INDEX.get("input_msgs")
    #     ptxs = [m for m in blk_msg[inputs_idx] if not nodedb.isDBvalue(m)]
    #     if len(ptxs) > 0 or len(ptxs) != len(blk_msg[inputs_idx]):
    #         return False # reject block
    #     return True


    # def updateWallet(self, wallet_id, msg_hash, decoded_msg): #wallet_id = hash(pub_key)
    #     if not self.DB.isDBvalue(wallet_id):
    #         isWalletExist = self.createWallet(wallet_id)
    #         if not isWalletExist:
    #             return False
    #         else:
    #             self.insertDataToWallet(wallet_id, msg_hash, decoded_msg)
    #     pass

    def insertTxsToDbWallets(self, ptx_msg, ptx_hash, block_id): #pub_addr, input_txs, asset_id, amount, inputs=[], outputs=[]):
        try:
            unspent_itxs = ptx_msg[transaction.Transaction().TX_MSG_FIELD_INDEX["input_txs"]]
            assets = ptx_msg[transaction.Transaction().TX_MSG_FIELD_INDEX["asset_type"]]
            amounts = ptx_msg[transaction.Transaction().TX_MSG_FIELD_INDEX["amounts"]]
            recipients = ptx_msg[transaction.Transaction().TX_MSG_FIELD_INDEX["to_addrs"]]
            sender_addr = crypto.Crypto.to_HMAC(ptx_msg[-1])
            if len(assets) != len(amounts) or len(amounts) != len(unspent_itxs) or len(unspent_itxs) != len(recipients):
                return False # missing data
            not_existing_assets = [a for a in assets if db.Db.getDbKey(a) is None]
            if len(not_existing_assets) > 0:
                return False #assets not yet created in the blockchain
            sender_wallet_id = self.getWalletId(sender_addr) #config.Config.MsgType.WALLET.decode() + sender_addr
            sender_wallet = self.getDbWallet(sender_wallet_id) #if multisig #TODO if fee on create is required
            print("insertTxsToDbWallets from sender", sender_wallet_id)
            assert sender_wallet #todo remove test
            if not sender_wallet:
                return False

            for i in range(len(recipients)):
                reciever_wallet_id = recipients[i] #config.Config.MsgType.WALLET.decode() + recipients[i]
                reciever_wallet = self.getDbWallet(reciever_wallet_id)
                if not reciever_wallet:
                    reciever_wallet = self.getDbWalletTemplate()
                if not assets[i] in reciever_wallet[b"assets"]:
                    reciever_wallet[b"assets"][assets[i]] = {b'inputs': [], b'outputs': []}
                if not assets[i] in sender_wallet[b"assets"]:
                    ##sender_wallet["assets"][assets[i].encode()] = {b'inputs': [], b'outputs': []}
                    return False
                #todo to remove redundant bytes inputs/outputs 1/0, assets a, version v, contracts c
                reciever_utxi = self.Config.MsgType.UNSPENT_TX.decode() + crypto.Crypto.to_HMAC((ptx_msg[0], ptx_msg[1], ptx_msg[2][0], ptx_msg[3][i], ptx_msg[4][i], ptx_msg[5][0], ptx_msg[6], ptx_msg[8], ptx_msg[9]))
                print("Wallet %s reciever_utxi/amount/ptx_hash: %s/%s/%s" % (recipients[i], reciever_utxi, amounts[i], ptx_hash))
                reciever_wallet[b"assets"][assets[i]][b'inputs'].append([reciever_utxi, amounts[i], ptx_hash])## todo link-ptx-block?

                #TODO limit ctx <=255 in Ptx? 1000 or 100
##              assert ptx_msg[7][0][1:] == reciever_utxi[1:] #ctx_hash

                # print('INSERT -PTX TRANSACTION %s to BLOCK %s'  % (self.Config.MsgType.SPENT_TX.decode() + ptx_hash[1:], block_id))
                # self.Db.addToBatch([self.Config.MsgType.SPENT_TX.decode() + ptx_hash[1:], block_id]) #Flaf ITX as Spent
                print("INSERT +CTX TRANSACTION %s from *PTX %s"  % (reciever_utxi, ptx_hash))
                self.Db.addToBatch([reciever_utxi, ptx_hash]) #new unspent tx
                print("Wallet %s INSERT +CTX %s from *PTX %s to Wallet %s" % (recipients[i], reciever_utxi, ptx_hash, reciever_wallet_id)) #recipients[i]
                self.Db.addToBatch([reciever_wallet_id, reciever_wallet])
                print("Payment of %s %s coins from %s to wallet %s" % (assets[i], amounts[i], sender_wallet_id, reciever_wallet_id))
                print("Reciever Wallet:\n", reciever_wallet)
                sender_wallet = self.getDbWallet(sender_wallet_id)
                assert sender_wallet
                sender_wallet[b"assets"][assets[i]][b'outputs'].append(
                    [self.Config.MsgType.SPENT_TX + ptx_hash[1:], block_id])
                self.Db.addToBatch([sender_wallet_id, sender_wallet]) #, override=True)
                print("Payment from %s to wallet %s of  %s %s coins" % (sender_wallet_id, reciever_wallet_id, assets[i], amounts[i]))
                print("Sender Wallet %s:\n" % sender_wallet_id, sender_wallet)

            #TODO to continue, to think of timestamp in block_msg + validation prev amounts, txs? +-5m
            #TODO - supress wallet's redundant bytes: version?->v assets:a inputs:i outputs:o contracts:c msg:m ...etc

            # assets = [{x: wallet[self.ASSSETS][x]} for x in wallet[self.ASSSETS].keys()]
            # tx_amount = [a for a in tx['amounts']]
            # if tx['asset_type'] not in tx[self.ASSSETS].keys():
            #     pass #TODO to continue
            #     #'{0:.8g}'.format(sum(Decimal(x) for x in d.values()))  '3.9125000'
            #     # '{0:.8g}'.format(sum(d.values())) # '3.9125'
            #
            # wallet[self.INPUTS] += tx[self.INPUTS]
            # wallet[self.OUTPUTS] += tx[self.OUTPUTS]
            return True #TODO state for blockchain integrity
        except Exception as ex:
            print("Exception wallets.py insertTxsToWallets %s %s" % (ex.__traceback__.tb_lineno, ex))
            #tools.printStackTrace(ex)
            return False


    def getDbWallet(self, wallet_id): #TODO at least same result from 3 random miners /byVerify for expected StateHash + report minerForPenalty
        wallet = self.Db.getDbRec(wallet_id)
        if wallet is None:
            return False
        else:
            return unpackb(wallet)


    def getDbWalletTemplate(self, local=False):
        wallet_data = {b'inputs': [], b'outputs': [], b'outputs_pending': []} if local else \
                      {b'inputs': [], b'outputs': []}
        return {b'version': self.Config.VERSION, b'assets': {self.Config.MAIN_COIN: wallet_data}}


    def getDbWalletDefault(self, wallet_id, local=False):
        wallet = self.Db.getDbRec(wallet_id)
        if wallet is None:
            return self.getDbWalletTemplate(local)
        else:
            return unpackb(wallet)


    def isWalletVerified(self, pub_addr):
        return True #todo miner * 3 verification + prevData exist
        #pass


    def reportInconsistentWallet(self, pub_addr):
        return True
        #pass


    def encodeLocalWallet(self, wallet_bin_data, pwd):
       return wallet_bin_data
       #pass #TODO


    def decodeLocalWallet(self, wallet_bin_data, pwd="TODO"):
       return wallet_bin_data #TODO
       #pass


    def getLocalWallet(self, wallet_id):
        try:
            wallet_path = os.path.join(self.wallets_path + "/", wallet_id + '.wallet')
            with open(wallet_path, "rb") as wallet:
                return self.decodeLocalWallet(wallet.read())
        except Exception as ex:
            print("Exception getLocalWallet %s %s" % (ex, ex.__traceback__.tb_lineno))
            return None


    def saveLocalWallet(self, pub_addr, bin_data): #todo pwd protection and encoding
        print("saveLocalWallet pub_addr", pub_addr)
        wallet_path = os.path.join(config.Config.WALLETS_FOLDER, pub_addr + '.wallet')
        if not self.isWalletVerified(pub_addr):
            self.reportInconsistentWallet(pub_addr)
            return False
        try:
            if os.path.exists(wallet_path):
                os.rename(wallet_path, wallet_path + ".prev")
            if not isinstance(bin_data, bytes):
                bin_data = packb(bin_data)
            with open(wallet_path, "wb") as wallet:
                wallet.write(self.encodeLocalWallet(bin_data, "TODO"))
                #os.remove(wallet_path + ".prev")
            return True
        except Exception as ex:
            if os.path.exists(wallet_path + ".tmp"):
                os.remove(wallet_path)
                os.rename(wallet_path + ".tmp", wallet_path)
            print("Exception saveLocalWallet ", ex.__traceback__.tb_lineno, ex)
            return False


    def getLocalWalletUnspentAssets(self, wallet_id, asset_type=None):
        try:
            wallet_path = os.path.join(config.Config.WALLETS_FOLDER, wallet_id + '.wallet')
            #todo remove 4 test only
            if not os.path.exists(wallet_path):
                created = self.createWallet(wallet_id[1:], local=True)
                assert created
                wallet_data = db.Db.getDbKey(wallet_id)
                self.saveLocalWallet(wallet_id, wallet_data)
            #
            with open(wallet_path, "rb") as read_wallet:
                wallet_content = read_wallet.read()
                wallet_data = unpackb(self.decodeLocalWallet(wallet_content, "TODO")) #TODO encrypted filed or sqlite db
                if asset_type is None:
                    # todo field indexing + stateNotPending?
                    unspent_assets = {}
                    for a in wallet_data["assets"]:
                        utxis_total = sum([Decimal(inps[1].decode()) for inps in wallet_data["assets"][a]["inputs"]])
                        #remove pending onSync DB and local wallets
                        utxos_pending_total = sum([Decimal(outps[1].decode()) for outps in wallet_data["assets"][a]["outputs_pending"]])
                        utxos_total = sum([Decimal(outps[1].decode()) for outps in wallet_data["assets"][a]["outputs"]])
                        #TODO total_otput+fees
                        print("wallet_id: %s - inputs: %s, outputs: %s, pending: %s" % (wallet_id, utxis_total, utxos_total, utxos_pending_total))
                        if utxos_total + utxos_pending_total  > utxis_total: #or utxos_total == 0 or utxis_total == 0:
                            return None
                        else:
                            #utxis = set()
                            #[utxis.add(inps[0]) for inps in wallet_data[b"assets"][a][b"inputs"]]
                            utxis_amounts = [(inps[0], inps[1]) for inps in wallet_data["assets"][a]["inputs"]]
                            unspent_assets[a] = (utxis_total - utxos_total - utxos_pending_total), utxis_amounts
                    print("unspent_assets: ", unspent_assets)
                    return unspent_assets
                else:
                    utxis_total = sum([Decimal(inps[1].decode()) for inps in wallet_data["assets"][asset_type]["inputs"]])
                    utxos_total = sum([Decimal(outps[1].decode()) for outps in wallet_data["assets"][asset_type]["outputs"]])
                    utxos_pending_total = sum([Decimal(outps[1].decode()) for outps in wallet_data["assets"][a][b"outputs_pending"]])
                    if utxos_total + utxos_pending_total > utxis_total:
                        return None
                    else:
                        utxis_amounts = [(inps[0], inps[1]) for inps in wallet_data[b"assets"][a][b"inputs"]]
                        return (utxis_total - utxos_total - utxos_pending_total), utxis_amounts

        except Exception as ex:
            print('Exception getLocalWalletUnspentAssets: %s %s' % (ex.__traceback__.tb_lineno, ex))
            #tools.printStackTrace(ex)
            return None


    def getDbWalletUnspentAmounts(self, msg_sender_wallet, asset=None):
        #todo remove "pendin" from dbWallet
        try:
            db_wallet = self.getDbWallet(msg_sender_wallet)
            db_wallet_assets = db_wallet["assets"].keys() if asset is None else db_wallet[asset]
            db_wallet_free = {}
            for a in db_wallet_assets:
                utxis_total = sum([Decimal(inps[1].decode()) for inps in db_wallet["assets"][a]["inputs"]])
                utxos_total = sum([Decimal(outps[1].decode()) for outps in db_wallet["assets"][a]["outputs"]])
                asset_free_amount = utxis_total - utxos_total
                db_wallet_free[a] = asset_free_amount

                return db_wallet_free, db_wallet
        except Exception as ex:
            print("Exception getDbWalletUnspentAmounts: " , ex, ex.__traceback__.tb_lineno)
            return None, None


    def signAndSendPtx(self, ptx=None, signer=None):
        if ptx is None or signer is None:
            return None
        smsg = self.Crypto.signMsg(ptx, signer)
        #host, port = self.Net.getValidNodesList()[0] #todo
        ##assert smsg[-32:] == ptx[-1]
        #msg_headers = packb((ptx[0], ptx[-1]))
        msg_headers_and_data = packb((config.Config.MsgType.PARENT_TX_MSG, smsg)) #ptx[1]
        print("req msg_headers", unpackb(msg_headers_and_data)[0])
        print("req_wallet_id", self.getWalletId(unpackb(msg_headers_and_data)[1][-32:]))
        #sys.exit(0)
        res = self.Net.sendMsgZmqReq(msg_headers_and_data, 'localhost', self.Config.PORT_REP)
        print(res)
        assert res
        return res
        # ptx_id = "+" + smsg[3]
        # sender_wallet_id = "W" + self.Crypto.to_HMAC(vk)
        # isLocalWalletUpdated = self.appendPendingPtxToLocalWallet(sender_wallet_id, ptx_id, ptx) if res else None
        # ret = smsg[3] if isLocalWalletUpdated else None
        # # if ret is None:
        # #     self.TASKS.deleteSdbVerifiedMsqQ.add(smsg[3])
        # return ret

#########local #todo js
        # @func_wrapper
        # def createPtx(self, pub_key, asset_types=[], amounts=[], to_addrs=[],
        #               service_fee=b"0.001"):  # todo set fee from config+validate min 4 miners
        #     pub_addr = self.Crypto.to_HMAC(pub_key)
        #     wallet_id = "W" + pub_addr
        #     ua = self.getLocalWalletUnspentAssets(wallet_id)
        #     if ua is None:
        #         return None
        #     else:
        #         if len(asset_types) != len(amounts) or len(amounts) != len(to_addrs) or len(
        #                 amounts) > Structure().PTX_TX_LIMIT:
        #             return None
        #         utc_ts = self.Utils.utc_timestamp_b()
        #         assetsU = set()
        #         [assetsU.add(a) for a in asset_types if a not in assetsU]
        #         total_wallet_asset_amount = {}
        #         change_wallet_asset_amount = {}
        #         change_wallet_asset_itx = {}
        #         asset_itxs = []
        # 
        #         for a in assetsU:  # check that assets exist in the local wallet and tx's funds doesn't exceeds
        #             if not a in ua.keys():
        #                 return None
        #             wallet_asset_amount = sum([Decimal(amount[-1].decode()) for amount in ua[a][1]])
        #             tx_asset_amount = sum(
        #                 [Decimal(amounts[i].decode()) for i in range(len(amounts)) if asset_types[i] == a])
        #             total_service_fee = Decimal(service_fee.decode()) * len([c for c in asset_types if c == a])
        #             if (tx_asset_amount + total_service_fee) > wallet_asset_amount:
        #                 print("TX outputs > inputs")
        #                 return None
        #             total_wallet_asset_amount[a] = wallet_asset_amount
        #             change_wallet_asset_amount[a] = wallet_asset_amount - (tx_asset_amount + total_service_fee)
        # 
        #         for i in range(len(asset_types)):  # Distribute wallet inputs+service fees per asset
        #             # Create a list of ascending by amount transactions, get rid of numerous itxs
        #             sorted_itxs = sorted(ua[asset_types[i]][1], key=lambda x: x[1])
        #             included_itxs = []
        #             included_itxs_amount = 0
        #             for j in range(len(sorted_itxs)):
        #                 ctx_amount = Decimal(amounts[j].decode()) + Decimal(service_fee.decode())
        #                 itx_amount = Decimal(sorted_itxs[j][1].decode())
        #                 itx = sorted_itxs[j][0]
        #                 included_itxs.append(itx)
        #                 included_itxs_amount += itx_amount
        #                 if included_itxs_amount >= ctx_amount:
        #                     asset_itxs.append(included_itxs)
        #                     # change_wallet_asset_amount[asset_types[i]] -= ctx_amount
        #                     change_wallet_asset_itx[asset_types[i]] = itx
        #                     if change_wallet_asset_amount[asset_types[i]] < 0:
        #                         return None
        #                     k = len(sorted_itxs)
        #                     n = k if included_itxs_amount == ctx_amount else j
        #                     sorted_itxs = sorted_itxs[n:]  # advance to next sorted tx
        #                     j = k
        # 
        #         ctxs = []
        #         ctxs_outputs = []
        #         ptx = None
        #         if len(asset_itxs) != len(to_addrs):
        #             return None
        #         for n in range(len(amounts)):
        #             ctx = packb((self.Config.MsgType.VERSION, self.Config.MsgType.PARENT_TX_MSG.decode(),
        #                          asset_itxs[n], to_addrs[n], asset_types[n], amounts[n], service_fee, utc_ts))
        #             ctxs_outputs.append(self.Config.MsgType.UNSPENT_TX.decode() + self.Crypto.to_HMAC((ctx, pub_key)))
        #             ctxs.append(ctx)  # (ctx[0][:-1]) #exclude pub_key, it will be taken from the parentTx -> ptx
        #         for n in range(len(assetsU)):  # keep change #TODO assert in block
        #             asset = list(assetsU)[n]
        #             if asset in change_wallet_asset_amount:  # skip exceptions
        #                 change_amount = change_wallet_asset_amount[asset]
        #                 change_fee = Decimal(service_fee.decode())
        #                 if change_amount - change_fee > 0:
        #                     ctx = packb((self.Config.MsgType.VERSION, self.Config.MsgType.PARENT_TX_MSG,
        #                                  [change_wallet_asset_itx[asset]],
        #                                  ("W" + pub_addr).encode(), asset, self.Utils.dec2b(change_amount - change_fee),
        #                                  service_fee, utc_ts))
        #                     ctxs_outputs.append(
        #                         self.Config.MsgType.UNSPENT_TX + self.Crypto.to_HMAC((ctx, pub_key)).encode())
        #                     ctxs.append(ctx)  # (ctx[:-1]) #exclude pub_key, it will be taken from the parentTx -> ptx
        #                     change_amount -= change_fee
        #                     amounts.append(self.Utils.dec2b(change_amount - change_fee))
        #                     asset_types.append(asset)
        #                     to_addrs.append("W" + pub_addr)
        #                     change_wallet_asset_amount[asset] -= change_fee
        # 
        #         ptx = (self.Config.MsgType.VERSION,
        #                self.Config.MsgType.PARENT_TX_MSG, ctxs,
        #                to_addrs, asset_types, amounts,
        #                self.Utils.dec2b(Decimal(service_fee.decode()) * len(ctxs)),
        #                ctxs_outputs, utc_ts, pub_key)
        #         return ptx
        #     return None
     
        

    #@func_wrapper
    # def createPtxUser(self, pub_key, asset_types=[], amounts=[], to_addrs=[], service_fee=b"0.001"): #todo set fee from config+validate min 4 miners
    #     pub_addr = self.Crypto.to_HMAC(pub_key)
    #     wallet_id = "W" + pub_addr
    #     ua  = self.getLocalWalletUnspentAssets(wallet_id)
    #     if ua is None:
    #         return None
    #     else:
    #         if len(asset_types) != len(amounts) or len(amounts) != len(to_addrs) or len(amounts) > Structure().PTX_TX_LIMIT:
    #             return None
    #         utc_ts = self.Utils.utc_timestamp_b()
    #         assetsU = set()
    #         [assetsU.add(a) for a in asset_types if a not in assetsU]
    #         total_wallet_asset_amount = {}
    #         change_wallet_asset_amount = {}
    #         change_wallet_asset_itx = {}
    #         asset_itxs = []
    # 
    #         for a in assetsU: #check that assets exist in the local wallet and tx's funds doesn't exceeds
    #             if not a in ua.keys():
    #                 return None
    #             wallet_asset_amount = sum([Decimal(amount[-1].decode()) for amount in ua[a][1]])
    #             tx_asset_amount = sum([Decimal(amounts[i].decode()) for i in range(len(amounts)) if asset_types[i] == a])
    #             total_service_fee = Decimal(service_fee.decode()) * len([c for c in asset_types if c==a])
    #             if (tx_asset_amount + total_service_fee) > wallet_asset_amount:
    #                 print("TX outputs > inputs")
    #                 return None
    #             total_wallet_asset_amount[a] = wallet_asset_amount
    #             change_wallet_asset_amount[a] = wallet_asset_amount - (tx_asset_amount + total_service_fee)
    # 
    # 
    #         for i in range(len(asset_types)): #Distribute wallet inputs+service fees per asset
    #             # Create a list of ascending by amount transactions, get rid of numerous itxs
    #             sorted_itxs = sorted(ua[asset_types[i]][1], key=lambda x: x[1])
    #             included_itxs = []
    #             included_itxs_amount = 0
    #             for j in range(len(sorted_itxs)):
    #                 ctx_amount = Decimal(amounts[j].decode()) + Decimal(service_fee.decode())
    #                 itx_amount = Decimal(sorted_itxs[j][1].decode())
    #                 itx = sorted_itxs[j][0]
    #                 included_itxs.append(itx)
    #                 included_itxs_amount += itx_amount
    #                 if included_itxs_amount >= ctx_amount:
    #                     asset_itxs.append(included_itxs)
    #                     #change_wallet_asset_amount[asset_types[i]] -= ctx_amount
    #                     change_wallet_asset_itx[asset_types[i]] = itx
    #                     if change_wallet_asset_amount[asset_types[i]] < 0:
    #                         return None
    #                     k = len(sorted_itxs)
    #                     n = k if included_itxs_amount == ctx_amount else j
    #                     sorted_itxs = sorted_itxs[n:] # advance to next sorted tx
    #                     j = k
    # 
    #         ctxs = []
    #         ctxs_outputs = []
    #         ptx = None
    #         if len(asset_itxs) != len(to_addrs):
    #             return None
    #         for n in range(len(amounts)):
    #             ctx = packb((self.Config.MsgType.Type.VERSION, self.Config.MsgType.Type.PARENT_TX_MSG.decode(), asset_itxs[n], to_addrs[n], asset_types[n], amounts[n], service_fee, utc_ts))
    #             ctxs_outputs.append(self.Config.MsgType.UNSPENT_TX.decode() + self.Crypto.to_HMAC((ctx, pub_key)))
    #             ctxs.append(ctx) #(ctx[0][:-1]) #exclude pub_key, it will be taken from the parentTx -> ptx
    #         for n in range(len(assetsU)): # keep change #TODO assert in block
    #             asset = list(assetsU)[n]
    #             if asset in change_wallet_asset_amount: #skip exceptions
    #                 change_amount = change_wallet_asset_amount[asset]
    #                 change_fee = Decimal(service_fee.decode())
    #                 if change_amount - change_fee > 0:
    #                     ctx = packb((self.Config.MsgType.Type.VERSION, self.Config.MsgType.PARENT_TX_MSG, [change_wallet_asset_itx[asset]],
    #                                  ("W" + pub_addr).encode(), asset, self.Utils.dec2b(change_amount - change_fee), service_fee, utc_ts))
    #                     ctxs_outputs.append(self.Config.MsgType.UNSPENT_TX + self.Crypto.to_HMAC((ctx, pub_key)).encode())
    #                     ctxs.append(ctx) #(ctx[:-1]) #exclude pub_key, it will be taken from the parentTx -> ptx
    #                     change_amount -= change_fee
    #                     amounts.append(self.Utils.dec2b(change_amount - change_fee))
    #                     asset_types.append(asset)
    #                     to_addrs.append("W" + pub_addr)
    #                     change_wallet_asset_amount[asset] -= change_fee
    # 
    #         ptx = (self.Config.MsgType.VERSION,
    #                self.Config.MsgType.PARENT_TX_MSG, ctxs,
    #                to_addrs, asset_types, amounts,
    #                self.Utils.dec2b(Decimal(service_fee.decode()) * len(ctxs)),
    #                ctxs_outputs, utc_ts, pub_key)
    #         return ptx
    #     return None


    


    # def signMsg(self, msg, priv_key, pub_key):
    #     try:
    #         signed_msg = self.Crypto.signMsg(packb(msg), priv_key)
    #         signed_msg_and_pubkey = (signed_msg, pub_key)
    #         msg_and_pubkey_bytes = packb(signed_msg_and_pubkey)
    #         #msg_and_pubkey_hash = self.Crypto.to_HMAC(msg_and_pubkey_bytes)
    #         #return msg_and_pubkey_bytes #, msg_and_pubkey_hash
    #         msgtype_msg_pubkey_bytes = (msg[1], signed_msg_and_pubkey)
    #         print("DB msg key: %s, SDB wrapped msg key %s" % (crypto.Crypto.to_HMAC(msg_and_pubkey_bytes), self.Crypto.to_HMAC(msgtype_msg_pubkey_bytes)))
    #         ##return packb(msgtype_msg_pubkey_bytes)
    #         sdb_msg = packb(msgtype_msg_pubkey_bytes)
    #         sdb_hash = crypto.Crypto.to_HMAC(sdb_msg)
    #         db_msg = msg_and_pubkey_bytes
    #         db_hash = crypto.Crypto.to_HMAC(db_msg)
    #         return sdb_msg, sdb_hash, db_msg, db_hash
    # 
    #     except Exception as ex:
    #         print("Exception signMsg: %s %s" % (ex.__traceback__.tb_lineno, ex))
    #         return None


    # def sendMsg(self, msg, hosts=[], port=7777): #TODO get available hosts
    #      for h in host:
    #          if self.Net.sendMsgZmqReq(packb(bin_signed_msg), h, port):
    #              return True
    #      return False



    def areTxRecordsExistInTheWallet(self, tx_list, wallet, in_inputs=True, in_outputs=False):#todo msgs,icos...
        inps = b"inputs"
        outs = b"outputs"
        inputs_found = 0
        outputs_found = 0
        wallet_assets = list(set(wallet[b"assets"].keys()))
        for asset in wallet_assets:
            for inp in tx_list:
                if in_inputs:
                    if inp in [i for i in wallet[b'assets'][asset][inps] for i in i]:
                        print("Input %s found" % (inp))
                        inputs_found += 1
                if in_outputs:
                    if inp in [i for i in wallet[b'assets'][asset][outs] for i in i]:
                        print("Output %s found" % (inp))
                        outputs_found += 1
        if not in_inputs and not in_outputs:
            return False
        if in_inputs and in_outputs and len(tx_list)*2 != (inputs_found+outputs_found):
            return False
        if in_inputs and not in_outputs and len(tx_list) != inputs_found:
            return False
        if in_outputs and not in_inputs and len(tx_list) != outputs_found:
            return False
        return True



    def markSpentTxRecordsInTheWallet(self, itx_list, wallet, spent_block_id):
        try:
            itx_list = list(set(itx_list))
            inps = b"inputs"
            outs = b"outputs"
            assets = b"assets"
            inputs_found = 0
            outputs_found = 0
            wallet_assets = list(set(wallet[assets].keys()))
            itx_list = list(set(itx_list))
            inp_asset = {}
            inp_ptx = {}
            block_chain_updates = {}
            print('wallet', wallet)
            for asset in wallet_assets:
                for inp in itx_list:
                    print('inp', inp.encode())
                    if inp.encode() in [i for i in wallet[assets][asset][inps] for i in i]:
                        inputs_found += 1
                        inp_asset[inp] = asset
                        inp_ptx[inp] = [l[2] for l in wallet[assets][asset][inps] if inp.encode() in l[0]][0]
                    if inp[1:] in [i for i in wallet[assets][asset][outs] for i in i]:
                        return False, wallet, None
            if len(itx_list) != inputs_found:
                return False, wallet, None
            for itx in itx_list:
                asset_inp = inp_asset[itx]
                wallet[assets][asset_inp][outs].append(["-" + itx[1:], spent_block_id])
                block_chain_updates["-" + itx[1:]] = spent_block_id
            return True, wallet, block_chain_updates
        except Exception as ex:
            print("Exception wallets markSpentTxRecordsInTheWallet:", ex.__traceback__.tb_lineno, ex)
            return False, wallet, None


    def addUtxoToTheWallet(self, asset, ctx_hash, amount, ptx_hash, wallet):
        try: #todo check duplicate keys
            inps = b"inputs"
            outs = b"outputs"
            assets = b"assets"
            inputs_found = 0
            outputs_found = 0
            wallet_assets = list(set(wallet[assets].keys()))
            inp_asset = {}
            inp_ptx = {}
            block_chain_updates = {}
            print('wallet', wallet)
            for a in wallet_assets:
                itx_list = [v for v in wallet[assets][a][inps] for v in v]
                otx_list = [v for v in wallet[assets][a][outs] for v in v]
                itxs = [t for t in itx_list if t == "+" + ctx_hash]
                otxs = [t for t in itx_list if t == "-" + ctx_hash]
                if self.Db.isDBkey("-" + ctx_hash) or self.Db.isDBkey("+" + ctx_hash) or \
                        self.Db.isDBkey("*" + ptx_hash) or self.Db.isDBkey("+" + ptx_hash):
                    raise Exception("Exception wallets Duplicate, Ptx or Ctx are exist in DB")
                if len(itxs) > 0 or len(otxs) > 0:
                    raise Exception("Exception wallets Duplicate, Ctx %s already exist in the wallet" % (ctx[1:]))
                # if ptx[1:] in itxs: #todo
                #     raise Exception("Exception wallets Duplicate Ptx %s already exist in the wallet" % (ptx[1:]))

                if not self.Db.isDBkey(asset):
                    raise Exception("Exception wallets Asset %s DOESN'T exist" % asset)
                if not Decimal(amount) > 0:
                    raise Exception("Exception wallets Invalid Amount %s format" % amount)
                wallet[assets][asset][inps].append(["+" + ctx_hash, amount.encode(), "*" + ptx_hash])


            return wallet
        except Exception as ex:
            print("Exception wallets addUtxoToTheWallet:", ex.__traceback__.tb_lineno, ex)
            print("Exception wallet", wallet)
            return None


    def updateDbWallet(self, pub_addr):
        pass


#@func_wrapper
    def createPtx(self, pub_key, asset_types=[], amounts=[], to_addrs=[], service_fee=b"0.001"): #todo set fee from config+validate min 4 miners
        try:
            pub_addr = crypto.Crypto.to_HMAC(pub_key)
            wallet_id = self.getWalletId(pub_key) #"W" + pub_key
            ua  = self.getWalletUnspentAssets(wallet_id)
            if ua is None:
                print(wallet_id, "ua is None")
                return None
            else:
                if len(asset_types) != len(amounts) or len(amounts) != len(to_addrs) or len(amounts) > self.Config.PTX_TX_LIMIT:
                    return None
                utc_ts = self.Utils.utc_timestamp_b()
                assetsU = set()
                [assetsU.add(a) for a in asset_types if a not in assetsU]
                total_wallet_asset_amount = {}
                change_wallet_asset_amount = {}
                change_wallet_asset_itx = {}
                asset_itxs = []

                for a in assetsU: #check that assets exist in the local wallet and tx's funds doesn't exceeds
                    if not a in ua.keys():
                        return None
                    wallet_asset_amount = sum([Decimal(amount[-1].decode()) for amount in ua[a][1]])
                    tx_asset_amount = sum([Decimal(amounts[i].decode()) for i in range(len(amounts)) if asset_types[i] == a])
                    total_service_fee = Decimal(service_fee.decode()) * len([c for c in asset_types if c==a])
                    if (tx_asset_amount + total_service_fee) > wallet_asset_amount:
                        print("TX outputs > inputs")
                        return None
                    total_wallet_asset_amount[a] = wallet_asset_amount
                    change_wallet_asset_amount[a] = wallet_asset_amount - (tx_asset_amount + total_service_fee)


                for i in range(len(asset_types)): #Distribute wallet inputs+service fees per asset
                    # Create a list of ascending by amount transactions, reorginize itxs
                    sorted_itxs = sorted(ua[asset_types[i]][1], key=lambda x: x[1])
                    included_itxs = []
                    included_itxs_amount = 0
                    for j in range(len(sorted_itxs)):
                        ctx_amount = Decimal(amounts[j].decode()) + Decimal(service_fee.decode())
                        itx_amount = Decimal(sorted_itxs[j][1].decode())
                        itx = sorted_itxs[j][0]
                        included_itxs.append(itx)
                        included_itxs_amount += itx_amount
                        if included_itxs_amount >= ctx_amount:
                            asset_itxs.append(included_itxs)
                            #change_wallet_asset_amount[asset_types[i]] -= ctx_amount
                            change_wallet_asset_itx[asset_types[i]] = itx
                            if change_wallet_asset_amount[asset_types[i]] < 0:
                                return None
                            k = len(sorted_itxs)
                            n = k if included_itxs_amount == ctx_amount else j
                            sorted_itxs = sorted_itxs[n:] # advance to next sorted tx
                            j = k

                ctxs = []
                ctxs_outputs = []
                ptx = None
                if len(asset_itxs) != len(to_addrs):
                    return None
                for n in range(len(amounts)):
                    ctx = packb((self.Config.MsgType.VERSION, self.Config.MsgType.PARENT_TX_MSG.decode(), asset_itxs[n], to_addrs[n], asset_types[n], amounts[n], service_fee, utc_ts))
                    ctxs_outputs.append(self.Config.MsgType.UNSPENT_TX.decode() + self.Crypto.to_HMAC((ctx, pub_key)))
                    ctxs.append(ctx) #(ctx[0][:-1]) #exclude pub_key, it will be taken from the parentTx -> ptx
                for n in range(len(assetsU)): # keep change #TODO assert in block
                    asset = list(assetsU)[n]
                    if asset in change_wallet_asset_amount: #skip exceptions
                        change_amount = change_wallet_asset_amount[asset]
                        change_fee = Decimal(service_fee.decode())
                        if change_amount - change_fee > 0:
                            ctx = packb((self.Config.MsgType.VERSION, self.Config.MsgType.PARENT_TX_MSG, [change_wallet_asset_itx[asset]],
                                         ("W" + pub_addr).encode(), asset, self.Utils.dec2b(change_amount - change_fee), service_fee, utc_ts))
                            ctxs_outputs.append(self.Config.MsgType.UNSPENT_TX + self.Crypto.to_HMAC((ctx, pub_key)).encode())
                            ctxs.append(ctx) #(ctx[:-1]) #exclude pub_key, it will be taken from the parentTx -> ptx
                            change_amount -= change_fee
                            amounts.append(self.Utils.dec2b(change_amount - change_fee))
                            asset_types.append(asset)
                            to_addrs.append("W" + pub_addr)
                            change_wallet_asset_amount[asset] -= change_fee

                ptx = (self.Config.MsgType.VERSION,
                       self.Config.MsgType.PARENT_TX_MSG, ctxs,
                       to_addrs, asset_types, amounts,
                       self.Utils.dec2b(Decimal(service_fee.decode()) * len(ctxs)),
                       ctxs_outputs, utc_ts, pub_key)
                return ptx
            return None
        except Exception as ex:
            print("Exeption createPtx" , ex.__traceback__.tb_lineno, ex)
            return None
