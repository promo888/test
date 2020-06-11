import os, sys, time, subprocess #, #psutil, pkgutil, shutil
import msgpack as mp
from msgpack import packb, unpackb
import json
import sqlite3
import plyvel
import datetime, time, arrow, configparser
import logging
from logging.handlers import RotatingFileHandler
from nacl.signing import SigningKey, VerifyKey, SignedMessage
from Crypto.Hash import SHA256, HMAC
from decimal import Decimal
import time, socket, zmq
from time import sleep
import threading
from queue import Queue, PriorityQueue

##sys.setrecursionlimit(100)

from v.v1 import logger, config, node, crypto, network, web, \
                 sdb, db, wallets, transaction, message, block, \
                 contract, ico, exchange, utils

class Tools():

    def factory(self, cls):
        return self.cls()

    def __init__(self):
        self.logger = logger.Logger()
        config.Config = config.Config()
        self.Utils = utils.Utils()
        self.Crypto = crypto.Crypto()
        self.Wallets = wallets.Wallet()
        self.Db = db.Db()
        self.Sdb = sdb.ServiceDb()
        self.Ico = ico.Ico()
        self.Net = network.Network()
        self.Tx = transaction.Transaction()
        self.Block = block.Block()
        self.Node = node.Node()
        #tools dep consumed by Node?, vRunners


    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Tools, cls).__new__(cls)
        return cls.instance

    def insertGenesis(self): #todo if not GenesisBlockExist ts 02.02.2020
        crt = crypto.Crypto()
        wlt = wallets.Wallet()
        g_sender_keys = crt.getKeysFromSeed('Miner0')
        g_reciever_keys = crt.getKeysFromSeed('Miner1')
        g_sender_pubaddr = crt.to_HMAC(g_sender_keys.vk)
        g_reciever_pubaddr = crt.to_HMAC(g_reciever_keys.vk)
        g_sender_wallet_id = wlt.getWalletId(g_sender_pubaddr) #"W" + g_sender_pubaddr
        g_reciever_wallet_id = wlt.getWalletId(g_reciever_pubaddr)

        isWalletCreated = wlt.createWallet(g_sender_pubaddr)
        assert isWalletCreated

        g_sender_db_wallet = db.Db.getDbKey(g_sender_wallet_id)
        assert not g_sender_db_wallet is None
        print(unpackb(g_sender_db_wallet)[b'version'], config.Config.VERSION)
        assert unpackb(g_sender_db_wallet)[b'version'] == config.Config.VERSION
        isAssetCreated = self.Ico.createAsset(config.Config.MAIN_COIN,
                                              ' MainCoin - FxCash ', 128000000000,
                                              config.Config.NEW_ASSET_FEE,
                                              config.Config.BLOCK_REWARDS, [],
                                              g_sender_wallet_id,  desc='createAsset')
        assert isAssetCreated

        genesis_msg = crypto.Crypto.to_HMAC('* GENESIS FX CRYPTO CASH COIN *')
        utc_ts = utils.Utils.utc_timestamp_b()
        unspent_input_genesis_tx = config.Config.MsgType.UNSPENT_TX.decode() + genesis_msg.ljust(32)
        print("fake unspent_input_genesis_tx", unspent_input_genesis_tx)
        genesis_ctx = ('1', config.Config.MsgType.PARENT_TX_MSG.decode(), [[unspent_input_genesis_tx]][0],
                       [g_reciever_wallet_id][0], [config.Config.MAIN_COIN][0], [b'999999999.12345678'][0], b'0.001',
                       utc_ts, g_sender_keys.vk)
        genesis_ctx_hmac = crypto.Crypto.to_HMAC(genesis_ctx)
        utxo_ctx0 = config.Config.MsgType.UNSPENT_TX.decode() + genesis_ctx_hmac
        print("genesis_ctx", utxo_ctx0)
        genesis_tx = (b'1', config.Config.MsgType.PARENT_TX_MSG, [[unspent_input_genesis_tx.encode()]],
                      [g_reciever_wallet_id.encode()], [config.Config.MAIN_COIN], [b'999999999.12345678'], b'0.001',
                      [utxo_ctx0.encode()], bytes(utc_ts),
                      g_sender_keys.vk)
        g_tx_signed_msg = crypto.Crypto.signMsg(genesis_tx, g_sender_keys) #msgtype + msg
        g_verified_sig, g_verified_msg = crypto.Crypto.verifyMsgSig(g_tx_signed_msg, g_sender_keys.vk)
        assert g_verified_sig
        #print("unpackb(g_verified_msg)", unpackb(g_verified_msg))
        assert unpackb(g_verified_msg) == list(genesis_tx)
        #g_signed_msg_and_key = (g_tx_signed_msg, g_sender_keys.vk)
        #g_signed_msg_and_key_bytes = packb(g_signed_msg_and_key)#TODO salt(lastKnownBlockNum) in order to prevent duplicate TX in the same and the next blocks
        #g_tx_hash = crypto.Crypto.to_HMAC(g_signed_msg_and_key_bytes) ##g_signed_msg_and_key_bytes
        g_tx_hash = crypto.Crypto.to_HMAC(g_tx_signed_msg)
        print('Genesis TX hash = VerifyKey: ', g_tx_hash)
        #g_signed_msg_and_key_bytes = g_tx_signed_msg

        g_tx_hash_list = [config.Config.MsgType.PARENT_TX_MSG + g_tx_hash.encode()] #[config.Config.MsgType.PARENT_TX_MSG + packb(g_tx_hash)]
        #TODO votes
        g_block_votes_list = [config.Config.MsgType.VOTE_MSG + crypto.Crypto.to_HMAC('Miner Block Votes are Ignored in GENESIS block').encode()] #['msg == minerMsg 32b hash :{msgSig, msgPk is not penaltied miner has wallet, fee}] #ignored onGenesis #todo rsa sigs from ecdsa
        g_block_prev_block_hash = genesis_msg.encode() #ignored onGenesis
        #
        g_block_msg = (b'1', config.Config.MsgType.BLOCK_MSG, 0, g_block_prev_block_hash,
                       g_tx_hash_list, g_block_votes_list, self.Utils.utc_timestamp_b(), g_sender_keys.vk)
        g_signed_block_msg = crypto.Crypto.signMsg(g_block_msg, g_sender_keys)
        assert isinstance(g_signed_block_msg, bytes)
        genesis_block_msg = packb(g_signed_block_msg)
        genesis_block_hash = crypto.Crypto.to_HMAC(genesis_block_msg)
        sm = crypto.Crypto.verifyMsgSig(unpackb(genesis_block_msg), g_sender_keys.vk) #SignedMessage(unpackb(genesis_block)[0])
        assert sm[0]
        assert unpackb(sm[1]) == list(g_block_msg)
        assert unpackb(sm[1])[-1] == g_sender_keys.vk
        isValidMsg = self.Utils.isMsgValid(genesis_block_msg)
        assert not isValidMsg is None
        # block_umsg = unpackb(genesis_block)
        # isBlockSigVerified, block_msg_verified_bin = crypto.Crypto.verifyMsgSig(block_umsg[0], block_umsg[1])
        # assert isBlockSigVerified
        print("Genesis block verified")
        # todo isMinerValid(min_supply, penalties_limit)
        #tools.insertDbKey(config.Config.MsgType.BLOCK_MSG + genesis_msg, 0) #insert Genesis block (blockHash, blockNum)
        block_msg = sm[1]
        isBlockValid = block.Block.validateBlock(block_msg)
        assert isBlockValid
        ##isBlockVerified = tools.verifyBlock(block_msg, genesis_block_hash) #TODO - After Genesis
        ##assert isBlockVerified #TODO rollback onError?
        #print("INSERT BLOCK: %s" % (genesis_block_hash))
        block_id = self.Block.getBlockId(genesis_block_hash)#self.Block.insertBlock(genesis_block_hash, block_msg_verified_bin)
        g_tx_hash = unpackb(block_msg)[4][0][1:]
        print("INSERT *PTX TRANSACTION: %s to Block %s" % (config.Config.MsgType.PARENT_TX_MSG + g_tx_hash, block_id))
        self.Db.addToBatch([config.Config.MsgType.PARENT_TX_MSG + g_tx_hash, packb(g_tx_signed_msg)])
        print("INSERT +PTX TRANSACTION: %s to Block %s" % (config.Config.MsgType.UNSPENT_TX + g_tx_hash, block_id))
        self.Db.addToBatch([config.Config.MsgType.UNSPENT_TX + g_tx_hash, block_id])
        print('INSERT -PTX TRANSACTION %s to Block %s' % (config.Config.MsgType.SPENT_TX + g_tx_hash[1:], block_id))
        self.Db.addToBatch([config.Config.MsgType.SPENT_TX + g_tx_hash[1:], block_id])  # Flaf ITX as Spent

        print("INSERT TXs to DB Wallets")
        insertWallets = self.Wallets.insertTxsToDbWallets(genesis_tx, config.Config.MsgType.PARENT_TX_MSG + g_tx_hash, block_id) #wallets update TODO state
        assert insertWallets
        print("INSERT GENESIS BLOCK", block_id, g_block_msg)
        self.Db.addToBatch([block_id, genesis_block_msg])
        assert self.Db.writeBatch()
        assert self.Block.saveLastBlockState(block_id.decode())
        print('\n*** Genesis created ***\n')
        return True


    def testTx(self, sender='Miner1', reciever='Test1', asset=config.Config.MAIN_COIN, amount=Decimal(0.01)):
        gSK = self.Crypto.getKeysFromSeed(sender)
        gSK2 = self.Crypto.getKeysFromSeed(reciever)
        s_wallet_id = "W" + crypto.Crypto.to_HMAC(gSK.vk)
        #r_wallet = "W" + crypto.Crypto.to_HMAC(gSK2.vk)
        s_wallet_data = self.Wallets.getDbWallet(s_wallet_id)
        print('\n*****test DB wallet Sender*****%s\n' % s_wallet_id, s_wallet_data)
        # print('\n*****test Local wallet Sender*****%s\n' % s_wallet, wallet_data)
        # self.Wallets.saveLocalWallet(s_wallet, wallet_data)
        # wallet_data = self.Wallets.getDbWallet(r_wallet)
        # print('\n*****test DB wallet Reciever*****%s\n' % r_wallet, wallet_data)
        # wallet_data = self.Db.getDbRec(r_wallet) or self.Wallets.getDbWalletTemplate(local=True)
        # print('\n*****Genesis Local wallet Reciever*****%s\n' % r_wallet, wallet_data)
        # self.Wallets.saveLocalWallet(r_wallet, wallet_data)
        ua = self.Wallets.getWalletUnspentAssets(s_wallet_id)
        ##assert not ua is None
        print("\nWallet", s_wallet_id, " Unspent amounts", ua)

        to_addrs = ["W" + crypto.Crypto.to_HMAC("test%s" % i) for i in range(2, 5)]
        print("*****3 payments - valid TX*****")
        ptx = self.Wallets.createPtx(gSK.vk,
                [config.Config.MAIN_COIN, config.Config.MAIN_COIN, config.Config.MAIN_COIN],
                [b'1', b'1', b'1'], to_addrs)

        assert not ptx is None
        print("WALLET.createPtx 3 payments - valid PTX : ", ptx)
        smsg = crypto.Crypto.signMsg(ptx, gSK)
        ptx_hash = self.Crypto.to_HMAC(smsg)

        print("tools verifyMsg:", ptx_hash, self.Tx.verifyMsg(ptx_hash, ptx))
        isVerified, msg_bin = self.Crypto.verifyMsgSig(smsg, smsg[-32:])
        umsg = unpackb(msg_bin)
        umsg_data = umsg #[unpackb(msg) for msg in umsg[2]][0]
        print("ptx", ptx)
        print("umsg_data", umsg_data)
        print("tools verifyMsg:", ptx_hash, self.Tx.verifyMsg(ptx_hash, tuple(umsg_data)))
        #print("Diff: \n%s " % self.Utils.diff(ptx, umsg_data))
##        assert tuple(umsg_data) == ptx
##        sys.exit(0)
        isPtxOk = self.Wallets.signAndSendPtx(ptx, gSK)
        assert isPtxOk
        print("PTX %s is Accepted: %s" % (ptx_hash, isPtxOk if not isPtxOk is None else None))
        time.sleep(12)
        #print(self.Tx.verifyMsg(self.Crypto.to_HMAC(smsg), ptx))
        #sys.exit(0)
        ##self.Node.verifySdbMsgTask()
        ##time.sleep(12)
        #sys.exit(0)
        # tests
        # tools.persistPendingMsg(tools.to_HMAC(smsg), smsg, gVK2._key) #TODO to continue/fix + onCreateSdbFile chmod for insert folder: chmod -R 766 venv/service_db/DATA/
        # tools.insertDbTx(umsg) #dummy test TODO to continue/fix
        # print("*****3 payments - DUPLICATE TX*****")
        # isOk = tools.signAndSendPtx(gSK2, gSK2.vk,
        #                             ptx)  # #tools.sendMsgZmqReq(smsg[0], 'localhost', tools.Node.PORT_REP)
        # print("PTX is 3p Duplicate signAndSendPtx: %s\n" % (isOk if not isOk is None else None))
        #
        # print("*****1 payments same input - DUPLICATE TX*****")
        # ptx = tools.WALLET.createPtx(gSK2.vk, [tools.config.MAIN_COIN], [b'1'], [to_addrs[0]])
        # isOk = tools.signAndSendPtx(gSK2, gSK2.vk,
        #                             ptx)  # #tools.sendMsgZmqReq(smsg[0], 'localhost', tools.Node.PORT_REP)
        # print("PTX is 1p Duplicate signAndSendPtx: %s\n" % (isOk if not isOk is None else None))

        ###tests end

        ##ptx1 = tools.createAndSendPtx("Miner1", [tools.config.MAIN_COIN], [b"1"], ["test1"])
        ##assert not ptx1 is None

        # ptx2 = tools.testTx("test1", [tools.config.MAIN_COIN], [b"1"], ["test2"]) # ptx2 is None #TODO toValidate

        ##time.sleep(1)

        # ptx2 = tools.testTx("Miner1", [tools.config.MAIN_COIN], [b"1"], ["test1"]) #Negative test without sleep -> duplicateMsg
        # assert ptx1 != ptx2 #todo assert duplicates in ptx wallet pending?
        # ptx2 = tools.createAndSendPtx("Miner1", [tools.config.MAIN_COIN, tools.config.MAIN_COIN], [b"1", b"1"], ["test1", "test1"])
        # assert not ptx2 is None
        sptx_hash = self.Crypto.to_HMAC(smsg).encode()
        msg_list = [sptx_hash] #[smsg[3]]  # [ptx] ##[ptx1, ptx2] #[ptx1, ptx2] [ptx1, ptx1] # Negative test for ptx2 = None + TODO check for None msg
        # msg_list = ["*" + tools.to_HMAC(ptx1), "*" + tools.to_HMAC(ptx2)]
        # msg_list = [tools.to_HMAC(ptx1), tools.to_HMAC(ptx2)]
        #print("BLOCK_MSG_LIST before submit: ", msg_list)  # [unpackb(m)[2] for m in msg_list[0][2]])

        ## print("*****1st BLOCK validMsg - with INVALID TX inside*****")
        block_msg = (config.Config.MsgType.VERSION,
                     config.Config.MsgType.BLOCK_MSG,
                     b'1', self.Block.getLastBlockId().encode(),
                     msg_list, [b"ToDo_VerifyMinerSigs_turns_and_amounts"],
                     self.Utils.utc_timestamp_b(), gSK.vk)
        sbmsg = self.Crypto.signMsg(block_msg, gSK)
        assert sbmsg
        sbmsg_hash = self.Crypto.to_HMAC(sbmsg)
        print("REQ request hash", sbmsg_hash)
        msg_headers_and_data = packb((config.Config.MsgType.BLOCK_MSG, sbmsg))
        print("REQ request headers",unpackb(msg_headers_and_data)[0])
        print("req_wallet_id", self.Wallets.getWalletId(unpackb(msg_headers_and_data)[1][-32:]))
        self.Net.sendMsgZmqReq(msg_headers_and_data, 'localhost', config.Config.PORT_REP)
        #self.Block.saveBlock(msg_headers_and_data)
        verify_q = self.Sdb.queryServiceDB( "select * from v1_pending_msg \
                as p where p.signed_msg_hash not in \
                (select signed_msg_hash from v1_verified_msg) \
                order by msg_priority desc, node_date asc")  # where node_verified='0'
        # verify_q = tools.SERVICE_DB.queryServiceDB(
        #     "select signed_msg_hash,signed_msg,msg_type,pub_key from v1_pending_msg where node_verified='0' order by msg_priority desc, node_date asc")
        #print('verify_q: %s' % [h[0] for h in verify_q])
        # testQ

        # pmsg = tools.SERVICE_DB.PendingMsg() #v1_pending_msg()
        # pmsg.createTable(ifNotExists=True)
        # pmsg.signed_msg_hash = "1"
        # ##rows = pmsg.select()
        # rows = pmsg.select() #pmsg.q.msg_priority > 1
        # print("pmsg count", rows.count(), [print(r[1]) for r in rows])
        # #print("pmsg rows", pmsg.select(1))
        # #print(pmsg)
        # sys.exit(0)

        self.Node.verifySdbMsgTask()

        # time.sleep(2)

        # print("tools.Block.getLastBlockId()", self.Block.getLastBlockId())
        # # print("*****1st BLOCK validMsg - with INVALID TX inside*****")
        # block_msg = (config.Config.MsgType.VERSION,
        #              config.Config.MsgType.BLOCK_MSG,
        #              '1', self.Block.getLastBlockId().encode(),
        #              msg_list, [b"ToDo_VerifyMinerSigs_turns_and_amounts"],
        #              self.Utils.utc_timestamp_b())
        # wmsg = self.Crypto.signMsg(block_msg, gSK)
        # assert not wmsg[0] is None
        # msg_headers_and_data = packb((config.Config.MsgType.BLOCK_MSG, wmsg))
        # isOk = self.Net.sendMsgZmqReq(msg_headers_and_data, 'localhost', config.Config.PORT_REP)
        # assert isOk
        # time.sleep(12)
        # # tools.Node.TASKS.verifySdbMsg()
        # tools.Node.putQ(lambda: int("a"))