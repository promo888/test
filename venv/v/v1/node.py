import os, sys, logging
from msgpack import packb, unpackb
import time, socket, zmq
from time import sleep
import threading
from queue import PriorityQueue
import subprocess
from decimal import Decimal
from v1 import logger, config, crypto, network, web, \
                 sdb, db, wallets, transaction, message, block, \
                 contract, ico, exchange, utils

class Node():

    def __init__(self):
        self.logger = logger.Logger() #('Node')
        self.Config = config.Config
        self.version = self.Config.VERSION
        self.Utils = utils.Utils()
        self.TASKS = self.Task()
        self.Crypto = crypto.Crypto()
        self.Net = network.Network()
        self.DB = db.Db()
        self.SDB = sdb.ServiceDb()
        self.Tx = transaction.Transaction()
        self.Wallets = wallets.Wallet()
        self.BLK = block.Block()
        self.PORT_REP = config.Config.PORT_REP #7777  # Receiving data from the world TXs, queries ...etc
        self.PORT_UDP = config.Config.PORT_UDP #8888  # Submitting/Requesting data from the miners
        self.PORT_PUB = config.Config.PORT_PUB #9999  # Publish to Miners fanout
        self.PORT_PUB_SERVER = config.Config.PORT_PUB_SERVER #5555   # Optional fanout
        self.PORT_SUB_CLIENT = config.Config.PORT_SUB_CLIENT #6666   # Optional subscribe
        self.WORKERS = 5
        self.tasksQ = PriorityQueue()
        self.init_Qexec()
        self.init_servers()
        self.logger.logp('Node Started', logging.INFO)


    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Node, cls).__new__(cls)
        return cls.instance

    def loop(self):
        while True:
            pass

    def killByPort(self, ports):
        lines = subprocess.check_output(["netstat", "-ano"], universal_newlines=True)  # "-ano" "-ltnp"
        rows = []
        pids = []
        for port in ports:
            for line in lines.splitlines()[4:]:
                c = line.split()
                if port not in c:
                    continue
                rows.append(line)
                print("%s port is open " % port)
                col = {}
                col['proto'] = c[0]
                col['localaddress'] = c[1]
                col['foreignaddress'] = c[2]
                col['state'] = c[3]
                col['pid'] = c[4]
                if int(col['pid']) > 0:
                    pids.append(col['pid'])
                    print("Trying to kill port:%s pid:%s " % (port, col['pid']))
            if (os.name.lower() == 'nt' and len(pids) > 0):
                os.popen("taskkill /F /PID " + " ".join(pids))
            if (os.name.lower() != 'nt' and len(pids) > 0):
                os.popen("kill -9 " + " ".join(pids))
        else:
            print("Ports: ", ports, " are free")


    def restartServer(self, type):  # kill process and restart the server
        pass


    def init_Qexec(self):
        t = threading.Thread(target=self.exeQ, name='Q-Executor')
        t.daemon = True
        t.start()


    def putQ(self, func_with_args):
        try:
            if not self.tasksQ.full():
                self.tasksQ.put_nowait(func_with_args)
            else:
                print("The Q is FULL, persist or fallback")            #
        except Exception as ex:
            print("ExceptionQ: %s \n%s\n" % (ex, ex.__traceback__.tb_lineno))


    def exeQ(self):
        while True:
            try:
                if not self.tasksQ.empty():
                    func = self.tasksQ.get_nowait()
                    print("ExeQ")
                    func()
                    self.tasksQ.task_done()
            except Exception as ex:
                print("ExceptionQ: %s \n%s\n" % (ex, ex.__traceback__.tb_lineno) )


    def init_server(self, type):
        # from multiprocessing import Process #ToDo killPorts+watchdog

        if type is 'rep':
            context = zmq.Context()
            rep_socket = context.socket(zmq.REP)
            rep_socket.bind("tcp://*:%s" % self.PORT_REP)
            print('Starting REP server tcp://localhost:%s' % self.PORT_REP, flush=True)
            while True:
                rep_msg = rep_socket.recv(1024)
                # self.Q.put_nowait(rep_msg)
                sender_wallet_id = self.Wallets.getWalletId(unpackb(rep_msg)[1][-32:])
                print("ZMQ REP rep_msg_hash: ", self.Crypto.to_HMAC((unpackb(rep_msg)[1])))
                print('ZMQ REP request: {} bytes {}'.format(len(rep_msg), len(unpackb(rep_msg)[1])))  # TODO to continue msg&tx validation
                print("ZMQ REP request wallet_id:", sender_wallet_id)
                msg = unpackb(rep_msg)
                #print("REP msg:", type(unpackb(rep_msg)[0]), msg)
                msg_type = msg[0] #headers
                msg_key = msg[1][-32:] #public key
                msg_payload = msg[1]  #signed message
                msg_priority = 2 if msg_type == self.Config.MsgType.BLOCK_MSG else 0
                smsg = msg_payload #packb(unpackb(rep_msg)[1:][0])  # repack msg - get rid of msgType
                ##validated_msg = self.Tx.validateMsg(pmsg)
                validated_msg = True #TODO
                try:
                    ##pub_key = msg_key  # rep_msg[-32:]
                    ##wallet_id = self.Wallets.getWalletId(pub_key) #"W" + self.Crypto.to_HMAC(pub_key)
                    #print("REP wallet_id:", wallet_id)
                    wallet_exist = self.DB.getDbKey(sender_wallet_id)
                    if wallet_exist is None:
                        print("ZMQ REP response: Invalid Sender", sender_wallet_id)
                        rep_socket.send(b'Error: Invalid Sender')
                        continue
                    wallet_exist = True
                except Exception as ex:
                    print("Exception REP server: %s %s %s" % (sender_wallet_id, ex.__traceback__.tb_lineno, ex))
                    rep_socket.send(b'Error: Invalid Msg')
                    continue

                msg_id = self.Crypto.to_HMAC(smsg)  # (rep_msg)
                msg_in_db = self.DB.getDbRec(msg_id, self.Config.NODE_DB_FOLDER)
                msg_in_sdb = self.Tx.getServiceDbTx(msg_id)
                if not wallet_exist is None and not msg_in_sdb and validated_msg and msg_in_db is None:  # TODO reject if ipaddr > 1 or from_addr within the same block
                    if self.DB.isDBkey(msg_id, self.Config.NODE_DB_FOLDER):
                        print('msg Already Exist in DB:' , msg_id)
                        rep_socket.send(b'Error: Msg %s Exist\n')
                    else:
                        self.putQ(lambda: self.SDB.persistPendingMsg(msg_id, rep_msg, msg_key, msg_type, msg_priority=msg_priority))
                        rep_socket.send(b'OK: Msg is Valid\n')
                else:
                    error = "Msg Exist" if (msg_in_db is not None or msg_in_sdb) else "Invalid Msg"
                    error = "Sender Not Exist" if wallet_exist is None else error
                    rep_socket.send(b'Error: %s\n' % error.encode())

        if type is 'udps':
            udps_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udps_socket.bind(('', self.PORT_UDP))
            print('Starting UDP server udp://localhost:%s' % self.PORT_UDP, flush=True)
            while True:
                udp_msg = udps_socket.recvfrom(1024)
                data = udp_msg[0]
                addr = udp_msg[1]
                self.tasksQ.put_nowait(udp_msg[0])

                if not data:
                    break

                reply = data
                udps_socket.sendto(reply, addr)
                # print('Message[' + addr[0] + ':' + str(addr[1]) + '] - ') # + data.strip()) #ToDo validation on MinersIP + verify

        if type is 'pub':
            context = zmq.Context()
            pub_socket = context.socket(zmq.PUB)
            pub_socket.bind("tcp://*:%s" % self.PORT_PUB)
            print('Starting PUB server tcp://localhost:%s' % self.PORT_PUB, flush=True)
            while True:
                try:
                    if not self.tasksQ.empty():
                        pub_msg = Q.get_nowait()
                        pub_socket.send(pub_msg)
                except Exception as ex:
                    print('PUB Exception: %s' % ex, flush=True)
                    # self.logger.logp('Publish Error: ', logging.ERROR, ex)

        if type is 'sub':
            context = zmq.Context()
            sub_socket = context.socket(zmq.SUB)
            sub_socket.connect("tcp://localhost:%s" % self.PORT_PUB)
            sub_socket.setsockopt(zmq.SUBSCRIBE, b'')
            print('Starting SUB server tcp://localhost:%s' % self.PORT_PUB, flush=True)
            count = 0
            while True:
                sub_msg = sub_socket.recv()
                if sub_msg: count += 1

        if type is 'req':
            context = zmq.Context()
            req_socket = context.socket(zmq.REQ)
            req_socket.connect("tcp://localhost:%s" % self.PORT_REP)
            print('Starting REQ server tcp://localhost:%s' % self.PORT_REP, flush=True)


        if type is 'udpc':
            udpc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # test #TODO to remove
            print('Starting UDP client', flush=True)


    def sendUDP(self, bin_msg, host='localhost', port=None):
        if port is None:
            port = self.PORT_UDP
        udpc_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udpc_socket.sendto(bin_msg, (host, port))
        response = udpc_socket.recvfrom(1024)
        print('Response from %s:%s response: \n%s' %(host, port, response))
        return response


    def deleteSdbMsgTask(self):
        while True:
            try:
                now = int(time.time())
                if not self.TASKS.delete_processing and now - self.TASKS.start_time >= self.TASKS.RUN_SECS:  # TODO tools.config.TASK_VERIFY_SDB_INTERVAL_SECS
                    self.TASKS.delete_processing = True
                    # self.start_time #synced with verifyTask
                    print(now, ' - Task deleteSdbMsg')
                    sql = "delete from v1_pending_msg where signed_msg_hash in %s" %  msg_hashes
                    print(sql)
                    msg_hashes = "deleteSdbMsqQ: %s" % tuple(self.TASKS.deleteSdbVerifiedMsqQ)
                    self.SDB.queryServiceDB(sql)
                    self.TASKS.delete_processing = False
            except Exception as ex:
                self.TASKS.delete_processing = False


    # @debug_func(self.verifySdbMsgTask)
    def verifySdbMsgTask(self):
        while True:
            try:
                now = int(time.time())
                if not self.TASKS.verify_processing and now - self.TASKS.start_time >= self.TASKS.RUN_SECS:  # TODO tools.config.TASK_VERIFY_SDB_INTERVAL_SECS
                    self.TASKS.verify_processing = True
                    self.TASKS.start_time = now
                    print(now, ' - Task verifySdbMsg')
                    # print("%s Started Task verify_processing" % tools.utc())
                    verify_q = self.SDB.queryServiceDB \
                        ("select * from v1_pending_msg as p where p.signed_msg_hash not in \
                        (select signed_msg_hash from v1_verified_msg) \
                        order by msg_priority desc, node_date asc")  # todo limitBYconfig where node_verified='0'
                    print("verify_q size: ", len(verify_q))
                    for m in verify_q:
                        print("verify_q m:", m[0], m[1])
                        msg = unpackb(m[1])
                        print("Node verify msg: ", self.Crypto.to_HMAC(msg[1]))
                        #todo validation+verification
                        # if self.Crypto.to_HMAC(unpackb(m)[1])) != m[0]:
                        #     err_msg = "Node: INVALID Hash Header %s" % m[0]
                        #     print(err_msg)
                        #     self.TASKS.deleteSdbInvalidMsqQ.add(m[0])
                        #     continue
                        signed_msg_hash = self.Crypto.to_HMAC(msg[1])
                        signed_msg = msg[1]
                        # signed_msg_hash = self.Crypto.to_HMAC(signed_msg)
                        print('transport_hash: %s, signed_msg_hash: %s' % (self.Crypto.to_HMAC(m), signed_msg_hash))
                        pubk =  msg[1][-32:]
                        if self.isNodeValid("W" + self.Crypto.to_HMAC(pubk)):
                            if msg[0] == self.Config.MsgType.BLOCK_MSG:
                                msg_list = set()
                                block_persist_msgs = {}
                                block_delete_msgs = set()
                                # todo change in block write ->bin msg
                                smsg = msg[1]
                                ##assert signed_msg_hash == self.Crypto.to_HMAC(block_bin[1])  # DON'T REMOVE [msg,sig] correct hmac validation
                                nodeSig, blockMsg = self.Crypto.verifyMsgSig(smsg, pubk)
                                ublock = unpackb(blockMsg)
                                prev_block_hash = ublock[3]
                                msg_type = m[3]
                                msg_priority = m[-2]
                                block_id = "B" + signed_msg_hash
                                # print("ublock: %s\n%s\n" % (ublock, [unpackb(inp[2][2])[2] for inp in [m for m in ublock[4]]])) #[unpackb(inp[2][2])[2] for inp in [m for m in ublock[4]]] [inp[2] for inp in [m for m in ublock[4]]]
                                ##print("Duplicates found in Block = %s" % len(ublock[4]) == len(set(ublock[4])))
                                print("self.DB.getDbRec(prev_block_hash)", prev_block_hash, self.DB.getDbRec(prev_block_hash))
                                if not self.DB.getDbRec(prev_block_hash) or \
                                        self.DB.getDbRec(config.Config.MsgType.BLOCK_MSG + signed_msg_hash.encode()) \
                                        or len(ublock) < 6 or not nodeSig:  #none or duplicate check
                                    err_msg = "BLOCK (%s) IS INVALID" % signed_msg_hash
                                    print(err_msg)
                                    self.TASKS.deleteSdbInvalidMsqQ.add(signed_msg_hash)
                                    continue  # todo supposed to ignore irrelevant block or block with missing msgs

                                block_msg_hashes = [m.decode() for m in [msg for msg in ublock[4]]]
                                verified_sql = "select signed_msg_hash from v1_verified_msg where signed_msg_hash in (%s)" % (
                                    ",".join(["'%s'" % m for m in block_msg_hashes]))
                                print("verified_sql", verified_sql)
                                verified_msgs = self.SDB.queryServiceDB(verified_sql)
                                verified_msg_hashes = [m[0] for m in verified_msgs]
                                if len(verified_msg_hashes) != len(block_msg_hashes):  # TODO compare set of hashes
                                    missing_msgs = list(set(block_msg_hashes) - set(verified_msg_hashes))
                                    print("Error: Not Enough verified msgs -> If not in pending -> get missing - else verify/update priority")
                                    # print("Missing Block msgs: ", block_msg_hashes & verified_msg_hashes)
                                    continue

                                print("All Block msgs are exist in SDB", block_msg_hashes)
                                verified_sql = "select * from v1_verified_msg where signed_msg_hash in (%s)" % (
                                    ",".join(["'%s'" % m for m in block_msg_hashes]))
                                print(verified_sql)
                                verified_msgs = self.SDB.queryServiceDB(verified_sql)

                                # for mm in verified_msgs:
                                #     print(mm)
                                # sys.exit(0)

                                block_senders_wallets = []
                                block_recievers_wallets = []
                                msg_ctxs = []
                                ptxs_count = len(block_msg_hashes)  # (ublock[4])
                                print(verified_msgs)
                                for i in range(ptxs_count):
                                    msg_sender_wallet = "W" + self.Crypto.to_HMAC(verified_msgs[i][3])  # .encode()

                                    # sdb_ptx = self.DB.getDbRec(m_hash) #todo verify MsgType
                                    # if sdb_ptx is None:
                                    #     raise Exception(m_hash + "Not Exist in SDB")
                                    # sdb_ptx_verified, sdb_ptx_bin = self.Crypto.verifyMsgSig(signed_msg, signed_msg[-32:])
                                    # assert sdb_ptx_verified
                                    # sdb_ptx_u = unpackb(sdb_ptx_bin)
                                    # assert self.Tx.verifyMsg(sdb_ptx_bin, sdb_ptx_u)
                                    # assert self.Wallets.insertTxsToDbWallets(sdb_ptx_u, m_hash, block_id)
                                    # sys.exit(0)

                                if not msg_sender_wallet in block_persist_msgs.keys():  # block_senders_wallets.keys():
                                        msg_sender_wallet_data = self.Wallets.getDbWalletDefault(msg_sender_wallet)
                                        block_senders_wallets.append(msg_sender_wallet) # [msg_sender_wallet] = msg_sender_wallet_data
                                        block_persist_msgs[msg_sender_wallet] = msg_sender_wallet_data

                                else:
                                    raise Exception("Only 1 PTX/ permitted per Sender in block")  # todo msgType
                                    #TODO msg=PTX?
                                msg_inputs_ids = list(set([inp.decode() for inp in [itx[2]
                                            for itx in [unpackb(m) for m in unpackb(
                                            verified_msgs[i][2])[2]]] for inp in inp]))  # todo validate calc vs submitted or ignore? in-msg ctx hashes
                                print('Msg inputs hashes: ', len(msg_inputs_ids), msg_inputs_ids)
                                marked_spent_itxs, updated_wallet, db_updates = self.Wallets.markSpentTxRecordsInTheWallet \
                                        (msg_inputs_ids, block_persist_msgs[msg_sender_wallet], "B" + signed_msg_hash)
                                if not marked_spent_itxs or db_updates is None:
                                    raise Exception("Exception node All/Some inputs \n%s\n are missing in the Wallet %s" %
                                        (msg_inputs_ids, msg_sender_wallet))

                                # block_senders_wallets[msg_sender_wallet] = updated_wallet
                                block_persist_msgs[msg_sender_wallet] = updated_wallet
                                block_persist_msgs = {**block_persist_msgs, **db_updates}
                                    ##for k, v in db_updates.items():
                                    ##    block_persist_msgs[k] = v

                                msg_ctxs = [unpackb(m) for m in unpackb(verified_msgs[i][2])[2]]
                                ctx_receivers_wallets = [r_w[3] for r_w in msg_ctxs]
                                ctx_assets = [r_w[4] for r_w in msg_ctxs]
                                for a in set(ctx_assets):
                                    if not self.DB.isDBkey(a):
                                        raise Exception("Exception node block %s asset is NOT Exist in DB" % a.decode())
                                ctx_assets_u = set(ctx_assets)
                                ctx_receivers_wallets = [w.decode() if isinstance(w, bytes) else w for w in
                                                             ctx_receivers_wallets]
                                for wallet in ctx_receivers_wallets:
                                    if not wallet in block_persist_msgs:  # block_recievers_wallets.keys():
                                            ##wallet = wallet.encode() if isinstance(wallet, str) else wallet
                                            ##block_recievers_wallets[wallet] = (tools.getDbWalletDefault(wallet))
                                        block_persist_msgs[wallet] = self.Wallets.getDbWalletDefault(wallet)
                                        block_recievers_wallets.append(wallet)

                                msg_ctxs_pubkeys = [m[2] for m in verified_msgs]
                                ptx_hash = block_msg_hashes[i]
                                print("block_msg ptx_hash" , type(ptx_hash), ptx_hash)
##                                raise Exception("test")
                                for m in range(len(msg_ctxs)):
                                    ctx_hash = self.Crypto.to_HMAC(packb((msg_ctxs[m], msg_ctxs_pubkeys[0])))
                                    ctx_msg = packb((msg_ctxs[m], msg_ctxs_pubkeys[0]))
                                    ctx_reciever = msg_ctxs[m][3].decode() if isinstance(msg_ctxs[m][3], bytes) else \
                                    msg_ctxs[m][3]
                                    ctx_asset = msg_ctxs[m][4]
                                    ctx_asset_amount = Decimal(msg_ctxs[m][5].decode())  # todo to_miner_pool fee + Decimal(msg_ctxs[m][6].decode())

                                    if block_persist_msgs[ctx_reciever] is None:
                                        raise Exception("Exception node ctx_reciever not found in Q", ctx_reciever, block_persist_msgs)
                                    block_persist_msgs[ctx_reciever] = self.Wallets.addUtxoToTheWallet(ctx_asset, ctx_hash, str(ctx_asset_amount), ptx_hash, block_persist_msgs[ctx_reciever])
                                    assert ctx_reciever in block_persist_msgs and not block_persist_msgs[ctx_reciever] is None
                                    block_persist_msgs["+" + ctx_hash] = packb("*" + ptx_hash)
                                    print("Wallet ctx_reciever", ctx_reciever, block_persist_msgs[ctx_reciever])

                                    print("Block %s PTX: %s \nInputs: %s \nCTX: %s \nMsg: %s " % (
                                        "B" + signed_msg_hash, ptx_hash, msg_inputs_ids, ctx_hash, msg_ctxs[m]))

                                    print("signed_ptx", verified_msgs[i][1])
                                    block_persist_msgs["+" + ptx_hash] = "B" + signed_msg_hash
                                    block_persist_msgs["*" + ptx_hash] = packb(verified_msgs[i][1]) #signed_ptxN
                                block_delete_msgs.add(ptx_hash)

                                block_persist_msgs[block_id] = packb(smsg)

                                print("Block %s msg_hashes: %s %s" % (
                                signed_msg_hash, len(block_msg_hashes), block_msg_hashes))
                                print("%s (msg/ptx) inputs: %s" % (ptxs_count, msg_ctxs))

                                print("block_persist_msgs", block_persist_msgs)
                                assert self.DB.insertDbBatchFromDict(block_persist_msgs)
                                #sys.exit(0)
                                #raise Exception("Test")
                                self.SDB.deleteBlockSdbVerifiedMsgs(list(block_delete_msgs))


                                # Todo add to blockBatch
                                # Block is valid and msgs already verified!!!
                                # print('msg[1]', msg[1])
                                # self.SDB.saveSdbVerifiedMsg(signed_msg_hash, msg[1], blockMsg, pubk, msg_type,
                                #                          msg_priority)
                                # # TODO
                                # print("TODO######Update Wallets#####wallets state+ block_hash######")
                                # self.TASKS.deleteSdbVerifiedMsqQ.add(signed_msg_hash)
                                # # TODO raise exception/ignore if there are missing transactions, invalid...
                                #
                                # block_msg_hashes.append(signed_msg_hash)
                                # # todo? change saving blockchain verified_msg into signed_msg -> Sig 1000request/sec WebLoad
                                # # todo currently ptxs only
                                # verified_sql = "select * from v1_verified_msg where signed_msg_hash in (%s)" % (
                                #     ",".join(["'%s'" % m for m in block_msg_hashes]))
                                #
                                # block_ptx_inputs = set()
                                # block_senders = set()
                                # try:
                                #     for msg in verified_msgs:  # todo redo validation hash(msg,pubk)
                                #         umsg = unpackb(msg[2])
                                #         # msg_sender_wallet = b"W" + self.Crypto.to_HMAC(umsg[-1]).encode()
                                #         # msg_sender_wallet_data = tools.getDbWalletDefault(msg_sender_wallet)
                                #         # block_senders_wallets[msg_sender_wallet] = msg_sender_wallet_data
                                #         # if msg_sender_wallet in block_senders_wallets.keys(): #block_senders:
                                #         #    raise Exception("Only 1 PTX permitted pre block")
                                #         # block_senders.add(msg_sender_wallet.encode())
                                #
                                #         msg_receivers_wallets = umsg[3]
                                #         for wallet in msg_receivers_wallets:
                                #             if not wallet in block_persist_msgs.keys():
                                #                 msg_receiver_wallet_data = self.Wallets.getDbWalletDefault(wallet)
                                #                 block_recievers_wallets.append(wallet)
                                #                 block_persist_msgs[wallet] = msg_receiver_wallet_data
                                #
                                #         # block_senders_amounts[msg_sender_wallet] = tools.WALLET.getDbWalletUnspentAmounts(msg_sender_wallet)
                                #         # print("msg_sender_wallet", msg_sender_wallet, tools.WALLET.getDbWalletUnspentAmounts(msg_sender_wallet))
                                #             itx_list_u = set([item for item in [unpackb(itx)[2] for itx in umsg[2]] for item in item])
                                #         ##ptx_assets = [unpackb(itx)[4] for itx in umsg[2]]
                                #             print("PTX itx_list_u", itx_list_u)
                                #             for itx in itx_list_u:
                                #                 # if itx in block_ptx_inputs:  # duplicate
                                #                 #     raise Exception("PTX Duplicate Inputs/Spendings")
                                #                 block_ptx_inputs.add(itx)
                                #                 # if len(block_ptx_inputs) == 0:
                                #                 #     raise Exception("PTX Missing Inputs")
                                #
                                #                 save_itx = itx[1:] if isinstance(itx[1:], str) else itx[1:].decode()
                                #                 print('save_itx', save_itx, "B" + signed_msg_hash)
                                #                 block_persist_msgs["-" + save_itx] = "B" + signed_msg_hash
                                #                 # todo to continue last
                                #
                                #             print("block_ptx_inputs", block_ptx_inputs)
                                #             msg_bin = packb((msg[1], msg[2]))
                                #             msg_hash = msg[0]  # todo recalc hash validation
                                #             block_persist_msgs["*" + msg_hash] = msg_bin
                                #         if len(block_persist_msgs) == 0:
                                #             raise Exception('Block missing PTXs/msgs?')
                                #         if len(set(block_senders_wallets)) != ptxs_count:
                                #             raise Exception("Block Permits 1 PTX per Wallet")
                                #         block_persist_msgs["B" + signed_msg_hash] = blockMsg  # add blockMsg itself
                                #     # block_persist_wallets = {}
                                #     ##print("DB_Batch: ", block_persist_msgs)  # .keys())
                                #     # print("#####TODO -outer in start BlockCalcPtxHash #1",
                                #     #       self.Crypto.to_HMAC(packb((verified_msgs[0][1], (verified_msgs[0][3])))))
                                #     ##assert self.DB.insertDbBatchFromDict(block_persist_msgs)
                                #     # for k,v in block_persist_msgs.items():
                                #     #     self.DB.addToBatch([k, v])
                                #     # self.DB.writeBatch()
                                #     print('block_persist_msgs', block_persist_msgs)
                                #
                                #     # tools.SERVICE_DB.deleteBlockSdbVerifiedMsgs(block_persist_msgs.keys())
                                #     # block_persist_msgs = {}
                                #     # verify_q = []
                                #     print("%s Block deleteSdb Pending and Verified Msgs" % now)
                                #     self.SDB.deleteSdbPendingMsgsIfVerified()
                                #     self.SDB.deleteBlockSdbVerifiedMsgs(block_persist_msgs.keys())
                                #     self.SDB.deleteBlockSdbVerifiedMsgs([signed_msg_hash])  # del verified block
                                # except Exception as ex:
                                #     self.SDB.deleteSdbPendingMsgsIfVerified()
                                #     print("Block Exception: ", ex.__traceback__.tb_lineno, ex)
                                #     # continue #proceed to next msg
                                #     block_persist_msgs = {}
                                #     block_senders_wallets = []
                                #     block_recievers_wallets = []
                                #     raise Exception("Block Exception: ", ex)
                                ##assert self.DB.insertDbBatchFromDict(block_persist_msgs)

                                    # todo time<=blockchain time for each msg

                                # for ptx_input in ptx_inputs:
                                #     if not tools.isDBvalue(ptx_input.encode()):
                                #         log_msg = "PTX %s is NOT found in DB" % (ptx_input)
                                #         print(log_msg)
                                #         print("TODO getPtxWithHighestPriority+reschedule NextBlockPersist")
                                #         #raise Exception(log_msg) #exit presist/remove - leave data until downloaded
                                #         continue

                                # tools.Block.verified_block["block_id"] = "B" + signed_msg_hash
                                # tools.Block.verified_block["inputs_list"] = set(ptx_inputs)

                                # TODO to continue reTask download missing [ctxs, ptxs , blocks)
                                # print()

                                # # complete msgs in blocks
                                # msg_list = ublock[4] #[unpackb(msg) for msg in ublock[4]] #ublock[4]#
                                # print('block_msg_list after submit' , msg_list)
                                # block_txs = {}
                                # for msg in msg_list:
                                #     #msg_type = msg[0]
                                #     #msg_bin, msg_sig = msg[1]
                                #     # #print(tools.verifyMsgSig(msg_bin, msg_sig))
                                #     # isVerified, verified_msg_bin = tools.verifyMsgSig(msg_bin, msg_sig)
                                #     # if not isVerified:
                                #     #     raise Exception("Invalid Msg Sig in Block")
                                #     # unpacked_block_msg = unpackb(verified_msg_bin)
                                #     # print('verified_unpacked_block_msg: ', unpacked_block_msg)
                                #     # print('msg_type: ', msg_type)
                                #     # if msg_type == tools.MsgType.Type.PARENT_TX_MSG.value:
                                #     #     msg_itxs_valid = tools.arePtxInputsValid(unpacked_block_msg)
                                #     #     print('areMsgItxValid:', msg_itxs_valid == False, msg_itxs_valid)
                                #     #     if not msg_itxs_valid:
                                #     #         raise Exception("Invalid Msg Inputs in Block")
                                #     #     print("block msg inputs:\n", [msg for msg in unpacked_block_msg[2]])
                                #
                                #
                                #     sdb_verified_msg = tools.SERVICE_DB.queryServiceDB(
                                #         "select * from v1_verified_msg where signed_msg_hash='%s'" % msg.decode())
                                #     if sdb_verified_msg is None or len(sdb_verified_msg) == 0 :
                                #         sdb_pending_msg = tools.SERVICE_DB.queryServiceDB(
                                #             "select * from v1_pending_msg where signed_msg_hash='%s'" % msg.decode())
                                #     #print("verify msg %s in sdb - verified, pending: %s, %s" % (msg, len(sdb_verified_msg), len(sdb_pending_msg)))
                                #         if sdb_pending_msg is None or len(sdb_pending_msg) == 0:
                                #             print("%s msg NOT FOUND in SDB v1_pending_msg" % msg)
                                #             #pass
                                #             #todo getMsgFromNode(signed_msg_hash) + Verify
                                #             #continue (Don't delete prior retrieve & verify)
                                #     else:
                                #         # b_msg = unpackb(sdb_verified_msg[0][1])
                                #         # b_key = sdb_verified_msg[0][2] ##wmsg[-1]
                                #         # sig, msg = tools.verifyMsgSig(b_msg[0], b_key)
                                #         # #TODO verify amounts in ptx+here+delete verified+ indexSdb for another retrieval
                                #         # assert sig
                                #         # umsg =  unpackb(msg) ##wmsg
                                #         # #b_itx_list = list(set([itx for itx in [itx[2] for itx in umsg[2]]]))
                                #         # block_ptx_hashes = [umsg[itx] for itx in range(len(umsg)) if itx % 2 != 0]
                                #         #list(set([itx for itx in umsg[4]]))
                                #         #TODO to continue #[umsg[itx] for itx in range(len(umsg)) if itx % 2 != 0]
                                #         #print("block_msg PTX list %s %s" % ("block_id?", block_ptx_hashes))
                                #
                                #         msg_type = sdb_verified_msg[0][3]
                                #         if msg_type == tools.MsgType.Type.PARENT_TX_MSG.value:
                                #             ubmsg = unpackb(sdb_verified_msg[0][1])
                                #             #print("sdb_verified_msg:\n%s\n", sdb_verified_msg)
                                #             ptx_hash = sdb_verified_msg[0][0]
                                #             print("ptx_hash: %s , signed_msg_hash: %s" % (ptx_hash, signed_msg_hash))
                                #             ctxs = [unpackb(itx) for itx in ubmsg[2]]
                                #             itxs = list(set([i.decode() for i in [itx[2] for itx in ctxs ] for i in i]))
                                #             itx_assets = [itx[4] for itx in ctxs]
                                #             itx_amounts = [itx[5].decode() for itx in ctxs]
                                #             print("ITX list", itxs) #%s %s" % ("block_id?", block_ptx_hashes))
                                #             ptx_assets = list(set([itx[4] for itx in ctxs]))
                                #             wallet_id = "W" + self.Crypto.to_HMAC(sdb_verified_msg[0][2])
                                #             if not wallet_id in block_txs.keys():
                                #                 block_txs[wallet_id] = {"assets": set(), "amounts": []}
                                #             for a in ptx_assets:
                                #                 if a not in block_txs[wallet_id]["assets"]:
                                #                     block_txs[wallet_id]["assets"].add(a)
                                #                     #TODO +fees sum([Decimal(itx[5].decode()) + Decimal(itx[6].decode())  for itx in ctxs if itx[4] == a])
                                #                 ptx_asset_amounts = sum([Decimal(itx[5].decode())  for itx in ctxs if itx[4] == a])#sum([Decimal(itx[5].decode()) for itx in ctxs if itx[4] == a])
                                #                 block_txs[wallet_id]["amounts"].append(ptx_asset_amounts)
                                #
                                # #TODO? assert keepChange
                                # print("block_txs: \n", block_txs) #todo msgs, contracts, icos..
                                #             #ua = tools.getDbWallet(wallet_id) #tools.getLocalWalletUnspentAssets(wallet_id)
                                #             #print("Wallet %s Unspent Amounts \n%s" % (wallet_id, ua))

                            # TODO compute/calc MsgHash
                            elif m[3] == self.Config.MsgType.PARENT_TX_MSG:
                                print("PTX msg", m)
                                isVerified, msg_bin = self.Crypto.verifyMsgSig(signed_msg, signed_msg[-32:])
                                #assert isVerified
                                if not self.TASKS.isNone(isVerified):
                                    umsg = unpackb(msg_bin)
                                    ##assert signed_msg_hash == self.Crypto.to_HMAC(umsg[2])
                                    print("Processing msg: %s\n%s" % (signed_msg_hash, umsg))
                                    umsg_data = [unpackb(msg) for msg in umsg[2]][0]
                                    print("umsg_data", umsg_data)
                                    vmsg = self.Tx.verifyMsg(signed_msg_hash, umsg)##umsg_data
                                    print('vmsg', vmsg)
                                    # vmsg_hash = self.Crypto.to_HMAC(msg_bin)
                                    # print('vmsg_hash', vmsg_hash)
                                    msg_type = umsg[1]
                                    msg_priority = m[-2]
                                    # if m[3] == tools.MsgType.Type.PARENT_TX_MSG.value
                                    ##itx_list_u = list(set([item for item in [itx[2] for itx in umsg[2]] for item in item]))
                                    ##print("PTX itx_list_u", itx_list_u)
                                    ##self.Config.MsgType.PARENT_TX_MSG
                                    #itx_list = packb(itx_list_u)  # b'TODO' # #packb(['TODO ITX_LIST'])
                                    # self.putQ(lambda: tools.persistVerifiedMsg(signed_msg_hash, vmsg_hash, msg_bin, pubk, msg_type, itx_list, msg_priority=msg_priority))
                                    ##tools.persistVerifiedMsg(signed_msg_hash, msg_bin, pubk, msg_type, itx_list, msg_priority)
                                    self.SDB.saveSdbVerifiedMsg(signed_msg_hash, signed_msg, msg_bin, pubk, msg_type,
                                                             msg_priority)
                                    self.TASKS.deleteSdbVerifiedMsqQ.add(signed_msg_hash)  # todo ?if need
                                    print("%s PTX deleteSdbPendingMsgsIfVerified" % now)
                                    self.SDB.deleteSdbPendingMsgsIfVerified()
                                    # self.TASKS.deleteSdbInvalidMsqQ.add(signed_msg_hash) #negative test

                                else:
                                    self.TASKS.deleteSdbInvalidMsqQ.add(signed_msg_hash)

                            # TODO to continue pending2verified content with SqlObject
                            else:  # elif m[3] != tools.MsgType.Type.PARENT_TX_MSG.value:
                                continue  # TODO ICOs,Msgs
                            # if len(verify_q) > 0:
                            #     verify_q.pop()
                    # tools.SERVICE_DB.deleteSdbPendingMsgsIfVerified() #handled onBlock
                    # tools.SERVICE_DB.deleteBlockSdbVerifiedMsgs([signed_msg_hash]) #handled onBlock
                    self.TASKS.deleteSdbVerifiedMsqQ = set()
                    self.SDB.deleteSdbInvalidMsgs(self.TASKS.deleteSdbInvalidMsqQ)
                    self.TASKS.deleteSdbInvalidMsqQ = set()
                    self.TASKS.verify_processing = False
                    self.TASKS.start_time = now

                    print('%s - Task verifySdbMsg took %s sec' % (now, now - self.TASKS.start_time))
                    print("sdb verified count: ",
                          self.SDB.queryServiceDB("select count(*) from v1_verified_msg"))
                    # print("end verify_q size: ", len(verify_q))
                    # if len(verify_q) > 0:
                    #     print("Current verify_q: ", m)
                    # TODO - remove redundant Q
                    # sdb verified count: [(0,)]
                    # end verify_q size: 1

                    verify_q = []
            except Exception as ex:
                self.SDB.deleteSdbPendingMsgsIfVerified()
##                self.TASKS.deleteSdbInvalidMsqQ.add(signed_msg_hash)
                self.TASKS.verify_processing = False
                self.TASKS.start_time = now
                print("Exception node TaskVerifySdb: \n %s \n ErrorLine: %s" % (ex, ex.__traceback__.tb_lineno))
                print(' - Task verifySdbMsg took %s sec' % (now - self.TASKS.start_time))
                verify_q = []
                # pass

    def init_servers(self):
        # from time import sleep
        # import threading

        ports = [self.PORT_REP, self.PORT_UDP, self.PORT_PUB, self.PORT_PUB_SERVER]
        self.killByPort(ports)

        TYPES = ['rep', 'udps', 'TaskVerify']  # TaskVerify includes'TaskDelete']
        workers = []
        print('TYPES', TYPES)
        for s in range(len(TYPES)):
            print('Starting server %s' % TYPES[s])
            if TYPES[s] == 'TaskVerify':
                t = threading.Thread(target=self.verifySdbMsgTask, args=(), name='node-TaskVerify')
            elif TYPES[s] == 'TaskDelete':
                t = threading.Thread(target=self.TASKS.deleteSdbVerifiedMsqQ, args=(), name='node-TaskDelete')
            else:
                t = threading.Thread(target=self.init_server, args=(TYPES[s],), name='server-%s' % TYPES[
                    s])
            t.daemon = True
            t.start()
            workers.append(t)
        sleep(1)


    def getNodesList(self): #todo
        return []

    def getValidNodesList(self):#todo
        return [('localhost', self.PORT_REP)]

    def appendPendingPtxToLocalWallet(self, sender_wallet_id, msg_id, ptx):
        try:
            print(sender_wallet_id)
            wallet_data = unpackb(self.Wallets.getLocalWallet(sender_wallet_id))
            assert not wallet_data is None
            print("local_wallet_data %s %s: " % (sender_wallet_id, wallet_data))
            wallet_unspent_amounts = [{asset: sum([Decimal(inp[1].decode())
                                                   for inp in
                                                   wallet_data["assets"][asset]["inputs"]]) -
                                              sum([Decimal(inp[1].decode())
                                                   for inp in
                                                   wallet_data["assets"][asset]["outputs"]]) -
                                              sum([Decimal(inp[1].decode())
                                                   for inp in wallet_data["assets"][asset]["outputs_pending"]])}
                                      for asset in wallet_data["assets"]]
            # todo assert negative value doesnt exist in unspents + notify
            print("wallet_unspent_amounts", wallet_unspent_amounts)
            ptx_in = msg_id
            ptx_ctxs = [unpackb(itx) for itx in ptx[2]]
            ctxs_outs = [utx for utx in ptx[7]]  # todo recalc
            ctxs_assets = [itx[4] for itx in ptx_ctxs]
            ctxs_amounts = [Decimal(itx[5].decode()) for itx in ptx_ctxs]
            ctxs_fees = [Decimal(itx[6].decode()) for itx in ptx_ctxs]
            ptx_fee = Decimal(ptx[6].decode())
            for i in range(len(ctxs_assets)):
                asset = ctxs_assets[i]
                amounts_and_fees = self.Utils.dec2b(ctxs_amounts[i] + ctxs_fees[i])
                print("ctx asset: ", asset)
                wallet_data["assets"][asset]["outputs_pending"].append([ctxs_outs[i], amounts_and_fees, ptx_in])
                total_pending = sum([(Decimal(out[1].decode())) for
                                     out in wallet_data["assets"][asset]["outputs_pending"]])
                unspent_amount = [unspent_amount for unspent_amount in wallet_unspent_amounts if
                                  asset in unspent_amount.keys()]
                asset_unspent_amount = unspent_amount[0][asset] if len(unspent_amount) > 0 else 0
                if total_pending > asset_unspent_amount:
                    print("Outputs(%s) exceeds inputs(%s) for asset %s in ptx %s " % (
                    total_pending, asset_unspent_amount, asset, ptx_in))
                    return False

            # tools.WALLET.wallet_path
            wallet_path = os.path.join(self.Wallets.path, sender_wallet_id + '.wallet')
            with open(wallet_path, "wb") as wallet:
                wallet.write(packb(wallet_data))
                print("wallet updated: ", wallet_data)
            return True
        except Exception as ex:
            print("Exception appendPendingPtxToLocalWallet: %s %s" % (ex.__traceback__.tb_lineno, ex))
            return False

    def signAndSendPtx(self, sk=None, vk=None, ptx=None):
        assert not sk is None and not vk is None and not ptx is None  # to rem
        if ptx is None:
            return None
        smsg = self.Wallets.signMsg(ptx, sk, vk)
        assert not smsg is None and not smsg[0] is None  # todo rem
        if smsg[0] is None:
            return None
        res = self.Net.sendMsgZmqReq(smsg[0], 'localhost', self.PORT_REP)
        ##        assert res
        ptx_id = "+" + smsg[3]
        sender_wallet_id = "W" + self.Crypto.to_HMAC(vk)
        isLocalWalletUpdated = self.appendPendingPtxToLocalWallet(sender_wallet_id, ptx_id, ptx) if res else None
        ret = smsg[3] if isLocalWalletUpdated else None
        # if ret is None:
        #     self.TASKS.deleteSdbVerifiedMsqQ.add(smsg[3])
        return ret

    def createAndSendPtx(self, senderSeed, assets, amounts, to_addrs):
        sk, vk = self.Crypto.getKeysFromSeed(senderSeed)
        to = [self.Crypto.to_HMAC(s) for s in to_addrs]
        ptx = self.Wallets.createPtx(vk._key, assets, amounts, to)
        #        assert not ptx is None  #todo rem
        if ptx is None:
            return None
        smsg = self.Wallets.signMsg(ptx, sk, vk._key)  # signMsg prepends msgType
        assert not smsg is None and not smsg[0] is None  # todo rem
        if smsg[0] is None:
            return None
        res = self.Net.sendMsgZmqReq(smsg[0], 'localhost', self.PORT_REP)
        print("sendMsgZmqReq res:", res)
        assert res
        ptx_id = "+" + smsg[1]
        sender_wallet_id = "W" + self.Crypto.to_HMAC(vk._key)
        isLocalWalletUpdated = self.appendPendingPtxToLocalWallet(sender_wallet_id, ptx_id, ptx) if res else None
        ret = smsg[3] if isLocalWalletUpdated else None
        # if ret is None:
        #     self.TASKS.deleteSdbVerifiedMsqQ.add(smsg[3])
        return ret

    def isNodePenaltied(self):
        # todo config treshold - for penalty rewards
        return False

    def isNodeLastBlock(self):
        return True

    def isNodeValid(self, node_wallet_addr=None):
        # todo coins treshold amount + valid lastMsgBlock
        return True

    class Task():  # (Db, ServiceDb):
        def __init__(self, name="Global"):
            self.name = name
            self.start_time = int(time.time())
            self.verifiedSdbMsqQ = set()
            self.verify_processing = False
            self.delete_processing = False
            self.deleteSdbVerifiedMsqQ = set()
            self.deleteSdbInvalidMsqQ = set()
            self.RUN_SECS = 10  # ToDo config

        def resetTaskQ(self):
            self.verifiedSdbMsqQ = set()

        def isNone(self, var):
            try:
                if var is None:
                    return True
                return False
            except:
                return True