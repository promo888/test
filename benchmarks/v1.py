#Ok10git

# import os, sys, time
# from Crypto.PublicKey import RSA
# from Crypto.Signature import PKCS1_v1_5
# from Crypto.Hash import SHA256
import datetime, time
from fastecdsa import curve, ecdsa, keys
from fastecdsa.keys import export_key, import_key
from fastecdsa.curve import P256
from fastecdsa.point import Point
import leveldb


# Validations
def isTSvalid(tx): #TODO not more than current time
    pass

def areTxFieldsExist(tx):
    pass

def verifyTxSignature(tx):
    pass

def verifyTxChecksum(tx):
    pass

def isTxInDB(tx):
    pass

def areInputTxsHasOutputTxs(tx):
    pass

def txOutputsAreValid(tx):
    pass

def isTxFee(tx):
    pass

# Actions
def isValidTx(tx):
    return areTxFieldsExist(tx) and isTSvalid(tx) and verifyTxSignature(tx) and verifyTxChecksum(tx) and not isTxInDB(tx) \
           and areInputTxsHasOutputTxs(tx) and txOutputsAreValid(tx) and isTxFee(tx)

def appendFromWalletAddrToTx(tx): #TODO in TX
    pass


def appendMasterTimeToTx(tx):
    pass


def syncNodeTime(): #TODO at node start, redundant ?
    pass

def diffTimeSyncWithMasterNode(): #suppress latency
    pass

def isBlockTime():
    pass

def isDispatchTime():
    if getConfig('EllapsedSecsFromBlockStart') >= getEllapsedTimefromLastBlock and getEllapsedTimefromLastBlock <= getConfig('BlockSubmitSecs'):
    pass

def submitMasterBlock():
    pass

def amImaster():
    pass

def formatTXasMaster(tx):
    # remove Client's DateTime field -> could be erroneous/not in sync #TODO Nonce field
    #distributeTx(tx)
    if amImaster() and (isBlockTime() or isDispatchTime())  and not isDispatched(tx):
        submitMasterBlock()
    elif amImaster() and not isBlockTime() and getEllapsedSecsFromLastBlock() < getConfig('BlockSubmitSecs') and not isDispatched(tx):
        dispatchToNodes() #txs array
    elif not amImaster() and getEllapsedSecsFromLastBlock() < getConfig('BlockSubmitSecs') and not isDispatched(tx):
        dispatch2Master()
    pass


#TODO Batch Insert if NOT Exist and NOT inserted remainder to pending Q until retrieved
#TODO ??? BLOCK's hash is calculated from TXs LIST hashes (rehashed by master in order to prevent chained hash calculation from the block)
#TODO calc BLOCK_TX_HASH = sum[tx_msg hash + tx['server_time'] hash]

def savePendingTxsInQDB(tx_list): #redundant ?
    for tx in tx_list:
        if isValidTx(tx):
            new_tx = formatTXasMaster(tx)
            #save new_tx as pending and distribute
    pass

def getPendingTxsFromQDB(): #redundant ? #TODO Limit tx_list to BLOCK_TX_AMOUNT
    pass

def removePendingTxsFromQDB(tx_list): #redundant ?
    pass

def distributeTx(new_tx):
    #if not amImaster() -> distribute to Master else append to txArray for subscribers by [tx_submit_amount or by pub_timeout]
    if amImaster():
        new_tx = appendMasterTimeToTx(tx)
        pass #insert to subscription Q
    else:
        pass #distribute to Master Node
    pass

def saveTxInDB(tx):
    pass

def saveTxListInDB(tx_list):
    #save tx_list with a batch IF NOT EXIST -> to avoid duplicates
    approved_tx_list = getTxsFromDB(tx_list)
    pending_txs = [p for p in approved_tx_list if p not in approved_tx_list]
    for tx in pending_txs:
        #save in DB
        #remove from QDB
    pass

def getTxsFromDB(tx_list):
    #get TX's list from DB
    pass


def getBlockInfo(block="LAST")
    #blockN, blockHash, txsList
    pass

def isLastBlockInSync():
    pass

def resubmitTxsIfNotInBlock(block):
    #if last block time/number in Sync else get missing blocks/txs
    pending_tx_list = getPendingTxsFromQDB()
    approved_tx_list = getTxsFromDB(pending_tx_list)
    pending_txs = [p for p in pending_tx_list if p not in approved_tx_list]
    approved_txs = [p for p in pending_tx_list if p in approved_tx_list]
    removePendingTxsFromQDB(approved_txs) #TODO if downloading block , how to avoid retranmission of pending txs

    pass

def saveBlockInDB(block):
    #save block
    #save txs (persist from pending)
    #remove txs from pending Q
    #resubmit pending txs to new master if not in db #TODO how to avoid pending transmission from the multiple nodes
    pass


def getLastBlockID():
    pass

def getBlock(block_id): #Limit for 1 block per node distribution, with timeout of 10s
    #get block from Nodes
    pass


def appendNotRetrievedTXsToPendingForDownloadQDB(tx_list): #TODO onStart + Task Scheduler
    pass


def removeRetrievedTXsFromPendingForDownloadQDB(tx_list):
    pass


RETRIEVING_TXS = False
def getMissingTXs(tx_list):
    if not RETRIEVING_TXS:
        RETRIEVING_TXS = True
        last_block_id = getLastBlockID()
        retrieved_tx_list = getTxsFromDB(tx_list)
        #save tx_list in file or QDB for TaskScheduler retrieve
        saveTxListInDB(tx_list)
    else:
        RETRIEVING_TXS = False
    pass


RETRIEVING_BLOCKS = False
def getMissingBlocks():
    if not isLastBlockInSync() and not RETRIEVING_BLOCKS:
        RETRIEVING_BLOCKS = True
        last_block_id = getLastBlockID()
        block_msg = getBlock(last_block_id+1)
        if not getBlock(block_msg['msg_hash']):
            missing_tx_list = block_msg['txs'].keys()
            getMissingTXs(missing_tx_list)
            #Save block after its TXs downloaded
            saveBlockInDB(block_msg) #TODO error handler
    else:
        RETRIEVING_BLOCKS = False
    pass


##############################################################################
#3CHAR MSG IDENTIFIER
SINGLE_SIG_MSG = "STX"
#MULTI_SIG_MSG = "MTX"
TX_MSG = '_TX'
BLOCK_MSG = "BLK"
VOTE_MSG = "VOT"
SERVICE_TX = "SRV"

Q = {}
T_Q = {} #temp Q for matching and removing TXs in blocks
last_relay_time = None
last_relay_amount = None


def getConfigValue(key):
    pass

def validateTX(tx):
    #validate inputs/outputs are valid
    # update T_Q[tx['msg_hash']['tx']] = tx for a valid TX and remove if exist in BLOCK else resubmit in next block
    # update T_Q[tx['msg_hash']['utx']] = tx_hash for unspent outputs
    pass


def insertGenesis():
    GENESIS_MSG('1', 'TX', '9d25675fde074d1444439ef431848bd8b5314b268fd8edbe4e2a59d0700d6da2', ('1/1',
                                                                                                '[36406343224692063900833029031111854117178867930743205589528043357636889016454 6504559082621797771456835002966813839522833454231390100388342046748949207233]',
                                                                                                '[GENESIS]',
                                                                                                '[26063413541153741795311009536578546636609555338262636333004632681873009397378 72849517704928537413839627784171110912318787674252857837896776821469476844155]',
                                                                                                '19773ac41f111ea4ad5ef20ff1273aa0739f15661dafa3b4787961fd84bfb369',
                                                                                                '1', 10000000000,
                                                                                                '01-01-2018 00:00:00.000'))

    GENESIS_HASH = 'e2459cf1ea4f8245ef1b6985e8a83c6e946347c7a07ed8708d52c3481787ed47'


def v1(msg):
    #TODo replace by a GENESIS_HASH if len(DB_TXs == 0) -> on startNode
    # v1_genesis_fields
    # msg_fields_tx = (
    # 'ver_num', 'msg_type', 'msg_hash', 'msg', 'sig_type', 'sigs', 'input_txs', 'pub_key', 'to_addr', 'asset_type',
    # 'amount', 'ts')  # order & fields are handled by ver_num
    # # genesis_tx = ('1', '_TX', '1/1', '[%s %s]' % (r, s), ' [GENESIS]', 'GENESIS', to_sha256(pbk1), '1', 10000000000, merkle_date)
    # genesis_tx = (
    # '1', '_TX', '1/1', '[%s %s]' % (r, s), '[GENESIS]', '[%s %s]' % (pbk1.x, pbk.y), to_sha256(str(pbk1)), '1',
    # 10000000000, merkle_date)  # from_addre sha256(pubkey)

    pass

def validateMsgByVersion(func, msg)
    return func(msg)

def validateMsgByType(msg)
    #validate fields, format, ...etc
    #if tx -> validate TX
    res = False
    res = validateMsgByVersion('v' + msg[0], msg)
    return res

def isPersistBatchRule():
    batch_amount = getConfigValue('q_batch_amount')
    if len(Q) >= batch_amount:
        return True
    else:
        return False

def getHash(msg):
    pass

def removeMsgFromPendingQ(msg):
    #del Q[msg['msg_hash']]
    pass

def persistBatchToDB():
    batch_amount = getConfigValue('q_batch_amount')
    last_relay_time = time.time()
    last_relay_amount = batch_amount if len(Q) >= batch_amount else len(Q)
    #TODO persist batch
    pass

def appendMsgToPendingQ(msg):
    Q[msg['msg_hash']].append(msg)
    pass

def isRelayRule():
    relay_period = getConfigValue('q_batch_relay_secs')
    to_relay = False
    if time.time() - last_relay_time >= relay_period:
        to_relay = True


def removeBatchFromPendingQ():
    count = 0
    for e in Q:
        del e
        count += 1
        if count == last_relay_amount:
            break
    pass


def relay(ip_list, msg_list, msg_type):
    #removeBatchFromPendingQ(msg_list, msg_type)
    pass

def getNext3ValidNodesFromTheLastBlock():
    pass

def relayToNodes():
    pass

def relayToMaster():
    pass

def getDB(k):
    pass


def verifyTX(tx):
    #if not exist in DB
    #remove from DB(Q) if False, preserve in DB if True
    #return True or False
    pass


def verifyBlockTxs(block):
    declined_txs = []
    for m in block['tx_list']:
        tx = m['msg']
        verifiedTx = verifyTx(tx)
        if not verifiedTx:
            declined_txs.append(tx)
    if len(declined_txs) > 0:
        return False
    else:
        return True


def vote2Master(master_ip, block_hash, true_or_false):
    pass


def voteBlock(block):
    #vote(block['MASTER_IP'], True|False)
    approved_block = verifyBlockTxs(block)
    pass


def onNewMessage(msg):
    if msg['msg']['msg_type'] == BLOCK_MSG and not amImaster():
        missing_txs = []
        for m in msg['tx_list']:
            tx = m['tx_hash']
            if not getDB(tx) is None and not Q[tx] is None:
                #TX not exist - DON'T VOTE and get transaction - if still same master then vote
                missing_txs.append(tx)
        if len(missing_txs) > 0:
            getMissingTXs(missing_txs)
            #TODO
            #if current_time < next_master_end (previous votes being submitted)
            #    if len(declined_txs) == 0:
            #         voteBlock(msg)
        else:
            voteBlock(msg)
    elif msg['msg']['msg_type'] == VOTE_MSG:
            #TODO time < whoIsPrevMaster() nextToPrevTime -> append+relay service block msg
            pass
    else:
        if msg['msg']['msg_type'] == TX_MSG:
            if not validateMsgByType(msg): #Impose DB check - or not getDB(msg['msg_hash']) is None: # and msg['msg']['msg_type'] is not BLOCK_MSG  and msg['msg']['msg_type'] is not VOTE_MSG:
                #Not valid or duplicate
                return
            else:
                appendMsgToPendingQ(msg)
                if isPersistBatchRule():
                    persistBatchToDB() #TODO task scheduler
                if amImaster():
                    if isRelayRule():
                        relayToNodes() #TODO task scheduler
                else:
                    relayToMaster()
                removeBatchFromPendingQ() #BUT persist valid txs - Q is only 4 dispatch
    # AutoClean Q Pending DBs once a week



def onNodeStart():
    #Sync time
    #Sync chain DB (last block related data (txs,utxo,service...etc + resubmit pending TXs)
    #Sync penalties
    #Match persisted pending DBQ vs DB -> remove duplicates (msghash keys from db)
    #Start UDP server for incoming msgs from Nodes
    #Start WebSocketServer for serving WWW requests

    pass