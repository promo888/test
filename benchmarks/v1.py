import os, sys, time
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

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

def submitMasterBlock():
    pass

def amImaster():
    pass

def formatTXasMaster(tx):
    # remove Client's DateTime field -> could be erroneous/not in sync #TODO Nonce field
    distributeTx(tx)
    if isBlockTime():
        submitMasterBlock()
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

