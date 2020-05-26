import os

class Config():
    #system #todo read props from file ? bytes or str props_decoder?
    VERSION = b'1'
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    NODE_SERVICE_DB_FOLDER = '%s/../../service_db/DATA' % ROOT_DIR
    NODE_SERVICE_DB = '%s/service.db' % NODE_SERVICE_DB_FOLDER
    NODE_DB_FOLDER = '%s/../../db/DATA' % ROOT_DIR
    NODE_DB_TMP = '%s/../../db/DATA/tmp' % ROOT_DIR
    LOGS_FOLDER = '%s/../../logs' % ROOT_DIR
    WALLETS_FOLDER = '%s/../../wallets' % ROOT_DIR
    TASK_VERIFY_SDB_INTERVAL_SECS   = 10
    TASK_DELETE_SDB_INTERVAL_SECS   = 10
    MAIN_COIN                       = b'FxCash'
    MAIN_COIN_SUPPLY                = 128000000000
    MAX_MSG_SIZE_BYTES              = 32768
    PTX_TX_LIMIT                    = 100
    TX_FEE                          = 0.001 #todo ptx or ctx fee ???
    BLOCK_MSG_LIMIT                 = 1000
    BLOCK_MSG_MAX_SIZE              = 300000  # bytes
    MINER_FEE                       = 0.001
    NEW_ASSET_FEE                   = 1000
    BLOCK_REWARDS                   = 1000
    REWARDS_HALVING_PERCENT         = 50
    REWARDS_HALVING_BLOCKS          = [ 1000000, 10000000] #todo
    MSG_MAX_SIZE                    = 100000
    PORT_REP                        = 7777  # Receiving data from the world TXs, queries ...etc
    PORT_UDP                        = 8888  # Submitting/Requesting data from the miners
    PORT_PUB                        = 9999  # Publish to Miners fanout
    PORT_PUB_SERVER                 = 5555  # Optional fanout
    PORT_SUB_CLIENT                 = 6666  # Optional subscribe


    class MsgType():
        VERSION                 = b'1'
        UNSPENT_TX              = b'+'
        SPENT_TX                = b'-'
        PARENT_TX_MSG           = b'*'
        PARENT_TX_MSG_MAX_SIZE  = 1024
        SPEND_MULTI_SIG_TX      = b'\x03'
        MINER_FEE_TX            = b'\x04'
        MINER_ISSUE_TX          = b'\x05'
        BLOCK_MSG               = b'B'
        VOTE_MSG                = b'V'
        CONTRACT_TX             = b'C'
        CONTRACT_CONFIRM_TX     = b'T'
        CONTRACT_MSG            = b'D'
        REGISTER_TX             = b'\xe1'
        EXCHANGE_TX             = b'E'
        ICO_TX                  = b'I'
        AGENT_TX                = b'A'
        INVOKE_TX               = b'\xd1'
        RELAY_TX                = b'R'
        MSG_MSG                 = b'M'
        WALLET                  = b"W"

