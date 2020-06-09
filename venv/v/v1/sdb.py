import os, sys
from msgpack import packb, unpackb
import sqlite3

from v1 import logger, config, node, crypto, network, web, \
                 db, transaction, message, block, \
                 contract, ico, exchange, utils


class ServiceDb():

    def __init__(self):
        self.Config = config.Config
        self.logger = logger.Logger() #(log_file='ServiceDb')
        self.ROOT_DIR = self.Config.ROOT_DIR
        self.Utils = utils.Utils()
        self.SERVICE_DB_PATH = self.Config.NODE_SERVICE_DB
        self.DB_PATH = self.Config.NODE_DB_FOLDER
        self.WALLETS_PATH = self.Config.WALLETS_FOLDER
        self.LOGS_PATH = self.Config.LOGS_FOLDER
        #print('NODE_DB, NODE_SERVICE_DB', self.NODE_DB, self.NODE_SERVICE_DB)
        self.createNodeDbIfNotExist()
        self.SERVICE_DB = sqlite3.connect(self.SERVICE_DB_PATH, isolation_level=None, check_same_thread=False)
        self.SERVICE_DB.execute("pragma journal_mode=wal")
        self.createTablesIfNotExist()


    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(ServiceDb, cls).__new__(cls)
        return cls.instance


    def createTablesIfNotExist(self):
        ddl_v1_pending_msg = '''CREATE TABLE  if not exists  v1_pending_msg 
                                (
                                 'signed_msg_hash' TEXT NOT NULL,
                                 'signed_msg'	BLOB NOT NULL,                                 
                                 'pub_key'	BLOB NOT NULL,
                                 'msg_type' BLOB NOT NULL DEFAULT NULL,
                                 'msg_priority' INTEGER DEFAULT 0,
                                 'node_date'	timestamp default current_timestamp,                                 
                                 PRIMARY KEY(signed_msg_hash)                                 
                                );
                             '''
        ddl_v1_verified_msg = '''CREATE TABLE  if not exists  v1_verified_msg 
                                        (
                                         'signed_msg_hash' TEXT NOT NULL,   
                                         'signed_msg'	BLOB NOT NULL,                                      
                                         'verified_msg'	BLOB NOT NULL,                                 
                                         'pub_key'	BLOB NOT NULL,
                                         'msg_type' BLOB NOT NULL DEFAULT NULL,
                                         'msg_priority' INTEGER DEFAULT 0,                                         
                                         'node_date'	timestamp default current_timestamp,                                 
                                         PRIMARY KEY(signed_msg_hash)                                 
                                        );
                                     '''

        ddl_list = [ddl_v1_pending_msg,  ddl_v1_verified_msg] #ddl_v1_pending_blk, ddl_v1_pending_tx]
        con = self.SERVICE_DB
        try:
            with con:
                #cur = con.cursor()
                for ddl in ddl_list:
                    con.execute(ddl)
                con.commit()
        except Exception as ex:
            err_msg = 'Exception ServiceDb.createTablesIfNotExist SqlLite NODE_SERVICE_DB: %s, %s' % (self.logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            raise Exception(err_msg)


    def createNodeDbIfNotExist(self):
        dirs = [self.DB_PATH, self.SERVICE_DB_PATH, self.LOGS_PATH]
        for folder in dirs:
            if not os.path.exists(folder):
                if folder == self.SERVICE_DB_PATH:
                    folder = folder.replace('/service.db', '')
                os.makedirs(folder)


    def getServiceDB(self):
        try:
            if self.SERVICE_DB is None:
                self.SERVICE_DB = sqlite3.connect(self.SERVICE_DB_PATH, isolation_level=None) #TODO ConfigMap
            return self.SERVICE_DB
        except Exception as ex:
            err_msg = 'Exception on get serviceDbConnection to SqlLite NODE_SERVICE_DB: %s, %s' % (self.logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            return None


    def queryServiceDBkv(self, table, signed_msg_hash):
        sql = "select * from %s where signed_msg_hash='%s'" % (table, signed_msg_hash)
        return self.queryServiceDB(sql)


    def queryServiceDB(self, sql):
        try:
            if self.SERVICE_DB is None:
                self.SERVICE_DB = sqlite3.connect(self.SERVICE_DB_PATH, isolation_level=None) #TODO ConfigMap
            return self.SERVICE_DB.execute(sql).fetchall()
        except Exception as ex:
            print("self.SERVICE_DB type", type(self.SERVICE_DB) )
            err_msg = 'Exception: queryServiceDB on query (%s) from SqlLite NODE_SERVICE_DB: , %s' % (sql, ex.__traceback__.tb_lineno)
            #self.logger.logp(err_msg, logging.ERROR)
            self.Utils.printStackTrace(ex, "queryServiceDB")
            return None


    def insertServiceDB(self, sql, *params):
        try:
            if self.SERVICE_DB is None: #todo to think inmemory for cache
                self.SERVICE_DB = sqlite3.connect(self.SERVICE_DB_PATH, isolation_level=None, check_same_thread=False) #TODO ConfigMap

            con = self.SERVICE_DB
            with con:
                #cur = con.cursor()
                con.execute(sql, params[0])
                con.commit()
                return True
        except Exception as ex:
            err_msg = 'Exception ServiceDb.insertServiceDBpendingTX SqlLite NODE_SERVICE_DB: %s, %s' % (
            self.logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            return False


    def persistPendingMsg(self, signed_msg_hash, signed_msg, pub_key, msg_type, msg_priority=0):
        ddl_v1_pending_msg = ''''CREATE TABLE  if not exists  v1_pending_msg 
                                (
                                 'signed_msg_hash' TEXT NOT NULL,
                                 'signed_msg' BLOB UNIQUE NOT NULL,                                 
                                 'pub_key'	BLOB NOT NULL,
                                 'msg_priority' BLOB NOT NULL DEFAULT NULL,
                                 'node_verified'	INTEGER DEFAULT 0,
                                 'node_date'	timestamp default current_timestamp,                                 
                                 PRIMARY KEY(signed_msg_hash)
                                );
                             '''
        msg_priority = msg_priority if msg_priority > 1 else 1
        sql = "INSERT INTO v1_pending_msg (signed_msg_hash, signed_msg, pub_key, msg_type,  msg_priority) values (?,?,?,?,?)"
        print("INSERT INTO v1_pending_msg from %s msg_type: %s with %s priority" % (signed_msg_hash, msg_type, msg_priority))
        con = self.getServiceDB()
        try:
            with con:
                con.execute(sql, [signed_msg_hash, sqlite3.Binary(signed_msg), sqlite3.Binary(pub_key), msg_type, msg_priority])
                con.commit()
        except Exception as ex:
            err_msg = "Exception ServiceDB: \nINSERT INTO v1_pending_msg\n %s\n%s" % (ex, ex.__traceback__.tb_lineno)
            print(err_msg)
            self.logger.logp(err_msg, logging.ERROR)
            return None



    def saveSdbVerifiedMsg(self, signed_msg_hash, signed_msg, verified_msg, pub_key, msg_type, itx_list, msg_priority=0):
        msg_priority = msg_priority if msg_priority > 1 else 1
        ##sql = "INSERT INTO v1_verified_msg (signed_msg_hash, verified_msg, pub_key, msg_type, itx_list, msg_priority) values (?,?,?,?,?,?)"
        sql = "INSERT INTO v1_verified_msg (signed_msg_hash, signed_msg, verified_msg, pub_key, msg_type, msg_priority) values (?,?,?,?,?,?)"
        print("INSERT INTO v1_verified_msg from %s msg_type: %s with %s priority itx_list(%s)" % (type(signed_msg_hash), type(msg_type), type(msg_priority), type(itx_list)))
        con = self.getServiceDB()
        try:
            with con:
                ##con.execute(sql, [signed_msg_hash, sqlite3.Binary(verified_msg), sqlite3.Binary(pub_key), msg_type, sqlite3.Binary(itx_list), msg_priority])
                con.execute(sql, [signed_msg_hash, sqlite3.Binary(signed_msg), sqlite3.Binary(verified_msg), sqlite3.Binary(pub_key), msg_type, msg_priority])
                con.commit()
        except Exception as ex:
            err_msg = "Exception ServiceDB: \nINSERT INTO v1_verified_msg\n %s\n%s" % (ex, ex.__traceback__.tb_lineno)
            print(err_msg)
            #self.logger.logp(err_msg, logging.ERROR)
            return None


    def deleteSdbPendingMsgsIfVerified(self):
        try:
            sql = "delete from v1_pending_msg where signed_msg_hash in (select signed_msg_hash from v1_verified_msg)"
            del_msg_sql = "select signed_msg_hash from v1_pending_msg where signed_msg_hash in (select signed_msg_hash from v1_verified_msg)"
            print("DEBUG: Msgs (pending sdb) to Delete:\n", self.queryServiceDB(del_msg_sql))
            print("deleteSdbPendingMsgsIfVerified: ", sql)
            self.queryServiceDB(sql)
        except Exception as ex:
            err_msg = "Exception deleteSdbPendingMsgsIfVerified: %s \n%s" % (ex, ex.__traceback__.tb_lineno)
            #print(err_msg)
            self.Utils.printStackTrace(ex, "deleteSdbPendingMsgsIfVerified")
            self.Utils.printCaller()

    def deleteSdbVerifiedFromBlockMsgs(self, id_list):
        try:
            sql = "delete from v1_verified_msg where signed_msg_hash in (%s) " % str(",".join(id_list))[1:-1]
            print("deleteSdbVerifiedFromBlockMsgs: ", id_list)
            self.queryServiceDB(sql)
        except Exception as ex:
            #print("Exception deleteSdbVerifiedFromBlockMsgs: %s \n%s" % (ex, ex.__traceback__.tb_lineno) )
            self.Utils.printStackTrace(ex, "deleteSdbVerifiedFromBlockMsgs")

    def deleteSdbInvalidMsgs(self, signed_msgs):
        try:
            if len(signed_msgs) == 0:
                return
            signed_msg_hashes = "(%s)" % str(list(signed_msgs))[1:-1]#str(tuple(signed_msgs))[:-2] # -2 suppress last coma
            sql = "delete from v1_pending_msg where signed_msg_hash in %s" % signed_msg_hashes
            print("deleteSdbInvalidMsgsSql: ", sql)
            self.queryServiceDB(sql)
            #self.Node.TASKS.deleteSdbInvalidMsqQ.remove(msg) for msg in signed_msgs]
        except Exception as ex:
            #print("Exception deleteSdbInvalidMsgs: %s \n%s" % (ex, ex.__traceback__.tb_lineno) )
            self.Utils.printStackTrace(ex, "deleteSdbInvalidMsgs")

    def deleteBlockSdbVerifiedMsgs(self, hash_list):
        try:
            sql = "delete from v1_verified_msg where signed_msg_hash in (%s)" % ",".join(["'%s'" % (hash_id if isinstance(hash_id, str) else hash_id.decode()) for hash_id in hash_list])
            print("deleteBlockSdbVerifiedMsgsSql: %s\n ids: %s" % (sql, hash_list))
            self.queryServiceDB(sql)
        except Exception as ex:
            print("Exception deleteBlockSdbVerifiedMsgs: %s \n%s" % (ex, ex.__traceback__.tb_lineno) )


