import sys
from msgpack import packb, unpackb
import plyvel, sqlite3
import logging

#from . import tools
from v.v1 import logger, config

class Db():
    _db_batch =[]

    def __init__(self, db_path=None):
        #self.logger = l.Logger() #('DB')
        self.Config = config.Config
        self.DB_PATH = db_path if not db_path is None else self.Config.NODE_DB_FOLDER
        self._LEVEL_DB = None # plyvel.DB(self.DB_PATH, create_if_missing=True)
        self.connectDb(self.DB_PATH)
        #self._db_batch = []

    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Db, cls).__new__(cls)
        return cls.instance


    def connectDb(self, db_path=None):
        if db_path is None:
            db_path = self.DB_PATH
        if self._LEVEL_DB is None:
            self._LEVEL_DB = plyvel.DB(db_path, create_if_missing=True)

    def insertDbKv(self, bin_key, bin_value, db_path=None, override=False, desc=''):
        # print('Insert to DB %s with Closed connection %s, key: %s, value: %s ' % (db_path, DB is None, bin_key, bin_value))
        caller_n = sys._getframe().f_back.f_code.co_name
        try:
            if db_path is None:
                db_path = config.Config.NODE_DB_FOLDER
            if isinstance(bin_key, str):
                bin_key = bin_key.strip()
                # if len(bin_key) != 33:
                #     raise Exception("Invalid DB key length, 33b expected")
            if not isinstance(bin_key, bytes):
                bin_key = bin_key.encode() #('utf8')
            if isinstance(bin_value, str):
                bin_value = bin_value.strip()
            if not isinstance(bin_value, bytes):
                bin_value = packb(bin_value)
            if self._LEVEL_DB is None:
                self._LEVEL_DB = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(db_path) #self.DB.DB_PATH
            if self.getDbKey(bin_key, db_path) is None or override:
                self._LEVEL_DB.put(bin_key, bin_value) #Put is not plyvel
                ##print("%s %s Inserting Key/Value: \nKey: %s \nValue: %s" % (desc, caller_n, unpackb(bin_key), unpackb(bin_value)))
                # print("%s %s Inserting Key/Value: \nKey: %s \nValue: %s" % (
                # desc, caller_n, bin_key.decode() , unpackb(bin_value))) #)) #
                return True
            else:
                print('%s %s ERROR: Key %s Exist in DB' % (desc, caller_n, bin_key))
                return False
        except Exception as ex:
            err_msg = '%s %s Exception on insert (key %s) (value %s) to LevelDB NODE_DB, ex:%s ' % (
                desc, caller_n, bin_key, bin_value, ex)
            self.logger.logp(err_msg, logging.ERROR)
            print('ERROR:', err_msg)
            return None


    def insertDbBatchFromDict(self, kv_dict, db_path=None, override=False):
        try:
            if db_path is None:
                db_path = self.Config.NODE_DB_FOLDER
            if self._LEVEL_DB is None:
                self._LEVEL_DB = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(db_path) #self.DB.DB_PATH
            with self._LEVEL_DB.write_batch() as wb:
                #print("DB_Batch: ", kv_dict.keys())
                for k, v in kv_dict.items():
                    if isinstance(k, str):
                        k = k.encode()
                    if not isinstance(k, bytes):
                        k = packb(k)
                    if isinstance(v, str):
                        v = v.encode()
                    if not isinstance(v, bytes):
                        v = packb(v)
                    wb.put(k, v)
            return True
        except Exception as ex:
            err_msg = 'Exception on insert to LevelDB NODE_DB:\n (kv_list %s\n) : %s %s ' \
                      % (kv_dict, logger.Logger.exc_info(), ex)
            #self.logger.logp(err_msg, logging.ERROR)
            return False
        finally:
            self.resetDbBatch()


    @staticmethod
    def getDbKey(bin_key, db_path=None):
        if db_path is None:
            db_path = config.Config.NODE_DB_FOLDER
        if isinstance(bin_key, str):
            bin_key = bin_key.encode()
        if type(bin_key) is not bytes:
            bin_key = packb(bin_key)
        try:
            if Db()._LEVEL_DB is None:
                Db()._LEVEL_DB = plyvel.DB(db_path, create_if_missing=True)
            res =  Db()._LEVEL_DB.get(bin_key)
            return res
        except Exception as ex:
            print("Exception getDbKey: db.py line", ex.__traceback__.tb_lineno, ex)
            return None


    def deleteDbKey(self, bin_key, db_path):
        try:
            if self.DB._LEVEL_DB is None:
                self.DB._LEVEL_DB = plyvel.DB(db_path)
                self.DB._LEVEL_DB.delete(bin_key)
        except Exception as ex:
            err_msg = 'Exception on delete (key %s) from LevelDB NODE_DB: %s %s ' % (
            bin_key, exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)


    @staticmethod
    def isDBkey(bin_key, db_path=None, dbm='db', print_caller=''):
        caller_n = sys._getframe().f_back.f_code.co_name
        if print_caller != '':
            print('Caller: ' + caller_n)
        try:
            if isinstance(bin_key, str):
                bin_key = bin_key.encode()
            if not isinstance(bin_key, bytes):
                bin_key = packb(bin_key)
            if db_path is None:
                _db_path = config.Config.NODE_DB_FOLDER
                dbm = Db()._LEVEL_DB
            else:
                _db_path = db_path
                dbm = Db()._LEVEL_DB
            if dbm is None:
                dbm = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(_db_path)  # Once init held by the process
            value = dbm.get(bin_key) #dbm.Get(bin_key)
            #print('isDBkey value key=%s, \nvalue=%s' % (bin_key, value))
            if value is None:
                return False
            return True
        except Exception as ex:
            print("Exception Db isDbValue:", ex.__traceback__.tb_lineno, ex)
            return False


    def getDbRec(self, msg_hash, db_path = None):
        if db_path is None:
            _db_path = self.DB_PATH
        else:
            _db_path = db_path
        try:
            value = self.getDbKey(msg_hash, _db_path)
            if value is not None:
                return value
            return None
        except Exception as ex:
            return None

    @staticmethod
    def getDbBatch():
        return Db._db_batch

    @staticmethod
    def addToBatch(kv):
        Db._db_batch.append(kv)

    @staticmethod
    def addListToBatch(self, kv_list):
        for kv in kv_list:
            Db.addToBatch(kv)

    @staticmethod
    def resetDbBatch():
        Db._db_batch = []


    def writeBatch(self,db_path=None):
        try:
            if db_path is None:
                db_path = self.Config.NODE_DB_FOLDER
            if self._LEVEL_DB is None:
                self._LEVEL_DB = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(db_path) #self.DB.DB_PATH
            with self._LEVEL_DB.write_batch() as wb:
                for kv in Db._db_batch:
                    if isinstance(kv[0], str):
                        kv[0] = kv[0].encode()
                    if not isinstance(kv[0], bytes):
                        kv[0] = packb(kv[0])
                    if isinstance(kv[1], str):
                        kv[1] = kv[1].encode()
                    if not isinstance(kv[1], bytes):
                        kv[1] = packb(kv[1])
                    wb.put(kv[0], kv[1])
            return True
        except Exception as ex:
            err_msg = 'Exception on insertBatch to LevelDB NODE_DB:\n (kv_list %s\n) : %s %s' \
                      % (Db._db_batch,  ex.__traceback__.tb_lineno, ex) #, logger.Logger.exc_info()
            #self.logger.logp(err_msg, logging.ERROR)
            print(err_msg)
            return False#None
        finally:
            Db.resetDbBatch()

