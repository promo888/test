from flask import Flask, render_template, request, send_file, send_from_directory, jsonify
import html
from html import escape, unescape

import os, sys, subprocess, psutil, pkgutil
import msgpack as mp
from msgpack import packb, unpackb
import json
import sqlite3, plyvel #leveldb
import datetime, time, arrow, configparser
import logging
from logging.handlers import RotatingFileHandler
app = Flask(__name__, static_url_path='', template_folder='web')
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
NODE_SERVICE_DB = '%s/../service_db/DATA/service.db' % ROOT_DIR
NODE_DB = '%s/../db/DATA' % ROOT_DIR
NODE_DB_TMP = '%s/../db/DATA/tmp' % ROOT_DIR
WALLETS = '%s/../WALLETS' % ROOT_DIR


class Db():
    def __init__(self, db_path):
        #self.logger = Logger() #Logger('Db')
        self.LEVEL_DB = None
        self.DB_PATH = db_path

    def insertDbKey(self, bin_key, bin_value, db_path=None, override=False, desc=''):
        # print('Insert to DB %s with Closed connection %s, key: %s, value: %s ' % (db_path, DB is None, bin_key, bin_value))
        caller_n = sys._getframe().f_back.f_code.co_name
        try:
            if db_path is None:
                db_path = self.DB_PATH
            if not isinstance(bin_key, bytes):
                bin_key = packb(bin_key)
            if not isinstance(bin_value, bytes):
                bin_value = packb(bin_value)
            if self.LEVEL_DB is None:
                self.LEVEL_DB = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(db_path) #self.DB.DB_PATH
            if self.getDbKey(bin_key, db_path) is None or override:
                self.LEVEL_DB.put(bin_key, bin_value) #Put is not plyvel
                print("%s %s Inserting Key/Value: \nKey: %s \nValue: %s" % (desc, caller_n, unpackb(bin_key), unpackb(bin_value)))
                return True
            else:
                print('%s %s ERROR: Key %s Exist in DB' % (desc, caller_n, bin_key))
                return False
        except Exception as ex:
            # err_msg = '%s %s Exception on insert (key %s) (value %s) to LevelDB NODE_DB: %s %s ' % (
            #     desc, caller_n, bin_key, bin_value, Logger.exc_info(), ex)
            #tools.logger.logp(err_msg, logging.ERROR)
            print('ERROR:', err_msg)
            return None


    def insertDbKeys(self, kv_dict, db_path, override=False):
        try:
            if self.DB.LEVEL_DB is None:
                self.DB.LEVEL_DB = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(db_path) #self.DB.DB_PATH
            with db.write_batch() as wb:
                for k, v in kv_dict.items():
                    wb.put(k, v)
            return True
        except Exception as ex:
            err_msg = 'Exception on insert (key %s) (value %s) to LevelDB NODE_DB: %s %s ' % (
            bin_key, bin_value, Logger.exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)
            return None



    def getDbKey(self, bin_key, db_path=None):
        if db_path is None:
            db_path = self.DB_PATH
        if type(bin_key) is not bytes:
            bin_key = bin_key.encode() ##packb(bin_key)#str(bin_key).encode() #self.b(bin_key)
        try:
            _db = None
            _db_path = self.DB_PATH
            _db = self.LEVEL_DB

            if _db is None:
                _db = plyvel.DB(db_path) #leveldb.LevelDB(_db_path)
            return _db.get(bin_key) ##bytes(_db.get(bin_key)) #bytes(_db.Get(bin_key))
        except Exception as ex:
            print(ex)
            return None



    def deleteDbKey(self, bin_key, db_path):
        try:
            if self.DB.LEVEL_DB is None:
                self.DB.LEVEL_DB = plyvel.DB(db_path) #leveldb.LevelDB(db_path)
                self.DB.LEVEL_DB.delete(bin_key) #Delete(bin_key)
        except Exception as ex:
            err_msg = 'Exception on delete (key %s) from LevelDB NODE_DB: %s %s ' % (
            bin_key, exc_info(), ex)
            self.logger.logp(err_msg, logging.ERROR)


    def isDBvalue(self, bin_key, db_path=None, dbm='db', print_caller=''):
        caller_n = sys._getframe().f_back.f_code.co_name
        if print_caller != '':
            print('Caller: ' + caller_n)
        try:
            if not isinstance(bin_key, bytes):
                bin_key = packb(bin_key)
            if db_path is None:
                _db_path = self.DB_PATH
                dbm = self.LEVEL_DB
            else:
                _db_path = db_path
                dbm = self.LEVEL_DB
            if dbm is None:
                dbm = plyvel.DB(db_path, create_if_missing=True) #leveldb.LevelDB(_db_path)  # Once init held by the process
            value = dbm.get(bin_key) #dbm.Get(bin_key)
            # print('isDBvalue key=%s, \nvalue=%s' % (bin_key, value)
            if value is None or value == b'': # or not isinstance(value, bytes):
                return False
            return True
        except Exception as ex:
            return False


    def getDbRec(self, msg_hash, db_path = None):
        if db_path is None:
            _db_path = self.DB_PATH
        else:
            _db_path = db_path
        try:
            value = self.getDbKey(msg_hash, _db_path) # self.DB.DB_PATH
            if value is not None:
                return value #self.decodeMsg(unpackb(unpackb(value)[0]))
            return None
        except Exception as ex:
            return None


DB = Db(NODE_DB)

@app.route('/dbk', methods=['GET', 'POST'])
def query_leveldb_key():
    key = request.query_string.decode().split("key=")[1] or None #request.args.get('key') #.encode()
    print('key"%s"' % key)
    res = DB.getDbKey(key)
    resp = "Key %s NOT EXIST" % key if res is None else "Key: %s, Value: %s" %(key,unpackb(res))
    return resp

@app.route('/dbq', methods=['GET', 'POST'])
def query_leveldb_range():
    query = request.args.get('query')


@app.route('/sdbk', methods=['GET', 'POST'])
def query_sqlitedb_key():
    table = request.args.get('table')
    key = request.args.get('key')

@app.route('/sdbq', methods=['GET', 'POST'])
def query_sqlitedb():
    query = request.args.get('query')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port='5000', debug=True)
