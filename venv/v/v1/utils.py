import os, sys, time, arrow, subprocess
from Crypto.Hash import SHA256, HMAC
from msgpack import packb, unpackb
from v1 import logger, config, node, crypto, network, web, \
                 sdb, db, wallets, transaction, message, block, \
                 contract, ico, exchange


class Utils():

    # def __init__(self):
    #     self.Config = config.Config()
    #     self.Db = db.Db()

    # config = c.Config()
    # db = db.Db()

    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Utils, cls).__new__(cls)
        return cls.instance

    @staticmethod
    def deleteDir(path):
        """deletes the path entirely"""
        if sys.platform == "win32":
            cmd = "RMDIR " + path + " /s /q"
        else:
            cmd = "rm -rf " + path
        result = os.system(cmd)
        print('res: %s cmd: %s' % (result, cmd))

    @staticmethod
    def printCaller():
        import inspect
        curframe = inspect.currentframe()
        calframe = inspect.getouterframes(curframe, 2)
        print('Caller name: ', calframe[1][3])
        print('Caller name: ', inspect.stack()[1][3])

    @staticmethod
    def getCaller():
        return sys._getframe().f_back.f_code.co_name

    @staticmethod
    def resetDb():
        Utils.deleteDir(config.Config.NODE_DB_FOLDER)

    @staticmethod
    def resetNode():
        Utils.deleteDir(config.Config.NODE_DB_FOLDER)
        Utils.deleteDir(config.Config.NODE_SERVICE_DB_FOLDER)
        Utils.deleteDir(config.Config.LOGS_FOLDER)
        Utils.deleteDir(config.Config.WALLETS_FOLDER)
        Utils.mkdir(config.Config.WALLETS_FOLDER) #todo remove test


    @staticmethod
    def mkdir(dir):
        if not os.path.exists(dir):
            os.makedirs(dir)

    @staticmethod
    def utc_timestamp(self):
        return arrow.utcnow().timestamp

    @staticmethod
    def utc_timestamp_b():
        return str(arrow.utcnow().timestamp).encode('utf-8')

    @staticmethod
    def utc():
        # return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')
        # datetime.datetime.timestamp(datetime.datetime.now())
        return str(arrow.get(Utils.utc_timestamp()))

    @staticmethod
    def printStackTrace(ex, label=None):
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback_details = {
            'filename': exc_traceback.tb_frame.f_code.co_filename,
            'lineno': exc_traceback.tb_lineno,
            'name': exc_traceback.tb_frame.f_code.co_name,
            'type': exc_type.__name__,
            'message': exc_value #.message,  # or see traceback._some_str()
        }
        print('ErrorLine: ', ("Exception " +label+ ":\n" if not label is None else ""),
              traceback_details["filename"], traceback_details["lineno"], traceback_details["message"])

    @staticmethod
    def b(str):
        try:
            return bytes(str, 'utf8')
        except:
            return None

    @staticmethod
    def s(o):
        try:
            return str(o, 'utf8')
        except:
            return None

    @staticmethod
    def dec(b):
        try:
            try:
                v = b.decode()  # is str
            except:
                # TODO to continue
                return self.bdecimal2str(b)  # DoublePacked number

            return v
        except:
            return b


    @staticmethod
    def isStrNumber(str):
        try:
            Decimal(str)
            return True
        except:
            return False

    @staticmethod
    def dec2b(dec):
        return str(dec).encode()

    @staticmethod
    def strdecimal2bytes(str_decimal):
        if not isinstance(str_decimal, str):
            return None
        if len(str_decimal) > 21:  # ToDo fromConfig->updateHome -> n9.n8 100m MaxTx(9)-??? 4now 100b(12)
            return None
        if "." in str_decimal:
            nums = str_decimal.split(".")
            int_num = nums[0]
            float_num = nums[1]
            if not self.isStrNumber(int_num) or not self.isStrNumber(float_num):
                return None
            if len(int_num) > 9 or len(float_num) > 8:  # ToDo config = 4b.4b
                return None
            return int(int_num).to_bytes(4, byteorder='big') + int(float_num).to_bytes(4, byteorder='big')
        else:
            int_num = str_decimal
            if not self.isStrNumber(int_num):
                return None
            if len(int_num) > 9:  # ToDo config = 4b
                return None
            return int(int_num).to_bytes(4, byteorder='big')

    @staticmethod
    def bdecimal2str(b_decimal):
        if not isinstance(b_decimal, bytes):
            return None
        else:
            if len(b_decimal) > 4:  # is float
                int_num = str(int.from_bytes(b_decimal[:4], 'big'))
                float_num = str(int.from_bytes(b_decimal[4:], 'big'))
                if int_num is None or not Utils.isStrNumber(int_num) or not Utils.isStrNumber(float_num):
                    return None
                if float_num is not None:
                    return str(Decimal(int_num + '.' + float_num))
                else:
                    return str(Decimal(int_num))  # point . exist without an exp
            else:
                int_num = str(int.from_bytes(b_decimal[:4], 'big'))  # is int
                if not self.isStrNumber(int_num):
                    return None
                if len(int_num) > 9:  # ToDo config = 4b
                    return None
                return str(Decimal(int_num))

    @staticmethod
    def p(s):
        print(s)

    @staticmethod
    def pp(s):
        print(s)

    @staticmethod
    def isVersionCompatible(msg):
       try:
           return int(unpackb(msg)[0]) <= int(config.Config.VERSION)
       except:
           return False

##
    @staticmethod
    def to_HMAC(bytes_msg):
        '''Return HMAC hash from bytes'''
        try:
            if isinstance(bytes_msg, str):
                bytes_msg = bytes_msg.encode()
            if not isinstance(bytes_msg, bytes):
                bytes_msg = packb(bytes_msg)
            return HMAC.new(bytes_msg).hexdigest()
        except:
            return None

    @staticmethod
    def getWalletAddr(pubk_bytes):
        try:
            pub_addr = config.Config.MsgType.WALLET.decode() + HMAC.new(pubk_bytes).hexdigest()
            return pub_addr
        except:
            return None

    @staticmethod
    def isDbWalletExist(bin_msg):
        try:
            pk = unpackb(bin_msg)[1]
            if not db.Db.isDBkey(crypto.Crypto.to_HMAC(pk)):
                return False
            else:
                return True
        except:
            return False

    @staticmethod
    def isMsgValid(bin_msg): #todo escape bySizeOf "\" injection
        if len(bin_msg) > config.Config.MAX_MSG_SIZE_BYTES:
            return False
        try:
            pk = bin_msg[-32:]#unpackb(bin_msg)[1] #validate correct packaging
            wlt = crypto.Crypto.getWalletAddr(pk)
            return db.Db.getDbKey(wlt)
        except:
            print('utils.py isMsgValid ERROR: Failed to unpack Public/Verifying Key')
            return False

    @staticmethod
    def validateBlock(self, block_msg):
        #print('ValidateBlock...')
        try:
            if len(block_msg) > self.Config.MsgType.BLOCK_MSG_MAX_SIZE:
                return False
            if not self.isVersionCompatible(block_msg):
                return False
            if not block_msg[1] is self.Config.MsgType.BLOCK_MSG:
                return False
            block_umsg = block_msg
            if isinstance(block_umsg, bytes):
                block_umsg = unpackb(block_msg)
            if not block_umsg[1].encode() is self.Config.MsgType.BLOCK_MSG:
                return False
            if type(self) is Tools:
                block_msg_fields = self.Block.BLOCK_MSG_FIELD_TYPE  # TODO getMsgFields(msgType) + msgLimit
                block_msg_fields_index = self.Block.BLOCK_MSG_FIELD_INDEX
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

    @staticmethod
    def diff(first, second):
        try:
            if not isinstance(first, list):
                first = list(first)
            if not isinstance(second, list):
                second = list(second)
            second = set(second)
            return {"-": [item for item in first if item not in second], \
                    "+": [item for item in second if item not in first]}
        except:
            return "Error in compare"


    @staticmethod
    def decodev(v):
        try:
            return unpackb(v)
        except:
            try:
                return v.decode()
            except:
                return None

    @staticmethod
    def unpackv(v):
        if isinstance(v, bytes):
            return Utils.decodev(v)
        elif isinstance(v, str):
            return v
        elif isinstance(v, tuple):
            v = list(v)
        elif isinstance(v, list):
            return [Utils.decodev(vv) for vv in v]
        return None



##

    # class Task():  # (Db, ServiceDb):
    #     def __init__(self, name="Global"):
    #         self.name = name
    #         self.start_time = int(time.time())
    #         self.verifiedSdbMsqQ = set()
    #         self.verify_processing = False
    #         self.delete_processing = False
    #         self.deleteSdbVerifiedMsqQ = set()
    #         self.deleteSdbInvalidMsqQ = set()
    #         self.RUN_SECS = 10  # ToDo config
    #
    #     def resetTaskQ(self):
    #         self.verifiedSdbMsqQ = set()
    #
    #     def isNone(self, var):
    #         try:
    #             if var is None:
    #                 return True
    #             return False
    #         except:
    #             return True



