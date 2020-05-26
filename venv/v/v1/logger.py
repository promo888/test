import os, logging
from logging.handlers import RotatingFileHandler
from . import config as C
import datetime, time

class Logger():

    def __init__(self, log_file='Node', config=C):
        self.config = C.Config
        self.log_file = None
        self.Logger = None
        self.getLogger(log_file)

    def __new__(cls): #singleton
        if not hasattr(cls, 'instance'):
            cls.instance = super(Logger, cls).__new__(cls)
        return cls.instance

    def create_rotating_log(self, path, label="Rotating Log"):
        self.logger = logging.getLogger(label)
        self.logger.setLevel(logging.INFO)

        #create file if not exist
        directory = os.path.dirname(path)
        if not os.path.exists(directory):
            os.makedirs(directory)
        if not os.path.exists(path):
            with open(path, 'w'): pass

        # add a rotating handler
        self.handler = RotatingFileHandler(path, maxBytes=10000000, backupCount=10000)
        self.logger.addHandler(self.handler)
        return self.logger

    def setup_logger(self, logger_name, log_file, level=logging.INFO):
        self.log_setup = logging.getLogger(logger_name)
        self.formatter = logging.Formatter('%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
        self.fileHandler = logging.FileHandler(log_file, mode='a')
        self.fileHandler.setFormatter(formatter)
        self.streamHandler = logging.StreamHandler()
        self.streamHandler.setFormatter(formatter)
        self.log_setup.setLevel(level)
        self.log_setup.addHandler(fileHandler)
        self.log_setup.addHandler(streamHandler)

    def logger(self, msg, level, logfile=None):
        #self.logfile = logfile if not logfile is None else self.logfile
        if self.level == 'info': self.log.info(msg)
        if self.level == 'warning': self.log.warning(msg)
        if self.level == 'error': self.log.error(msg)

    def utc():
        return datetime.datetime.utcfromtimestamp(time.time()).strftime('%d-%m-%Y %H:%M:%S.%f')

    def exc_info():
        exc_type, exc_value, exc_tb = sys.exc_info()
        return '%s %s' % (os.path.basename(exc_tb.tb_frame.f_code.co_filename), exc_tb.tb_lineno)

    def getLogger(self, logFile='Node'):
        if self.Logger is None:
            self.log_file = "%s/%s.log" % (self.config.LOGS_FOLDER, logFile)
            self.Logger = self.create_rotating_log(self.log_file, "logger")
        return self.Logger

    def logp(self, msg, mode, console=True):
        msg = '%s %s' % (Logger.utc(), msg)
        if mode == logging.ERROR:
            self.getLogger().error(msg)
        elif mode == logging.WARNING:
            self.getLogger().warning(msg)
        else:
            self.getLogger().info(msg)
        if console:
            print(msg)