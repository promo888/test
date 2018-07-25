import os, sys
import calendar
from datetime import *
from time import *
import configparser
import psutil, subprocess, re
import asyncio

# https://docs.python.org/3/library/configparser.html


# config utils

CONFIG = None


def load_config(path='config.ini'):
    try:
        config = configparser.ConfigParser()
        config.read(path)
        CONFIG = config
        return CONFIG
    except FileNotFoundError:
        raise FileNotFoundError


def get_config_value(section, key, path='config.ini'):
    if CONFIG is None: load_config(path)
    if CONFIG is None:
        raise Exception("No config found")
    else:
        try:
            value = CONFIG[section][key]
            return value
        except Exception:
            raise Exception('[%s][%] is not found in config' % (section, key))


def update_config_value(section, key, value, path='config.ini', update_only_inmem=False):
    """

    should be approved (voted) by nodes quorum
    """

    if CONFIG is None: load_config(path)
    if CONFIG is None:
        raise Exception("No config found")
    else:
        try:
            CONFIG[section][key] = value
            if (not update_only_inmem):
                with open(path, 'w') as configfile:
                    CONFIG.write(configfile)

            print("%s config updated with [%s][%] = %s" % (path, section, key, value))
            return load_config(path)
        except Exception:
            raise Exception('[%s][%] is not found in config %s' % (section, key, path))


def add_config_key_value():  # should be approved by nodes quorum
    pass


def save_config_as_binary():
    pass


def save_config_as_binary():
    pass


def load_config_as_binary():
    pass


def get_config_checksum():
    pass


def killByPort(*ports):
    lines = subprocess.check_output(["netstat", "-ano"], universal_newlines=True)
    rows = []
    pids = []
    for port in ports:
        for line in lines.splitlines()[4:]:
            # print (line)
            c = line.split()
            if port not in c[1]:
                continue
            rows.append(line)
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


def getConfig():
    if CONFIG is None: return load_config()
    else: return CONFIG



def whoIsMaster():
    """

    :return: miner's turn index in config
    """

    # configuration = load_config()
    configuration = getConfig()
    start_time = datetime(2017, 1, 1)  # BlockChain start - TODO change to 2018 real start date
    current_time = datetime.utcnow()
    s = calendar.timegm(start_time.utctimetuple())
    e = calendar.timegm(current_time.utctimetuple())
    ellapsed_sec = (s - e)  # seconds ellapsed since genesis
    miners_amount = len(configuration['nodes'])
    # return (ellapsed_sec % miners_amount)  # miner's index in config
    master_index = (ellapsed_sec // int(configuration['settings']['block_time_sec'])) % miners_amount
    return (configuration['nodes'][list(configuration['nodes'])[master_index]])


def getNode(count, nodes={}):
    configuration = getConfig()
    if len(nodes) == 0: nodes = configuration['nodes']
    if count not in range(0, len(nodes)): return None
    node_key = list(nodes)[count]
    return nodes[node_key]

# log utils
# file utils
# crypto utils
# validation utils
# verification utils
