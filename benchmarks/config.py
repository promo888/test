import os
import configparser

config = configparser.ConfigParser()
config['DEFAULT'] = {'ServerAliveInterval': '45',
                     'Compression': 'yes',
                     'CompressionLevel': '9'}

config['bitbucket.org'] = {}
config['bitbucket.org']['User'] = 'hg'
config['topsecret.server.com'] = {}
topsecret = config['topsecret.server.com']
topsecret['Port'] = '50022'     # mutates the parser
topsecret['ForwardX11'] = 'no'  # same here
config['DEFAULT']['ForwardX11'] = 'yes'

def init_config():
    with open('config.ini', 'w') as configfile:
        config.write(configfile)

# print('Config value: ' + config['bitbucket.org']['User'])
#
# with open('config.ini') as configfile:
#     print(config.sections())
#     config['bitbucket.org']['User'] = 'new user'
#
# print('Run-Time value: ' + config['bitbucket.org']['User'])

def get_config(path=os.getcwd() + os.sep + 'config.ini'):
    config = configparser.ConfigParser()
    config.read(path)
    return config


def load_config(path='config.ini'):
    config = configparser.ConfigParser()
    with open(path, 'r') as configfile:
        return config.read(configfile)

# import os
# path2 = os.getcwd() + os.sep + 'config.ini'
# config.read(path2)
# print(config.sections())


def init_dict_config():
    parser = configparser.ConfigParser()

    parser.read_dict({'section1': {'key1': 'value1',
                                     'key2': 'value2',
                                     'key3': 'value3'},
                        'section2': {'keyA': 'valueA',
                                     'keyB': 'valueB',
                                     'keyC': 'valueC'},
                        'section3': {'foo': 'x',
                                     'bar': 'y',
                                     'baz': 'z'}
    })
    print(parser.sections())
    # ['section3', 'section2', 'section1']
    [print(option) for option in parser['section3']]
    # ['baz', 'foo', 'bar']
    parser.write(open('dict.conf', 'w'))


def setInConfigFile(k, v, path=os.getcwd() + os.sep + 'config.ini', section='config'):
    try:
        Config = configparser.ConfigParser()
        Config.read(path)
        Config.set(section, k, v)
    except configparser.NoSectionError:
        Config.add_section(section)
        Config.set(section, k, v)

    try:
        cfgfile = open(path, 'w')
        Config.write(cfgfile)
        cfgfile.close()
    except:
        return False

    return True



def getFromConfigFile(k, path=os.getcwd() + os.sep + 'config.ini', section='config'):
    value = None
    try:
        Config = configparser.ConfigParser()
        Config.read(path)
        value = Config[section][k]
    except:
        value = None

    return value

if __name__ == "__main__":
     import sys
     #load_config(sys.argv[1])
     #init_dict_config()
     c = load_config()
     print(c)

     c2 = get_config()
     print(c2.sections())

     setInConfigFile('k', 'v', section='NEW')
     print(getFromConfigFile('k', section='NEW'))
     print(getFromConfigFile('k'))

    # print(os.getcwd())
    # f = open('config.ini').read()
    # print(config.sections())
    # #print(f)

