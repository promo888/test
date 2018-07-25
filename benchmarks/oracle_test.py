import sys, os, traceback, time, datetime
import cx_Oracle
import  pymongo
import asyncio
import pytest
from pprint import pprint
import paramiko
import re
from scp import SCPClient
from paramiko import SSHClient
import shutil
import psutil
from py.xml import html

def getFolderSize(folder):
    total_size = os.path.getsize(folder)
    try:
        for item in os.listdir(folder):
            itempath = os.path.join(folder, item)
            if os.path.isfile(itempath):
                size = os.stat(itempath).st_size # os.path.getsize(itempath)
                if not size is None: total_size += size
                else: return None
            elif os.path.isdir(itempath):
                size = getFolderSize(itempath)
                if not size is None: total_size += size
                else: return None
    except Exception as exc:
        print('%s: %s' % (folder, exc))
        return None
    return total_size / 1024 / 1024 #mb

#print("Size: " + str(getFolderSize(".")))
# print(os.stat('c:%sAnaconda2' % os.sep).st_size)
# start = time.time()
# print(getFolderSize('c:%sAnaconda2' % os.sep), ' Gb in c:\Anaconda2')
# duration = time.time() - start
# print('Duration: %s sec' % duration)
# #sys.exit(0)
#
# start_path = 'c:%s' % (os.sep)
# filter_size_mb = 10000
# for (dir, subdirs, files) in os.walk(start_path): # os.curdir, followlinks=False):
#     for folder in subdirs:
#         total_size = getFolderSize(os.path.join(dir, folder))
#         if not total_size is None and total_size > filter_size_mb: print('%s %s Mb' % (os.path.abspath(folder), total_size))
# sys.exit(0)

#https://stackoverflow.com/questions/1392413/calculating-a-directorys-size-using-python
#sum([sum(map(lambda fname: os.path.getsize(os.path.join(directory, fname)), files)) for directory, folders, files in os.walk(start_path)])
#fp = os.path.join(dirpath, file) total_size += os.stat(fp).st_size
#import commands
#size = commands.getoutput('du -sh /path/').split()[0] commands.getstatusoutput

#exc_info = sys.exc_info()
#traceback.print_tb(exc_info[2])
# print(os.environ)
# db = cx_Oracle.connect('FR1', 'fr1', '10.20.42.50:1521/PTDB.am.icap.com')
# print(db.version)
#
# cursor = db.cursor()
# cursor.execute('SELECT * FROM fx_order_event')
# # pprint(cursor.fetchall())
#
# limit = 10
# count = 0
# for row in cursor: ## notice that this is plain English!
#     print(row)
#     count += 1
#     if count >= limit: break
#
# cursor.close()
# db.close()

class Oracle:
    def __init__(self, user, pwd, ip, port, service):
        self.user = user
        self.pwd = pwd
        self.ip = ip
        self.port = port
        self.service = service
        self.connected = None
        self.conn = None
        self.cursor = None


    def connect(self):
        is_connected = False
        try:
            host_port_service =  '{}:{}/{}'.format(self.ip, self.port, self.service)
            self.conn = cx_Oracle.connect(self.user.upper(), self.pwd.lower(), host_port_service)
            print(self.conn.version)
            self.cursor = self.conn.cursor()
            is_connected = True
            self.connected = True
        except Exception as e:
            #raise ("Failed to connect")
            exc_info = sys.exc_info()
            print(exc_info)
            traceback.print_tb(exc_info[2])
            is_connected = False
        return is_connected


    def nulify(self):
        self.conn = None
        self.cursor = None
        self.connected = None


    def closeConnection(self):
        try:
            if not self.cursor is None: self.cursor.close()
            if not self.conn is None: self.conn.close()
        except:
            pass
        self.nulify()
        self.cursor = None
        self.conn = None


    def query(self, sql, close_connection=True):
        res = None
        outcome = []
        if self.conn is None or self.connected is None:
            is_connected = self.connect()
        if self.connected is None or not self.connected:
            print("Failed to connect")
            return None
        res = self.cursor.execute(sql)
        if res is None:
            if close_connection:
                self.closeConnection()
            return None

        for row in res:
            _row = row
            _l = list(_row)
            for field in _l:
                if 'lob' in str(type(field)).lower(): _l[_l.index(field)] = "LOB"
                if 'datetime' in str(type(field)).lower(): _l[_l.index(field)] = str(_l[_l.index(field)])
            outcome += _l
            #outcome += list(row) #row
        if close_connection:
            self.closeConnection()
        return outcome


    def commit(self):
        pass


#'lob' in str(type(row[9])).lower()
#'datetime' in str(type(row[9])).lower() str(row[12])

ora = Oracle('FR1', 'fr1', '10.20.42.50', '1521', 'PTDB.am.icap.com')
# res = ora.query("select count(*) from SCHEMA_VERSION")
# print(res)
res = ora.query("select * from SCHEMA_VERSION", False)
print(res)
res = ora.query("select * from fr_audit_in")
print(res)

#https://gist.github.com/mlafeldt/841944
#https://stackoverflow.com/questions/35821184/implement-an-interactive-shell-over-ssh-in-python-using-paramiko
#https://daanlenaerts.com/blog/2016/01/02/python-and-ssh-sending-commands-over-ssh-using-paramiko/
#https://stackoverflow.com/questions/3562403/how-can-you-get-the-ssh-return-code-using-paramiko


host = "10.20.42.88"
user = "root"
pwd = '123456'
port = 22

# try:
#     t = paramiko.Transport((hostname, port))
#     t.connect(username=username, password=password)
#     sftp = paramiko.SFTPClient.from_transport(t)
#     sftp.get(source, dest)
#
# finally:
#     t.close()

#https://docs.pytest.org/en/latest/example/
#https://stackoverflow.com/questions/68335/how-to-copy-a-file-to-a-remote-server-in-python-using-scp-or-ssh
#https://medium.com/@keagileageek/paramiko-how-to-ssh-and-file-transfers-with-python-75766179de73
class SSH:
    def __init__(self, host, port, user, pwd):
        self.host = host
        self.port = port
        self.user = user
        self.pwd = pwd
        self.client = paramiko.SSHClient()
        try:
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
            self.client.connect(hostname=self.host, port=self.port, username=user, password=self.pwd)
        except Exception as exc:
            print("Failed to init connection at %s:%s with %s/%s" % (host, port, user, pwd))
        finally:
            pass

    def exe(self, cmd, close_connection=True):
        self.ret_code = None
        self.ret_text = None
        try:
            # self.client.load_system_host_keys()
            # self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy)
            # self.client.connect(hostname=self.host, port=self.port, username=user, password=self.pwd)
            stdin, stdout, stderr = self.client.exec_command(cmd)
            self.ret_code = stdout.channel.recv_exit_status()
            if self.ret_code != 0:
                self.ret_text = stdout.channel.recv_stderr(4096).decode('ascii')
                print("cmd %s Failed at %s@%s" % (cmd, self.user, self.host))
            else:
                self.ret_text = stdout.read()
                print("cmd %s executed at %s@%s" % (cmd, self.user, self.host))
        finally:
            if close_connection: self.client.close()
            return self.ret_text, self.ret_code

    def upload(self, local_path, remote_path):
        try:
            ftp_client = self.client.open_sftp()
            ftp_client.put(local_path, remote_path)
            ftp_client.close()
            #local_path = 'C:/python_projects/PySyncObj/benchmarks/perf.py"'
            print("%s uploaded to %s for %s@%s" % (local_path, remote_path, self.user, self.host))
            return True
        except Exception as exc:
            print("Failed to upload from: {} to: {}  for %s@%s" % (local_path, remote_path, self.user, self.host))
            return False

    def download(self, remote_path, local_path):
        try:
            ftp_client = self.client.open_sftp()
            ftp_client.get(remote_path, local_path)
            ftp_client.close()
            print("%s downloaded from %s for %s@%s" % (local_path, remote_path, self.user, self.host))
            return True
        except Exception as exc:
            print("Failed to download from: {} to: {}  for %s@%s" % (remote_path, local_path, self.user, self.host))
            return False


outp, code = SSH(host, port, user, pwd).exe('ls')
print(outp, code)
outp, code = SSH(host, port, user, pwd).exe('aaa')
print(outp, code)
ssh1 = SSH(host, port, user, pwd)
res = ssh1.upload(os.path.join(os.getcwd(), 'perf.py'), "~")
print(res)
# from paramiko import SSHClient
# from scp import SCPClient
#
# ssh = SSHClient()
# ssh.load_system_host_keys()
# ssh.connect('example.com')
#
# with SCPClient(ssh.get_transport()) as scp:
#     scp.put('test.txt', 'test2.txt')
#     scp.get('test2.txt')

# class SSH:
#
#     def __init__(self, host, user, psw):
#         self.ssh = paramiko.SSHClient()
#         self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#         self.ssh.connect(host, username=user, password=psw, port=22)
#
#         channel = self.ssh.invoke_shell()
#         self.stdin = channel.makefile('wb')
#         self.stdout = channel.makefile('r')
#
#     def __del__(self):
#         self.ssh.close()
#
#     def execute(self, cmd):
#         """
#
#         :param cmd: the command to be executed on the remote computer
#         :examples:  execute('ls')
#                     execute('finger')
#                     execute('cd folder_name')
#         """
#         cmd = cmd.strip('\n')
#         self.stdin.write(cmd + '\n')
#         finish = 'end of stdOUT buffer. finished with exit status'
#         echo_cmd = 'echo {} $?'.format(finish)
#         self.stdin.write(echo_cmd + '\n')
#         shin = self.stdin
#         self.stdin.flush()
#
#         shout = []
#         sherr = []
#         exit_status = 0
#         for line in self.stdout:
#             if str(line).startswith(cmd) or str(line).startswith(echo_cmd):
#                 # up for now filled with shell junk from stdin
#                 shout = []
#             elif str(line).startswith(finish):
#                 # our finish command ends with the exit status
#                 exit_status = int(str(line).rsplit(maxsplit=1)[1])
#                 print('cmd:{} exit_status:{}'.format(cmd, exit_status))
#                 if exit_status:
#                     # stderr is combined with stdout.
#                     # thus, swap sherr with shout in a case of failure.
#                     sherr = shout
#                     shout = []
#                 break
#             else:
#
#                 exit_status = int(str(line).rsplit(maxsplit=1)[1])
#                 print('cmd:{} exit_status:{}'.format(cmd, exit_status))
#                 # get rid of 'coloring and formatting' special characters
#                 shout.append(re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', line).
#                              replace('\b', '').replace('\r', ''))
#
#         # first and last lines of shout/sherr contain a prompt
#         if shout and echo_cmd in shout[-1]:
#             shout.pop()
#         if shout and cmd in shout[0]:
#             shout.pop(0)
#         if sherr and echo_cmd in sherr[-1]:
#             sherr.pop()
#         if sherr and cmd in sherr[0]:
#             sherr.pop(0)
#
#         return shin, shout, sherr
#
#
# ssh =  SSH(host, user, pwd)
# # stdin, stdout, stderr = ssh.execute("ls -la")
# # print(stdin, stdout, stderr)
# # print(stdout, end='')
# stdin, stdout, stderr = ssh.execute("aaa")
# print(stdin, stdout, stderr)
# print(stderr, end='')

# import shutil
# shutil.copy('a.txt', '~/sshmount')


# from multiprocessing import Pool
# from poolable import make_applicable, make_mappable
#
# def cube(x):
#   return x**3
#
# if __name__ == "__main__":
#   pool    = Pool(processes=2)
#   results = [pool.apply_async(*make_applicable(cube,x)) for x in range(1,7)]
#   print([result.get(timeout=10) for result in results])


from multiprocessing import Process
import requests

def func1():
  print ('func1: starting ' + datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S.%f'))
  #for i in range(10000000): pass
  r = requests.get('https://github.com/timeline.json')
  #r.status_code
  print ('func1: finishing ' + datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S.%f'))

def func2():
  print ('func2: starting ' + datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S.%f'))
  #for i in range(10000000): pass
  r = requests.get('https://github.com/timeline.json')
  #r.status_code
  print ('func2: finishing ' + datetime.datetime.now().strftime('%d-%m-%Y %H:%M:%S.%f'))

if __name__ == '__main__':
  p1 = Process(target=func1)
  p1.start()
  p2 = Process(target=func2)
  p2.start()
  p1.join()
  p2.join()


def runInParallel(*fns):
  proc = []
  for fn in fns:
    p = Process(target=fn)
    p.start()
    proc.append(p)
  for p in proc:
    p.join()

#runInParallel([func1, func2])