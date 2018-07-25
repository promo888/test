def graphIt(fromFile):
    import matplotlib.pyplot as plt
    import numpy as np

    # x, y = np.loadtxt(fromFile, delimiter=',', unpack=True)
    # plt.plot(x, y label='Time')

    import csv

    x = []
    y = []
    z = []
    n = []
    secs = []
    secs2 = []
    with open(fromFile, 'r') as csvfile:
        plots = csv.reader(csvfile, delimiter=',')
        sec = 0
        for row in plots:
            print(row)
            x.append(float(row[0]))
            y.append(float(row[1]))
            z.append(float(row[2]))
            n.append(float(row[3]))
            sec+=1
            secs.append(sec/60)
            secs2.append(sec+1)


    print(x)
    print(secs)
    labels = ['x', 'y', 'z', 'n']
    plt.plot(secs , secs2, x, y, z, n,  label=labels)
    plt.xlabel('min')
    plt.ylabel('%')
    plt.title('Stats')
    plt.legend()
    plt.show()

    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    ax1.set_title("Plot title...")
    ax1.set_xlabel('your x label..')
    ax1.set_ylabel('your y label...')
    ax1.plot(secs , secs2, x, y, z, n, label=labels)
    fig.savefig('../../myplot2.png')


graphIt('../../perf2.log')
#TODO add byPidTail + tweal graph
# https://matplotlib.org/examples/pylab_examples/multiple_figs_demo.html
# https://stackoverflow.com/questions/22276066/how-to-plot-multiple-functions-on-the-same-figure-in-matplotlib
# https://stackoverflow.com/questions/11481644/how-do-i-assign-multiple-labels-at-once-in-matplotlib
# https://nelsonslog.wordpress.com/2015/01/14/python-logging-different-threads-to-different-files/
# https://github.com/CopterExpress/python-async-logging-handler


import psutil,subprocess,re
def killByPort(port):
    from sys import platform
    # if platform == "linux" or platform == "linux2":
    # # linux
    # elif platform == "darwin":
    # # OS X
    # elif platform == "win32":

    lines = subprocess.check_output(["netstat", "-ano"], universal_newlines=True)
    rows = []
    pids = []
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
        print(col)
        pids.append(col['pid'])
    if (os.name.lower() == 'nt' and len(pids)>0):
        os.popen("taskkill /F /PID " + " ".join(pids))
    if (os.name.lower() != 'nt' and len(pids)>0):
        os.popen("kill -9 " + " ".join(pids))

def get_proc_by_id(pid):
    return psutil.Process(pid)

def get_proc_by_name(pname):
    """ get process by name

    return the first process if there are more than one
    """
    pids = []
    for proc in psutil.process_iter():
        try:
            if proc.name().lower() == pname.lower():
                #return proc  # return 1st if found one
                pids.append(proc.pid)
        except psutil.AccessDenied:
            pass
        except psutil.NoSuchProcess:
            pass
    return pids
print('chrome pids: ' + str(get_proc_by_name("chrome.exe")))

_pmap = {}


def process_iter():
    """Return a generator yielding a Process class instance for all
    running processes on the local machine.

    Every new Process instance is only created once and then cached
    into an internal table which is updated every time this is used.

    Cached Process instances are checked for identity so that you're
    safe in case a PID has been reused by another process, in which
    case the cached instance is updated.

    The sorting order in which processes are yielded is based on
    their PIDs.
    """

    def add(pid):
        proc = Process(pid)
        _pmap[proc.pid] = proc
        return proc

    def remove(pid):
        _pmap.pop(pid, None)

    a = set(get_pid_list())
    b = set(_pmap.keys())
    new_pids = a - b
    gone_pids = b - a

    for pid in gone_pids:
        remove(pid)
    for pid, proc in sorted(list(_pmap.items()) + \
                            list(dict.fromkeys(new_pids).items())):
        try:
            if proc is None:  # new process
                yield add(pid)
            else:
                # use is_running() to check whether PID has been reused by
                # another process in which case yield a new Process instance
                if proc.is_running():
                    yield proc
                else:
                    yield add(pid)
        except NoSuchProcess:
            remove(pid)
        except AccessDenied:
            # Process creation time can't be determined hence there's
            # no way to tell whether the pid of the cached process
            # has been reused. Just return the cached version.
            yield proc


@_deprecated()
def get_process_list():
    """Return a list of Process class instances for all running
    processes on the local machine (deprecated).
    """
    return list(process_iter())

#proc = psutil.Process(4364)

total = psutil.virtual_memory().total
rss, vss = proc.memory_info()
percent = proc.memory_percent()

print
"rss: %s Byte, vss: %s Byte" % (rss, vss)
print
"total: %.2f(M)" % (float(total) / 1024 / 1024 / 1024)
print
"percent: %.2f%%, calc: %.2f%%" % (percent, 100 * float(rss) / total)
import os

dirpath = os.getcwd()
print("current directory is : " + dirpath)
foldername = os.path.basename(dirpath)
print("Directory name is : " + foldername)
scriptpath = os.path.realpath(__file__)
print("Script path is : " + scriptpath)