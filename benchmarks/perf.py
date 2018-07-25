#!/usr/local/bin/python3
import psutil,os,sys,time

# For Windows
# process_data = {}
# process_names = {}
# for proc in psutil.process_iter():
#     #print(proc.name())
#     process_names[proc.name()] = {'pid' : proc.pid, 'proc' : proc.name(), 'cpu' : proc.cpu_percent(), 'memory': proc.memory_percent()}
#     print(process_names[proc.name()])
#     with open(os.getcwd() + os.sep +  'perf.log', 'a') as logfile:
#          logfile.write(str(proc.cpu_percent()) + "," + str(proc.memory_percent()) + '\n')

#For Linux
duration = 60
interval = 1
i = 0
while i < duration:
    process_data = {}
    process_names = {}
    for proc in psutil.process_iter():
        process_names[proc.name()] = {'cpu' : proc.cpu_percent(), 'memory': proc.memory_full_info()}
        print(process_names[proc.name()])
    time.sleep(interval)
    i += 1

#print(process_data)

# ps -ef | grep -v grep |grep perf.py | awk '{print $2}'|xargs kill -9
