'''
    udp socket client
    Silver Moon
'''

#https://wiki.python.org/moin/UdpCommunication #MultiCast
#https://www.hacksparrow.com/node-js-udp-server-and-client-example.html

import socket  # for sockets
import sys  # for exit

# create dgram udp socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except:  # socket.error:
    print
    'Failed to create socket'
    sys.exit()

host = '127.0.0.1'  # 'localhost'
port = 8888

import time

duration = 5
start = time.time()
count = 0
while (time.time() - start < duration):
    msg = "x" * 1000  # raw_input('Enter message to send : ')

    try:
        # Set the whole string
        s.sendto(msg.encode(), (host, port))

        # receive data from client (data, addr)
        d = s.recvfrom(1024)
        reply = d[0]
        #addr = d[1]

       # print('Server reply : ' + d[0].decode('utf-8'))
        count += 1

    except socket.error as msg:
        print('Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
print("{} req/sec".format(count // duration))
