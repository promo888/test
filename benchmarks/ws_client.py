import socket,time

PORT = 8000
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', PORT))

# while 1:
#     data = client_socket.recv(512)
#     if ( data == 'q' or data == 'Q'):
#         client_socket.close()
#         break;
#     else:
#         print ("RECIEVED:" , data)
#         data = raw_input ( "SEND( TYPE q or Q to Quit):" )
#         if (data <> 'Q' and data <> 'q'):
#             client_socket.send(data)
#         else:
#             client_socket.send(data)
#             client_socket.close()
#             break;

duration = 5
start = time.time()
buffersize = 1000000
count = 0
while(time.time()-start <= duration):
    client_socket.send(b'x' * buffersize)
    count += 1

client_socket.close()
print(duration, "sec,", count, " req/res of ", buffersize, " bytes, total: ", count * buffersize / 1024 / 1024 / duration, "mb/sec")