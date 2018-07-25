from flask import Flask, redirect
from flask import request
from datetime import datetime
import random, time

# from node import Node
import argparse
from utils import *  # whoIsMaster,getNode
import logging
import os, sys, re, glob

# http://flask.pocoo.org/docs/0.12/quickstart/#accessing-request-data

HOST = '127.0.0.1'
PORT = 8000
parser = argparse.ArgumentParser(description='Node init')
# parser.add_argument('-h', type=str, default='127.0.0.1', help='Server ip')
parser.add_argument('-p', type=int, default=8000, help='Server port')
args = parser.parse_args()
# print('args: ', args)
if not args.p is None: PORT = args.p
# if not args.h is None: HOST = args.h


app = Flask(__name__)


def purge(dir, pattern):
    for f in os.listdir(dir):
        if re.search(pattern, f):
            os.remove(os.path.join(dir, f))


def amImaster():
    master = whoIsMaster()
    host, port = master.split(":")
    if (host == HOST and int(port) == PORT):
        return True
    else:
        return False


# def redirectTo(master_host, slave_host, path="tx"):
#     if not request.data is None:
#         logging.debug('request data: ' + str(request.data))
#     else:
#         request.data = ""
#
#     if ("SLAVE" not in str(request.data) and amImaster()):
#         logging.debug('{}:{} Redirecting POST to SLAVE node: {}'.format(HOST, PORT, slave_host))
#         request.data = HOST
#         return redirect("http://" + slave_host + "/" + path, code=307)
#     else:
#         logging.debug('{}:{} Redirecting POST to MASTER node: {}'.format(HOST, PORT, master_host))
#         request.data = "SLAVE"
#         #master = whoIsMaster()
#         return redirect("http://" + master_host + "/" + path, code=307)



def redirectTo(slave_host, path="tx"):
    if not request.data is None:
        logging.debug('request data: ' + str(request.data))
    else:
        request.data = ""
    master_host = whoIsMaster()
    if ("SLAVE" in str(request.data)):
        if amImaster():
            logging.debug('{}:{} Redirecting POST to SLAVE node: {}'.format(HOST, PORT, slave_host))
            request.data = HOST
            return redirect("http://" + slave_host + "/" + path, code=307)
        # else:
        #     logging.debug('{}:{} Redirecting POST to MASTER node: {}'.format(HOST, PORT, master_host))
        #     request.data = "SLAVE"
        #     # master = whoIsMaster()
        #     return redirect("http://" + master_host + "/" + path, code=307)
    else:
        logging.debug('{}:{} Redirecting POST to MASTER node: {}'.format(HOST, PORT, master_host))
        request.data = "SLAVE"
        #master = whoIsMaster()
        return redirect("http://" + master_host + "/" + path, code=307)


@app.route('/tx2', methods=['POST'])
def echo():
    # return request.data
    # logging.INFO("Request: " + str(request))
    return ('POST response SLAVE from {}'.format(PORT).encode('utf-8'))


# flask.redirect(flask.url_for('operation'), code=307)


last_slave_index = 0


@app.route('/tx', methods=['POST'])
def tx():
    global last_slave_index
    # print(whoIsMaster())
    master = whoIsMaster()
    logging.info('master: %s' % (master))
    host, port = master.split(":")
    return ('POST response MASTER from {}'.format(PORT).encode('utf-8'))

    # if (host == HOST and int(port) == PORT):  # I'm a master

    # if (amImaster()):
    #     if last_slave_index == 0 or last_slave_index >= len(slave_nodes):
    #         node_index = 0
    #         #     last_slave_index = 0
    #         #     slave_node = getNode(node_index, slave_nodes)
    #         #     last_slave_index += 1
    #         #     return redirectTo(master, slave_node)
    #         # # elif last_slave_index < len(slave_nodes):
    #         # #     node_index = last_slave_index
    #         # #     slave_node = getNode(node_index, slave_nodes)
    #         # #     return redirectTo(master, slave_node)
    #         # else:
    #
    #     node_index = last_slave_index % len(slave_nodes)
    #     slave_node = getNode(node_index, slave_nodes)
    #     # logging.INFO("Request: " + str(request.form))
    #     # logging.debug('{}:{} Redirecting POST to SLAVE node: {}'.format(HOST, PORT, slave_node))
    #     last_slave_index += 1
    #     # return await redirect(request, "http://" + slave_node + "/tx2")
    #     # if not request.data is None: logging.debug('data: ' + str(request.data))
    #     if ("SLAVE" not in str(request.data)):
    #         request.data = HOST
    #         return redirect("http://" + slave_node + "/tx", code=307)
    #     else:
    #         return ('POST response MASTER from {}'.format(PORT).encode('utf-8'))
    #     #return redirectTo(slave_node)
    # else:
    #     #return ('POST response SLAVE from {}'.format(PORT).encode('utf-8'))
    #     if (HOST in str(request.data)):
    #         return ('POST response SLAVE from {}'.format(PORT).encode('utf-8'))
    #     else:
    #         request.data = "SLAVE"
    #         return ('Should redirect to MASTER from {}'.format(PORT).encode('utf-8'))
    #         #return redirect("http://" + master + "/tx", code=307)

        # if ("SLAVE" not in str(request.data)):
        #     request.data = "SLAVE"
        #     return redirect("http://" + master + "/tx", code=307)
        # else:
        #    # if (request.data = HOST):
        #      return ('POST response SLAVE (MASTER REDIRECT) from {}'.format(PORT).encode('utf-8'))
        #    # else:
        #    #     return ('POST response SLAVE (DIRECT) from {}'.format(PORT).encode('utf-8'))

# else:
#     last_slave_index = 0
#     node_index = last_slave_index % len(slave_nodes)
#     slave_node = getNode(node_index, slave_nodes)


# return await redirect(request, "http://" + master + "/tx")
# if not request.data is None: logging.debug('data: ' + str(request.data))
# if(request.headers.environ['REMOTE_ADDR'] not in str(request.data)):
#     # logging.debug('%s:%s Redirecting POST to MASTER: %s' % (HOST, PORT, master))
#     # request.data = "SLAVE"
#     # return redirect("http://" + master + "/tx", code=307)
#     return redirectTo(master, slave_node)
# else:
#     return ('POST response SLAVE from {}'.format(PORT).encode('utf-8'))


if __name__ == '__main__':
    # print(glob.glob("*_server.log"))
    purge(os.getcwd(), "^" + str(PORT) + "_server.log$")
    logging.basicConfig(filename='%s_server.log' % PORT, level=logging.DEBUG, format='%(asctime)s %(message)s')

    print("args: ", sys.argv)
    #killByPort(':8000')

    configuration = load_config()
    nodes = configuration['nodes']
    slave_nodes = {k: v for k, v in nodes.items() if not '%s:%s' % (HOST, PORT) in v}
    print(slave_nodes)

    # app = Flask("test")
    app.run(port=int(PORT))

# Copy of http://stackoverflow.com/a/20104705
# from flask import Flask, render_template
# from flask_sockets import Sockets
#
# app = Flask(__name__)
# app.debug = True
#
# sockets = Sockets(app)
#
# @sockets.route('/echo')
# def echo_socket(ws):
#     while True:
#         message = ws.receive()
#         ws.send(message[::-1])
#
# @app.route('/')
# def hello():
#     return 'Hello World!'
#
# @app.route('/echo_test', methods=['GET'])
# def echo_test():
#     return render_template('echo_test.html')
#
# if __name__ == '__main__':
#     app.run()

# templates-echo_test.html
# <!DOCTYPE html>
# <html>
#   <head>
#     <script type="text/javascript">
#        var ws = new WebSocket("ws://localhost:8000/echo");
#        ws.onopen = function() {
#            ws.send("socket open");
#        };
#        ws.onclose = function(evt) {
#            alert("socket closed");
#        };
#        ws.onmessage = function(evt) {
#            alert(evt.data);
#        };
#     </script>
#   </head>
# </html>
