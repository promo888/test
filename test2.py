import psutil
import websockets

import benchmarks.node as node

n = node.Node('127.0.0.1', 8000)
print(n.whoIsMaster())