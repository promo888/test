import psutil
import websockets

# import benchmarks.node as node
#
# n = node.Node('127.0.0.1', 8000)
# print(n.whoIsMaster())

from sklearn import datasets
import numpy as np
iris = datasets.load_iris()
Х = iris.data[:, [ 2 , 3 ]]
у = iris.target
from sklearn.model_selection import train_test_split
X_train, X_ test, y_train, y_test = train_test_split(Х , у , test_size=0.2, random_state=O, shuffle=False)