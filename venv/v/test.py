import numpy as np
import scipy as sp
import pandas as pd
#import tensoflow as tf
import keras as k

# import the necessary packages
from sklearn.preprocessing import LabelBinarizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from keras.models import Sequential
from keras.layers.core import Dense
from keras.optimizers import SGD
from imutils import paths
import matplotlib.pyplot as plt
import numpy as np
import argparse
import random
import pickle
import cv2
import os
#
# d = np.array([1, 2, 3, 4, 5])
# print(d**2)
# print(d>3)
# print(d.clip(3, 5))
#
# import timeit
# normal_py_sec = timeit.timeit('sum(x*x for x in range(1000))', number=10000)
# naive_np_sec = timeit.timeit('sum(na*na)', setup="import numpy as np; na=np.arange(1000)", number=10000)
# good_np_sec = timeit.timeit('na.dot(na)', setup="import numpy as np; na=np.arange(1000)", number=10000)
# print("Normal Python: %f sec" % normal_py_sec)
# print("Naive NumPy: %f sec" % naive_np_sec)
# print("Good NumPy: %f sec" % good_np_sec)
# Normal Python: 0.893944 sec
# Naive NumPy: 1.866529 sec
# Good NumPy: 0.018191 sec


import scipy as sp
data = sp.genfromtxt("/home/igor/py_samples1/ch01/data/web_traffic.tsv", delimiter="\t")
#print(data)
x = data[:, 0]
y = data[:, 1]
x = x[~sp.isnan(y)]
y = y[~sp.isnan(y)]

# представляем точки (х,у) кружочками диаметра 10
plt.scatter(x, y, s=10)
plt.title("Web traffic over the last month")
plt.xlabel("Time")
plt.ylabel("Hits/hour")
plt.xticks([w*7*24 for w in range(5)], ['week %i' % w for w in range(5)] )
plt.autoscale(tight=True)
#рисуем полупрозрачную сетку пунктирными линиями
plt.grid(True, linestyle='-', color='0.75')
plt.show()


