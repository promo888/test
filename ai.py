import psutil
import websockets

# import benchmarks.node as node
#
# n = node.Node('127.0.0.1', 8000)
# print(n.whoIsMaster())

from sklearn import datasets
import numpy as np
iris = datasets.load_iris()
Х = iris.data[:, [2, 3]]
у = iris.target
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(Х, у, test_size=0.3, random_state=0) #, shuffle=False)


from sklearn .preprocessing import StandardScaler
sc = StandardScaler()
sc.fit(X_train)
X_train_std = sc.transform(X_train)
X_test_std = sc.transform(X_test)



from matplotlib import pyplot as plt
from sklearn.linear_model import Perceptron
# ppn = Perceptron(eta0=0.1)
# ppn.fit(X_train, y_train)
# plt.plot(range(1, len(ppn.errors_) + 1), ppn.errors_, marker='o')
# plt.xlaЬel(' Эпохи ')
# # число ошибочно 1<Лассифицированных случ аев во время обновлений
# plt.ylaЬel(' Число случаев ошибочной KЛассификации ')
# plt.show()


ppn = Perceptron(max_iter=40, eta0=0.1, random_state=0) #, shuffle=True)
ppn.fit(X_train_std, y_train)
y_pred = ppn.predict(X_test_std)
print('Чиcлo ошибочно классифицированных образцов: %d/%d ' % ((y_test != y_pred).sum(), len(y_test)))
from sklearn.metrics import accuracy_score
print('accuracy_score: %.2f' % accuracy_score(y_test, y_pred))


# from keras.datasets import mnist
# from keras.models import Sequential, load_model
# from keras.layers . core import Dense, Dropout, Activation
# from keras.utils import np_utils
# (X_train, y_train), (X_test, y_test) = mnist.load_data()
# X_train = X_train.reshape(60000, 784)
# X_test = X_test.reshape(10000, 784)
# X_train = X_train.astype('float32')
# X_test = X_test.astype('float32')
# X_train /= 255
# X_test /= 255
#
#
# print(np.unique(y_train, return_counts=True))
# model = Sequential()
# model.add(Dense(512)) #, input_shape=(784, )))
# model.add(Activation('relu'))
# model.add(Dropout(0.2))
# model.add(Dense(512))
# model.add(Activation('relu'))
# model.add(Dropout(0.2))
# model.add(Dense(10))
# model.add(Activation('softmax'))
# model.compile(loss='categorical_crossentropy', metrics=['accuracy'], optimizer='adam')
# loss_and_metrics = model.evaluate(X_test, y_test) #, verbose=2)
# print("Test Loss", loss_and_metrics[0])
# print("Test Accuracy", loss_and_metrics[1])


