#from v.v1 import *
#from v.v1 import ROOT_DIR, config as C, wallets as W \

from v1 import tools

# print("ROOT_DIR", ROOT_DIR)
# config = C.Config()
# wallet = W.Wallet()
# print(dir(wallet))
# print(config.X)



from v.v1 import node

t = tools.Tools()
#print(not t.Db.isDBvalue("*29c2bd6eac2b1b1db2e00df221bf783e") and not t.Db.isDBvalue("-29c2bd6eac2b1b1db2e00df221bf783e") and t.Db.isDBvalue("+29c2bd6eac2b1b1db2e00df221bf783e"))
t.Utils.resetNode()
t.insertGenesis()
t.testTx()
#n = node.Node()
#n.loop()

