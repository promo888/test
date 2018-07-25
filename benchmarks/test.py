import math, zlib, time
n = math.factorial(333)
s = str(n)
print(len(s))
b = bytes(str(n), 'ascii') #to check without ascii
c = zlib.compress(b)
print(len(c))
#615 to 287

start = time.time()
for x in range(11000):
    u = zlib.decompress(c)
    int(u) == n
print("%s secs took to decompress and covert binary to bigint > 300decs" % (time.time() - start))


def kv(var, **kvargs):
    # for it in kvargs.items():
    #     print('key {}: value {}'.format(it[0], it[1]))
    for k, v in kvargs.items():
        print('key {}: value {}'.format(k, v))

def kv2(var, **kvargs):
    for it in kvargs.items():
        for it in kvargs['kvargs'].items():
            print(it[0], it[1])

def kv3(var, kvargs={}):
    for k, v in kvargs.items():
        print('key {}: value {}'.format(k, v))

kvs = {'a': 1, 'b': 2, 'c': 3}
kv(1, **kvs)
kv(1, a=1, b=2, c=3)
a = 1
b = 2
c = 3
includes = ['a', 'b', 'c']
#lst = [lambda it: it in vars(self) if it in includes]
lst = []
mp = {}
for i in includes:
    lst.append({i: locals()[i]})
    mp[i] = locals()[i]
#print(lst)
#mp = dict([(i, locals()[i]) for i in includes])

kv(1, **mp)
kv(1, kvargs=mp)
kv2(1, kvargs=mp)
kv3(1, kvargs=mp)
kv3(1, kvargs=dict(a=1, b=2))
kv2(1, kvargs=dict(a=1, b=2))

print('...')