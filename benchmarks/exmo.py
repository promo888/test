import krakenex
import bitstamp.client
#import poloniex
# from poloniex import Poloniex
import pprint, time
from datetime import datetime
import requests, json, ujson
import asyncio
import threading

#https://medium.com/@bfortuner/python-multithreading-vs-multiprocessing-73072ce5600b #numpy avoid gil
#https://gist.github.com/douglasmiranda/5127251 #dict nested lookups
#https://www.haykranen.nl/2016/02/13/handling-complex-nested-dicts-in-python/
#https://stackoverflow.com/questions/16956810/how-do-i-find-all-files-containing-specific-text-on-linux
#https://stackoverflow.com/questions/39450065/python-3-read-write-compressed-json-objects-from-to-gzip-file


from threading import Thread
import sys
from aiohttp import ClientSession
import http.client, urllib.parse
##from poloniex import Poloniex

IS_PY2 = sys.version_info < (3, 0)
if IS_PY2:
    from Queue import Queue
else:
    from queue import Queue




class Worker(Thread):
    """ Thread executing tasks from a given tasks queue """
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception as e:
                # An exception happened in this thread
                print(e)
            finally:
                # Mark this task as done, whether an exception happened or not
                self.tasks.task_done()


class ThreadPool:
    """ Pool of threads consuming tasks from a queue """
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads):
            Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        """ Add a task to the queue """
        self.tasks.put((func, args, kargs))

    def map(self, func, args_list):
        """ Add a list of tasks to the queue """
        for args in args_list:
            self.add_task(func, args)

    def wait_completion(self):
        """ Wait for completion of all the tasks in the queue """
        self.tasks.join()


#https://codingnetworker.com/2015/10/python-dictionaries-json-crash-course/



BIDS = "bids"
ASKS = "asks"

p = "poloniex"
k = "kraken"
b = "bitstamp"
e = "exmo"

BTCUSD = "btcusd"
XRPUSD = "xrpusd"
LTCUSD = "ltcusd"
BCHUSD = "bchusd"
ETHUSD = "ethusd"



P = None() #Poloniex()
K = krakenex.API()
B = bitstamp.client.Public()

# arb_prices = {
#     {k: {XRPUSD: {"price": None, "ts": None}, BTCUSD: {"price": None, "ts": None}, BCHUSD: {"price": None, "ts": None}}},
#     {e: {XRPUSD: {"price": None, "ts": None}, BTCUSD: {"price": None, "ts": None}, BCHUSD: {"price": None, "ts": None}}}
# }
arb_prices = {} #avg of 1,3,5k
arb_prices[k] = {XRPUSD: {"bidprice": None, "bidts": None,"askprice": None, "askts": None,
                          "last_trade_amount" : None, "last_trade_price" : None,
                          "portfolio_amount": None, "portfolio_ts": None},
                 LTCUSD: {"bidprice": None, "bidts": None,"askprice": None, "askts": None,
                          "last_trade_amount": None, "last_trade_price": None,
                          "portfolio_amount": None, "portfolio_ts": None},
                 BCHUSD: {"bidprice": None, "bidts": None,"askprice": None, "askts": None,
                          "last_trade_amount": None, "last_trade_price": None,
                          "portfolio_amount": None, "portfolio_ts": None},
                 ETHUSD: {"bidprice": None, "bidts": None,"askprice": None, "askts": None,
                          "last_trade_amount": None, "last_trade_price": None,
                          "portfolio_amount": None, "portfolio_ts": None}
                }
arb_prices[e] = {XRPUSD: {"bidprice": None, "bidts": None,"askprice": None, "askts": None,
                          "last_trade_amount": None, "last_trade_price": None,
                          "portfolio_amount": None, "portfolio_ts": None},
                 LTCUSD: {"bidprice": None, "bidts": None,"askprice": None, "askts": None,
                          "last_trade_amount": None, "last_trade_price": None,
                          "portfolio_amount": None, "portfolio_ts": None},
                 BCHUSD: {"bidprice": None, "bidts": None,"askprice": None, "askts": None,
                          "last_trade_amount" : None, "last_trade_price": None,
                          "portfolio_amount": None, "portfolio_ts": None},
                 ETHUSD: {"bidprice": None, "bidts": None,"askprice": None, "askts": None,
                          "last_trade_amount": None, "last_trade_price": None,
                          "portfolio_amount": None, "portfolio_ts": None}
                 }
arb_prices[k+e] = {} #avg of 1,3,5k
#k: buy, e: sell
arb_prices[k+e]['askbid'] = {XRPUSD: {"ratio": None, "ts": None}, LTCUSD: {"ratio": None, "ts": None}, BCHUSD: {"ratio": None, "ts": None}, ETHUSD: {"ratio": None, "ts": None}}
#k: sell, e: buy
arb_prices[k+e]['bidask'] = {XRPUSD: {"ratio": None, "ts": None}, LTCUSD: {"ratio": None, "ts": None}, BCHUSD: {"ratio": None, "ts": None}, ETHUSD: {"ratio": None, "ts": None}}
#k: buy, e: buy
arb_prices[k+e]['bidbid'] = {XRPUSD: {"ratio": None, "ts": None}, LTCUSD: {"ratio": None, "ts": None}, BCHUSD: {"ratio": None, "ts": None}, ETHUSD: {"ratio": None, "ts": None}}
#k: sell, e: sell
arb_prices[k+e]['askask'] = {XRPUSD: {"ratio": None, "ts": None}, LTCUSD: {"ratio": None, "ts": None}, BCHUSD: {"ratio": None, "ts": None}, ETHUSD: {"ratio": None, "ts": None}}


def getTicker(exchange, pair):
    tickers = {
        XRPUSD: {p: "USDT_XRP", k: "XXRPZUSD", b: "xrpusd", e: "XRP_USD"},
        LTCUSD: {p: "USDT_LTC", k: "XLTCZUSD", b: "ltcusd", e: "LTC_USD"},
        BCHUSD: {p: "USDT_BCH", k: "BCHUSD", b: "bchusd", e: "BCH_USD"},
        ETHUSD: {p: "USDT_ETH", k: "XETHZUSD", b: "ethusd", e: "ETH_USD"},
        BTCUSD: {p: "USDT_BTC", k: "XXBTZUSD", b: "btcusd", e: "BTC_USD"}
    }

    try:
        ticker = tickers[pair][exchange]
        return ticker
    except Exception as exc:
        print("Exception getTicker: ", exc)
        return None

def getTickerID(pair):
    if pair.upper() in ["USDT_XRP", "XXRPZUSD", "XRPUSD", "XRP_USD"]: return XRPUSD
    if pair.upper() in ["USDT_LTC", "XLTCZUSD", "LTCUSD", "LTC_USD"]: return LTCUSD
    if pair.upper() in ["USDT_BCH", "BCHUSD", "BCHUSD", "BCH_USD"]: return BCHUSD
    if pair.upper() in ["USDT_ETH", "XETHZUSD", "ETHUSD", "ETH_USD"]: return ETHUSD
    if pair.upper() in ["USDT_BTC", "XXBTZUSD", "BTCUSD", "BTC_USD"]: return BTCUSD

    return None


def getAsksBids(exchange, askbid):
    asksbids = {
        ASKS: {p: ASKS, k: ASKS, b: ASKS, e: "ask"},
        BIDS: {p: BIDS, k: BIDS, b: BIDS, e: "bid"}
    }

    try:
        ask_or_bid = asksbids[askbid][exchange]
        return ask_or_bid
    except Exception as exc:
        print("Exception: ", exc)
        return None

def getAskOrBid(askbid):
    if askbid.lower() in [ASKS, "ask"]: return "ask"
    if askbid.lower() in [BIDS, "bid"]: return "bid"

    return None


def returnKrakenOrderBook(pair):
    return K.query_public('Depth', {'pair': pair.upper(), 'count': '50'})


def returnBitstampOrderBook(pair):
    return B.order_book(True, pair.lower()[:3], pair.lower()[3:])


def returnPoloniexOrderBook(pair):
    return P.returnOrderBook(pair.upper())


def returnExmoOrderBook(pair):
    res = requests.get("https://api.exmo.com/v1/order_book/?pair={}".format(pair.upper()))
    #get("https://api.exmo.com/v1/order_book/?pair={}".format(pair.upper(), [])
    # await get("https://api.exmo.com/v1/order_book/?pair={}".format(pair.upper()))
    # https://api.exmo.com/v1/order_book/?pair=USDT_USD
    return res


def getDateTimeFromTs(ts):
    return time.strftime("%d-%m-%Y  %H:%M:%S.%f", time.localtime(int(ts)))[:-3]


def getDtUtcnow():
    return datetime.utcnow().strftime('%d-%m-%Y %H:%M:%S.%f')[:-3]


def getOrderBook(exchange, pair):
    try:
        ex = exchange.lower()
        if ex == k:
            return returnKrakenOrderBook(pair)
        elif ex == b:
            return returnBitstampOrderBook(pair)
        elif ex == p:
            return returnPoloniexOrderBook(pair)
        elif ex == e:
            return returnExmoOrderBook(pair)
        else:
            return None
    except Exception as exc:
        print("Exception getOrderBook: ", exc)
        #raise exc
        return None


#async
def getAvgPrice(exchange, pair, bidask, fiat_amount=1000, toprint=True):
    start = time.time()
    if toprint: print("Start: {}".format(getDtUtcnow()))
    ex = exchange.lower()
    ob = getOrderBook(ex, pair)
    count = 0
    price = 0
    amount = 0
    total_price = 0
    total_amount = 0
    if not ob is None:
        if ex == k:
            for quote in ob['result'][pair][bidask]:
                price = float(quote[0])
                amount = float(quote[1])
                total_price += (price * amount)
                total_amount += amount
                if (total_price >= fiat_amount):
                    avg_price = total_price / total_amount
                    if toprint:
                        print("{:0.3f} {} {} avg for {} fiat on {}".format(avg_price, pair.upper(), bidask.upper(),
                                                                       fiat_amount, exchange.upper()))
                        print("Req/Response %s secs" % (time.time() - start))
                        print("Finish: {}".format(getDtUtcnow()))
                    arb_prices[exchange][getTickerID(pair)][getAskOrBid(bidask) + 'price'] = avg_price
                    arb_prices[exchange][getTickerID(pair)][getAskOrBid(bidask) + 'ts'] = time.time()

                    return avg_price
        elif ex == b:
            for quote in ob[bidask]:
                price = float(quote[0])
                amount = float(quote[1])
                total_price += (price * amount)
                total_amount += amount
                if (total_price >= fiat_amount):
                    avg_price = total_price / total_amount
                    if toprint:
                        print("{:0.3f} {} {} avg for {} fiat on {}".format(avg_price, pair.upper(), bidask.upper(),
                                                                       fiat_amount, exchange.upper()))
                        print("Req/Response %s secs" % (time.time() - start))
                        print("Finish: {}".format(getDtUtcnow()))
                    arb_prices[exchange][getTickerID(pair)][getAskOrBid(bidask) + 'price'] = avg_price
                    arb_prices[exchange][getTickerID(pair)][getAskOrBid(bidask) + 'ts'] = time.time()

                    return avg_price
        elif ex == p:
            for quote in ob[bidask]:
                price = float(quote[0])
                amount = float(quote[1])
                total_price += (price * amount)
                total_amount += amount
                if (total_price >= fiat_amount):
                    avg_price = total_price / total_amount
                    if toprint:
                        print("{:0.3f} {} {} avg for {} fiat on {}".format(avg_price, pair.upper(), bidask.upper(),
                                                                       fiat_amount, exchange.upper()))
                        print("Req/Response %s secs" % (time.time() - start))
                        print("Finish: {}".format(getDtUtcnow()))
                    arb_prices[exchange][getTickerID(pair)][getAskOrBid(bidask)+'price'] = avg_price
                    arb_prices[exchange][getTickerID(pair)][getAskOrBid(bidask)+'ts'] = time.time()

                    return avg_price
        elif ex == e:
            for quote in json.loads(ob.content)[pair][bidask]:
                price = float(quote[0])
                amount = float(quote[1])
                total_price += (price * amount)
                total_amount += amount
                if (total_price >= fiat_amount):
                    avg_price = total_price / total_amount
                    if toprint:
                        print("{:0.3f} {} {} avg for {} fiat on {}".format(avg_price, pair.upper(), bidask.upper(),
                                                                       fiat_amount, exchange.upper()))
                        print("Req/Response %s secs" % (time.time() - start))
                        print("Finish: {}".format(getDtUtcnow()))
                    arb_prices[exchange][getTickerID(pair)][getAskOrBid(bidask) + 'price'] = avg_price
                    arb_prices[exchange][getTickerID(pair)][getAskOrBid(bidask) + 'ts'] = time.time()

                    return avg_price
        else:
            print("Req/Response %s secs" % (time.time() - start))
            return ""  # None


# print(P.returnOrderBook('USDT_XRP'))

# getAvgPrice(p, 'USDT_XRP', BIDS)
# getAvgPrice(b, 'xrpusd', ASKS)
# getAvgPrice(b, 'xrpusd', BIDS)
# getAvgPrice(b, 'xrpeur', ASKS)
# getAvgPrice(b, 'xrpeur', BIDS)
# getAvgPrice(k, 'XXRPZEUR', ASKS)
# getAvgPrice(k, 'XXRPZEUR', BIDS)
# getAvgPrice(k, 'XXRPZUSD', ASKS)
# getAvgPrice(k, 'XXRPZUSD', BIDS)
# getAvgPrice(b, 'bchusd', ASKS)
# getAvgPrice(k, 'BCHUSD', ASKS, 10000)
# getAvgPrice(b, 'ltcusd', ASKS, 10000)
# getAvgPrice(b, 'ethusd', ASKS, 10000)
# getAvgPrice(b, 'btcusd', ASKS, 10000)
# getAvgPrice(k, 'USDTZUSD', ASKS, 10000)
# getAvgPrice(k, 'USDTZUSD', BIDS, 10000)
#

async def getKrakenAskExmoBidAvg(toprint=False):
    bidask = "askbid"
    ratio ="ratio"
    ts = "ts"
    exmo_xrp_bid = getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_xrp_ask = getAvgPrice(k, getTicker(k, XRPUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_ltc_bid = getAvgPrice(e, getTicker(e, LTCUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_ltc_ask = getAvgPrice(k, getTicker(k, LTCUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_bch_bid = getAvgPrice(e, getTicker(e, BCHUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_bch_ask = getAvgPrice(k, getTicker(k, BCHUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_eth_bid = getAvgPrice(e, getTicker(e, ETHUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_eth_ask = getAvgPrice(k, getTicker(k, ETHUSD), getAsksBids(k, ASKS), 5000, False)

    xrp_ratio =(exmo_xrp_bid / kraken_xrp_ask - 1) * 100
    ltc_ratio = (exmo_ltc_bid / kraken_ltc_ask - 1) * 100
    bch_ratio = (exmo_bch_bid / kraken_bch_ask - 1) * 100
    eth_ratio = (exmo_eth_bid / kraken_eth_ask - 1) * 100

    if arb_prices[k + e][bidask][XRPUSD][ratio] is None and not xrp_ratio is None:
        arb_prices[k + e][bidask][XRPUSD][ratio] = xrp_ratio
        if (xrp_ratio >= 3): print("{}: {}% to [sell E, buy K] [{}] ".format(datetime.now(), xrp_ratio, XRPUSD))
    if (xrp_ratio >= 3 and xrp_ratio >= arb_prices[k + e][bidask][XRPUSD][ratio] + 0.3) and not xrp_ratio is None:
        print("{}: {}% to [sell E, buy K] [{}] ".format(datetime.now(), xrp_ratio, XRPUSD))
        arb_prices[k + e][bidask][XRPUSD][ratio] = xrp_ratio
        arb_prices[k + e][bidask][XRPUSD][ts] = time.time

    if arb_prices[k + e][bidask][LTCUSD][ratio] is None and not ltc_ratio is None:
        arb_prices[k + e][bidask][LTCUSD][ratio] = ltc_ratio
        if (ltc_ratio >= 3): print("{}: {}% to [sell E, buy K] [{}] ".format(datetime.now(), ltc_ratio, LTCUSD))
    if (ltc_ratio >= 3 and ltc_ratio >= arb_prices[k + e][bidask][LTCUSD][ratio] + 0.3 and not ltc_ratio is None):
        print("{}: {}% to [sell E, buy K] [{}] ".format(datetime.now(), ltc_ratio, LTCUSD))
    arb_prices[k + e][bidask][LTCUSD][ratio] = ltc_ratio
    arb_prices[k + e][bidask][LTCUSD][ts] = time.time()

    if arb_prices[k + e][bidask][BCHUSD][ratio] is None and not bch_ratio is None:
        arb_prices[k + e][bidask][BCHUSD][ratio] = xrp_ratio
        if (bch_ratio >= 3): print("{}: {}% to [sell E, buy K] [{}] ".format(datetime.now(), bch_ratio, BCHUSD))
    if (bch_ratio >= 3 and bch_ratio >= arb_prices[k + e][bidask][BCHUSD][ratio] + 0.3 and not bch_ratio is None):
        print("{}: {}% to [sell E, buy K] [{}] ".format(datetime.now(), bch_ratio, BCHUSD))
    arb_prices[k + e][bidask][BCHUSD][ratio] = bch_ratio
    arb_prices[k + e][bidask][BCHUSD][ts] = time.time()

    if arb_prices[k + e][bidask][ETHUSD][ratio] is None and not eth_ratio is None:
        arb_prices[k + e][bidask][ETHUSD][ratio] = eth_ratio
        if (eth_ratio >= 3): print("{}: {}% to [sell E, buy K] [{}] ".format(datetime.now(), eth_ratio, ETHUSD))
    if (eth_ratio >= 3 and eth_ratio >= arb_prices[k + e][bidask][ETHUSD][ratio] + 0.3 and not eth_ratio is None):
        print("{}: {}% to [sell E, buy K] [{}] ".format(datetime.now(), eth_ratio, ETHUSD))
    arb_prices[k + e][bidask][ETHUSD][ratio] = eth_ratio
    arb_prices[k + e][bidask][ETHUSD][ts] = time.time()


async def getKrakenBidExmoAskAvg(toprint=False):
    bidask = "bidask"
    ratio ="ratio"
    ts = "ts"
    exmo_xrp_ask = getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_xrp_bid = getAvgPrice(k, getTicker(k, XRPUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_ltc_ask = getAvgPrice(e, getTicker(e, LTCUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_ltc_bid = getAvgPrice(k, getTicker(k, LTCUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_bch_ask = getAvgPrice(e, getTicker(e, BCHUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_bch_bid = getAvgPrice(k, getTicker(k, BCHUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_eth_ask = getAvgPrice(e, getTicker(e, ETHUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_eth_bid = getAvgPrice(k, getTicker(k, ETHUSD), getAsksBids(k, ASKS), 5000, False)

    xrp_ratio =(exmo_xrp_ask / kraken_xrp_bid - 1) * 100
    ltc_ratio = (exmo_ltc_ask / kraken_ltc_bid - 1) * 100
    bch_ratio = (exmo_bch_ask / kraken_bch_bid - 1) * 100
    eth_ratio = (exmo_eth_ask / kraken_eth_bid - 1) * 100

    if arb_prices[k + e][bidask][XRPUSD][ratio] is None and not xrp_ratio is None:
        arb_prices[k + e][bidask][XRPUSD][ratio] = xrp_ratio
        if (xrp_ratio <= 1): print("{}: {}% to [sell K, buy E] [{}] ".format(datetime.now(), xrp_ratio, XRPUSD))
    if(xrp_ratio <= 1 and xrp_ratio <= arb_prices[k + e][bidask][XRPUSD][ratio] - 0.3) and not xrp_ratio is None:
        print("{}: {}% to [sell K, buy E] [{}] ".format(datetime.now(), xrp_ratio, XRPUSD))
    arb_prices[k + e][bidask][XRPUSD][ratio] = xrp_ratio
    arb_prices[k + e][bidask][XRPUSD][ts] = time.time()

    if arb_prices[k + e][bidask][LTCUSD][ratio] is None and not ltc_ratio is None:
        arb_prices[k + e][bidask][LTCUSD][ratio] = ltc_ratio
        if (ltc_ratio <= 1): print("{}: {}% to [sell K, buy E] [{}] ".format(datetime.now(), ltc_ratio, LTCUSD))
    if (ltc_ratio <= 1 and ltc_ratio <= arb_prices[k + e][bidask][LTCUSD][ratio] - 0.3) and not ltc_ratio is None:
        print("{}: {}% to [sell K, buy E] [{}] ".format(datetime.now(), ltc_ratio, LTCUSD))
    arb_prices[k + e][bidask][LTCUSD][ratio] = ltc_ratio
    arb_prices[k + e][bidask][LTCUSD][ts] = time.time()

    if arb_prices[k + e][bidask][BCHUSD][ratio] is None and not bch_ratio is None:
        arb_prices[k + e][bidask][BCHUSD][ratio] = bch_ratio
        if (bch_ratio <= 1): print("{}: {}% to [sell K, buy E] [{}] ".format(datetime.now(), bch_ratio, BCHUSD))
    if (bch_ratio <= 1 and bch_ratio <= arb_prices[k + e][bidask][BCHUSD][ratio] - 0.3) and not bch_ratio is None:
        print("{}: {}% to [sell K, buy E] [{}] ".format(datetime.now(), bch_ratio, BCHUSD))
    arb_prices[k + e][bidask][BCHUSD][ratio] = bch_ratio
    arb_prices[k + e][bidask][BCHUSD][ts] = time.time()

    if arb_prices[k + e][bidask][ETHUSD][ratio] is None and not eth_ratio is None:
        arb_prices[k + e][bidask][ETHUSD][ratio] = eth_ratio
        if (eth_ratio <= 1): print("{}: {}% to [sell K, buy E] [{}] ".format(datetime.now(), eth_ratio, ETHUSD))
    if (eth_ratio <= 1 and eth_ratio <= arb_prices[k + e][bidask][ETHUSD][ratio] - 0.3) and not eth_ratio is None:
        print("{}: {}% to [sell K, buy E] [{}] ".format(datetime.now(), eth_ratio, ETHUSD))
    arb_prices[k + e][bidask][ETHUSD][ratio] = eth_ratio
    arb_prices[k + e][bidask][ETHUSD][ts] = time.time()


async def getKrakenBidExmoBidAvg(toprint=False):
    bidask = "bidbid"
    ratio ="ratio"
    ts = "ts"
    exmo_xrp_bid = getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_xrp_bid = getAvgPrice(k, getTicker(k, XRPUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_ltc_bid = getAvgPrice(e, getTicker(e, LTCUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_ltc_bid = getAvgPrice(k, getTicker(k, LTCUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_bch_bid = getAvgPrice(e, getTicker(e, BCHUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_bch_bid = getAvgPrice(k, getTicker(k, BCHUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_eth_bid = getAvgPrice(e, getTicker(e, ETHUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_eth_bid = getAvgPrice(k, getTicker(k, ETHUSD), getAsksBids(k, ASKS), 5000, False)

    xrp_ratio =(exmo_xrp_bid / kraken_xrp_bid - 1) * 100
    ltc_ratio = (exmo_ltc_bid / kraken_ltc_bid - 1) * 100
    bch_ratio = (exmo_bch_bid / kraken_bch_bid - 1) * 100
    eth_ratio = (exmo_eth_bid / kraken_eth_bid - 1) * 100

    arb_prices[k + e][bidask][XRPUSD][ratio] = xrp_ratio
    arb_prices[k + e][bidask][XRPUSD][ts] = time.time()

    arb_prices[k + e][bidask][LTCUSD][ratio] = ltc_ratio
    arb_prices[k + e][bidask][LTCUSD][ts] = time.time()

    arb_prices[k + e][bidask][BCHUSD][ratio] = bch_ratio
    arb_prices[k + e][bidask][BCHUSD][ts] = time.time()

    arb_prices[k + e][bidask][ETHUSD][ratio] = eth_ratio
    arb_prices[k + e][bidask][ETHUSD][ts] = time.time()


async def getKrakenAskExmoAskAvg(toprint=False):
    bidask = "askask"
    ratio ="ratio"
    ts = "ts"
    exmo_xrp_ask = getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_xrp_ask = getAvgPrice(k, getTicker(k, XRPUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_ltc_ask = getAvgPrice(e, getTicker(e, LTCUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_ltc_ask = getAvgPrice(k, getTicker(k, LTCUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_bch_ask = getAvgPrice(e, getTicker(e, BCHUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_bch_ask = getAvgPrice(k, getTicker(k, BCHUSD), getAsksBids(k, ASKS), 5000, False)
    exmo_eth_ask = getAvgPrice(e, getTicker(e, ETHUSD), getAsksBids(e, BIDS), 5000, False)
    kraken_eth_ask = getAvgPrice(k, getTicker(k, ETHUSD), getAsksBids(k, ASKS), 5000, False)

    xrp_ratio =(exmo_xrp_ask / kraken_xrp_ask - 1) * 100
    ltc_ratio = (exmo_ltc_ask / kraken_ltc_ask - 1) * 100
    bch_ratio = (exmo_bch_ask / kraken_bch_ask - 1) * 100
    eth_ratio = (exmo_eth_ask / kraken_eth_ask - 1) * 100

    arb_prices[k + e][bidask][XRPUSD][ratio] = xrp_ratio
    arb_prices[k + e][bidask][XRPUSD][ts] = time.time()

    arb_prices[k + e][bidask][LTCUSD][ratio] = ltc_ratio
    arb_prices[k + e][bidask][LTCUSD][ts] = time.time()

    arb_prices[k + e][bidask][BCHUSD][ratio] = bch_ratio
    arb_prices[k + e][bidask][BCHUSD][ts] = time.time()

    arb_prices[k + e][bidask][ETHUSD][ratio] = eth_ratio
    arb_prices[k + e][bidask][ETHUSD][ts] = time.time()



#print("Start: %s" % datetime.now())
# while True:
#     try:
#         #buy k, sell e
#         getKrakenAskExmoBidAvg()
#         #sell k, buy e
#         getKrakenBidExmoAskAvg()
#         time.sleep(1)
#     except Exception as ex:
#         print(datetime.now() + " -> Exception")
#         raise ex



# exmo_xrp_bid = threading.Thread(target=getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, BIDS), 5000, True))
# kraken_xrp_ask = threading.Thread(target=getAvgPrice(k, getTicker(k, XRPUSD), getAsksBids(k, ASKS), 5000, True))
# exmo_xrp_bid.start()
# kraken_xrp_ask.start()
# exmo_xrp_bid.join()
# kraken_xrp_ask.join()

# # ticker = getTicker(e, XRPUSD)
# exmo_xrp_ask = getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, ASKS), 1000)
# exmo_xrp_ask = getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, ASKS), 3000)
# print(exmo_xrp_bid, kraken_xrp_ask)
# #str(datetime.now()))

# def wait_delay(d):
#     print("sleeping for (%d)sec" % d)
#     sleep(d)
# pool = ThreadPool(5)
# #pool.map(wait_delay, delays)

# worker1 = getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, BIDS), 5000)
# worker2 = getAvgPrice(k, getTicker(k, XRPUSD), getAsksBids(k, ASKS), 5000)

# pool.map(worker1, worker2)
# pool.wait_completion()

async def task1(future):
    res = getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, BIDS), 5000) #worker1
    #future.set_result('Future is done! - {}'.format(res))

async def task2(future):
    res = getAvgPrice(k, getTicker(k, XRPUSD), getAsksBids(k, ASKS), 5000) #worker2
    #future.set_result('Future is done! - {}'.format(res))

def future_result(future):
    print(future.result())
    #loop.stop()


async def fetch(url, session):
    async with session.get(url) as response:
        return await response.read()


e_url1 = "https://api.exmo.com/v1/order_book/?pair={}".format(getTicker(e, XRPUSD).upper())
e_url2 = "https://api.exmo.com/v1/order_book/?pair={}".format(getTicker(e, BCHUSD).upper())

e_url3 = "api.exmo.com"
p1 = "v1/order_book/?pair={}".format(getTicker(e, XRPUSD).upper())
p2 = "v1/order_book/?pair={}".format(getTicker(e, BCHUSD).upper())

secs = 1
count = 0
async def get(url="", urls=[]):

    global count
    if len(url) is not 0 and len(urls)== 0:
        start = time.time()
        #while (time.time() - start < secs):
        while True:
            print("Start {}".format(getDtUtcnow()))
            async with ClientSession() as session:
              # async with async_timeout.timeout(5):
              async with session.get(url) as response:
                  response = await response.read()
                  count += 1
                  print("Finish {}".format(getDtUtcnow()))
                  print(response)

                  #return response
    else:
        if len(urls) is 0: return
        start = time.time()
        #while (time.time() - start < secs):
        for uri in urls:
            print("Start {}".format(getDtUtcnow()))
            async with ClientSession() as session:
                # async with async_timeout.timeout(5):
                async with session.get(uri) as response:
                    response = await response.read()
            count += 1
            print("Finish {}".format(getDtUtcnow()))


async def get2(url, params, conn=None):
    print("Start {}".format(getDtUtcnow()))
    if conn is None: conn = http.client.HTTPConnection(url)
    conn.request("GET", "/%s" % params)
    res = conn.getresponse()
    print(res.status, res.reason)
    print('Data', str(res.read()))
    print("Finish {}".format(getDtUtcnow()))
    #conn.close()


def get3(url, params):
    print("Start {}".format(getDtUtcnow()))
    #if conn is None:
    conn = http.client.HTTPConnection(url)
    conn.request("GET", "/%s" % params)
    res = conn.getresponse()
    print(res.status, res.reason)
    print('Data', str(res.read()))
    print("Finish {}".format(getDtUtcnow()))
    #conn.close()



async def a(url,params):
    res = await get2(url, params)
    #await asyncio.sleep(1)
    #future.set_result('Future is done!')




async def task3():
    print(getDtUtcnow())
    await getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, BIDS), 5000) #worker1
    #t = Thread(target=getAvgPrice(e, getTicker(e, XRPUSD), getAsksBids(e, BIDS), 5000))
    #t = Thread(target=get3(e_url1, p1))
    # t.daemon = True
    # t.start()
    #t.join()

async def task4():
    print(getDtUtcnow())
    await getAvgPrice(k, getTicker(k, XRPUSD), getAsksBids(k, ASKS), 5000) #worker2
    #t = Thread(target=getAvgPrice(k, getTicker(k, XRPUSD), getAsksBids(k, ASKS), 5000))
    #t = Thread(target=get3(e_url3, p2))
    # t.daemon = True
    # t.start()
    # #t.join()



future = asyncio.Future()
#future.add_done_callback(future_result)
loop = asyncio.get_event_loop()
#loop.run_until_complete(worker1)
#loop.run_until_complete(worker2)

# asyncio.ensure_future(task1(future))
# asyncio.ensure_future(task2(future))
# try:
#     loop.run_forever()
# finally:
#     loop.close()

tasks = []
# tasks.append(task1(future))
# tasks.append(task2(future))
tasks.append(task3())
tasks.append(task4())
loop.run_until_complete(asyncio.gather(*tasks))
loop.close()
##asyncio.ensure_future(asyncio.gather(*tasks))
##loop.run_forever()

#tasks.append(task3())
#tasks.append(task4())
#loop.run_until_complete(asyncio.gather(*tasks)) #object float can't be used in 'await' expression
#asyncio.ensure_future(asyncio.gather(*tasks)) #150ms #object float can't be used in 'await' expression
#loop.run_forever()





# future - asyncio.Future()
# tasks = []
# tasks.append(worker1)
# tasks.append(worker2)
# res = loop.run_until_complete(asyncio.gather(*tasks))

# async def run():
#     #loop = asyncio.get_event_loop()
#     futures = [
#         loop.run_in_executor(None, worker1),
#         loop.run_in_executor(None, worker2)
#             #for i in range(20)
#         ]
#     for response in await asyncio.gather(*futures):
#         pass
# loop = asyncio.get_event_loop()
# loop.run_until_complete(run())


# loop = asyncio.get_event_loop()
# loop.run_until_complete(get(e_url1))
# loop.run_until_complete(get(e_url2))
# #loop.run_until_complete(get("", [e_url1, e_url2]))
# loop.close()

#200ml Best till now
#loop = asyncio.get_event_loop() #optional
# tasks = []
# tasks.append(get(e_url1))
# tasks.append(get(e_url2))
# #res = loop.run_until_complete(asyncio.gather(*tasks))
# #loop.close()
# asyncio.ensure_future(asyncio.gather(*tasks)) #150ms
# loop.run_forever()


# loop = asyncio.get_event_loop()
# future = asyncio.Future()
# asyncio.ensure_future(a(future, e_url3, p1))
# asyncio.ensure_future(a(future, e_url3, p2))
# loop.run_until_complete(future)
# #print(future.result())
# loop.close()

# tasks = []
# tasks.append(a(e_url3, p1))
# tasks.append(a(e_url3, p2))
# res = loop.run_until_complete(asyncio.gather(*tasks))

# conn = http.client.HTTPSConnection(e_url3)
# conn.request("GET", "/%s" %p1)
# r1 = conn.getresponse()
# print(r1.status, r1.reason)
# print(r1.read())

# conn = http.client.HTTPSConnection(e_url3)
# conn2 = http.client.HTTPSConnection(e_url3)

async def h1(u,p,conn=None):
    print("Start {}".format(getDtUtcnow()))
    if conn is None: conn = http.client.HTTPSConnection(u)
    conn.request("GET", "/%s" %p)
    r = conn.getresponse()
    print(r.status, r.reason)
    #print(r.read())
    print("Finish {}".format(getDtUtcnow()))



# loop = asyncio.get_event_loop()
# loop.run_until_complete(h1(e_url3, p1, conn))
# loop.run_until_complete(h1(e_url3, p2, conn2))
# loop.close()
# loop = asyncio.get_event_loop()
# future = asyncio.Future()
# asyncio.ensure_future(h1(e_url3, p1, conn))
# asyncio.ensure_future(h1(e_url3, p2, conn2))
# loop.run_until_complete(future)
# #print(future.result())
# loop.close()


#230ms
# loop = asyncio.get_event_loop()
# future = asyncio.Future()
# asyncio.ensure_future(a(future, e_url1))
# asyncio.ensure_future(a(future, e_url2))
# loop.run_until_complete(future)
# #print(future.result())
# loop.close()


# async def t(url):
#     tt = Thread(await get(url))
#     tt.daemon = True
#     tt.start()
#     tt.join()

#t1 = Thread(get(e_url1))
#t2 = Thread(get(e_url2))
#t1.daemon = True
#t2.daemon = True
#t1.start()
#t2.start()
#t1.join()
#t2.join()



# tasks = []
# tasks.append(t(e_url1))
# tasks.append(t(e_url2))
# res = loop.run_until_complete(asyncio.gather(*tasks))

#while True:

###########################################################################################################################################################################

# print("######################## XRP #################################")
# exmo_xrp_ask = getAvgPrice(e, 'XRP_USD', "ask", 3000)
# exmo_xrp_bid = getAvgPrice(e, 'XRP_USD', "bid", 3000)
# kraken_xrp_ask = getAvgPrice(k, 'XXRPZUSD', ASKS, 3000)
# kraken_xrp_bid = getAvgPrice(k, 'XXRPZUSD', BIDS, 3000)
# print("")
# print("Exmo sell/buy Kraken: {:0.2f}%".format((exmo_xrp_bid / kraken_xrp_ask - 1) * 100))
# print("Exmo buy/sell Kraken: {:0.2f}%".format((1 - exmo_xrp_ask / kraken_xrp_bid) * 100))
# print("Exmo sell/sell Kraken: {:0.2f}%".format((exmo_xrp_bid / kraken_xrp_bid - 1) * 100))
# print("Exmo buy/buy Kraken: {:0.2f}%".format((1 - exmo_xrp_ask / kraken_xrp_ask) * 100))
# print("")
#
# print("######################## USDT #################################")
# exmo_usdt_ask = getAvgPrice(e, 'USDT_USD', "ask", 1000)  # TODO NO LIQUIDITY
# exmo_usdt_bid = getAvgPrice(e, 'USDT_USD', "bid", 3000)  # TODO NO LIQUIDITY
# kraken_usdt_ask = getAvgPrice(k, 'USDTZUSD', ASKS, 5000)
# kraken_usdt_bid = getAvgPrice(k, 'USDTZUSD', BIDS, 5000)
# print("")
# print("Exmo sell/buy Kraken: {:0.2f}%".format((exmo_usdt_bid / kraken_usdt_ask - 1) * 100))
# print("Exmo buy/sell Kraken: {:0.2f}%".format((1 - exmo_usdt_ask / kraken_usdt_bid) * 100))
# # print("Exmo sell/sell Kraken: {:0.2f}%".format((exmo_usdt_bid / kraken_usdt_bid - 1) * 100))
# # print("Exmo buy/buy Kraken: {:0.2f}%".format((1 - exmo_usdt_ask / kraken_usdt_ask) * 100))
# print("Kraken sell: {:0.2f}%".format(kraken_usdt_bid))
# print("Kraken buy : {:0.2f}%".format(kraken_usdt_ask))
# print("")
#
# print("######################## LTC #################################")
# exmo_ltc_ask = getAvgPrice(e, 'LTC_USD', "ask", 3000)
# exmo_ltc_bid = getAvgPrice(e, 'LTC_USD', "bid", 3000)
# kraken_ltc_ask = getAvgPrice(k, 'XLTCZUSD', ASKS, 3000)
# kraken_ltc_bid = getAvgPrice(k, 'XLTCZUSD', BIDS, 3000)
# print("")
# print("Exmo sell/buy Kraken: {:0.2f}%".format((exmo_ltc_bid / kraken_ltc_ask - 1) * 100))
# print("Exmo buy/sell Kraken: {:0.2f}%".format((1 - exmo_ltc_ask / kraken_ltc_bid) * 100))
# print("Exmo sell/sell Kraken: {:0.2f}%".format((exmo_ltc_bid / kraken_ltc_bid - 1) * 100))
# print("Exmo buy/buy Kraken: {:0.2f}%".format((1 - exmo_ltc_ask / kraken_ltc_ask) * 100))
# print("")
#
# print("######################## BCH #################################")
# exmo_bch_ask = getAvgPrice(e, 'BCH_USD', "ask", 3000)
# exmo_bch_bid = getAvgPrice(e, 'BCH_USD', "bid", 3000)
# kraken_bch_ask = getAvgPrice(k, 'BCHUSD', ASKS, 3000)
# kraken_bch_bid = getAvgPrice(k, 'BCHUSD', BIDS, 3000)
# print("")
# print("Exmo sell/buy Kraken: {:0.2f}%".format((exmo_bch_bid / kraken_bch_ask - 1) * 100))
# print("Exmo buy/sell Kraken: {:0.2f}%".format((1 - exmo_bch_ask / kraken_bch_bid) * 100))
# print("Exmo sell/sell Kraken: {:0.2f}%".format((exmo_bch_bid / kraken_bch_bid - 1) * 100))
# print("Exmo buy/buy Kraken: {:0.2f}%".format((1 - exmo_bch_ask / kraken_bch_ask) * 100))
# print("")
#
# print("#########################################################")

###########################################################################################################################################################################

# USD/RUB 58.06
# 54.40 USD/RUB ASKS avg for 10000 fiat on EXMO #6.66%
# 54.20 USD/RUB BIDS avg for 10000 fiat on EXMO #-7%


# print(dir(P))

# p = Poloniex()
# print(p('returnOrderBook')['BTC_ETH'])
# print(p('returnTicker')['USDT_XRP'])


# print(P.returnOrderBook('USDT_XRP'))
#
#
# #response = k.query_public('Depth', {'pair': 'XXBTZUSD', 'count': '20'})
# response = k.query_public('Depth', {'pair': 'XRPUSD', 'count': '20'})
# pprint.pprint(response)
# print(time.time())
#
#
# public_client = bitstamp.client.Public()
# #print(public_client.ticker()['volume'])
# #public_client.ticker("xrp", "usd")
# print(public_client.order_book(True, "xrp", "usd"))
# print(time.time())
#

# public_client.order_book(True, "xrp", "usd")['asks']
# response['result']['XXRPZUSD']['bids']
