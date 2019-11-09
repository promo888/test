#
# from lxml import html
#
# from xml.etree import ElementTree
# import requests
#
# from time import sleep
#
# import json
#
# import argparse
#
# from collections import OrderedDict
#
# from time import sleep
#
#
#
# def parse(ticker):
#
#     url = "http://finance.yahoo.com/quote/%s?p=%s " %(ticker ,ticker)
#
#     response = requests.get(url, verify=False)
#
#     print ("Parsing %s " %(url))
#
#     sleep(4)
#
#     parser = html.fromstring(response.text)
#
#     summary_table = parser.xpath('//div[contains(@data-test,"summary-table")]//tr')
#
#     summary_data = OrderedDict()
#
#     other_details_json_link = "https://query2.finance.yahoo.com/v10/finance/quoteSummary/{0}?formatted=true&lang=en-US&region=US&modules=summaryProfile%2CfinancialData%2CrecommendationTrend%2CupgradeDowngradeHistory%2Cearnings%2CdefaultKeyStatistics%2CcalendarEvents&corsDomain=finance.yahoo.com".format \
#         (ticker)
#
#     summary_json_response = requests.get(other_details_json_link)
#
#     try:
#
#         json_loaded_summary =  json.loads(summary_json_response.text)
#
#         print('json_loaded_summary', json_loaded_summary)
#
#         y_Target_Est = json_loaded_summary["quoteSummary"]["result"][0]["financialData"]["targetMeanPrice"]['raw']
#
#         earnings_list = json_loaded_summary["quoteSummary"]["result"][0]["calendarEvents"]['earnings']
#
#         eps = json_loaded_summary["quoteSummary"]["result"][0]["defaultKeyStatistics"]["trailingEps"]['raw']
#
#         datelist = []
#
#         for i in earnings_list['earningsDate']:
#
#             datelist.append(i['fmt'])
#
#         earnings_date = ' to '.join(datelist)
#
#         for table_data in summary_table:
#
#             raw_table_key = table_data.xpath('.//td[contains(@class,"C(black)")]//text()')
#
#             raw_table_value = table_data.xpath('.//td[contains(@class,"Ta(end)")]//text()')
#
#             table_key = ''.join(raw_table_key).strip()
#
#             table_value = ''.join(raw_table_value).strip()
#
#             summary_data.update({table_key :table_value})
#
#         summary_data.update \
#             ({'1y Target Est' :y_Target_Est ,'EPS (TTM)' :eps ,'Earnings Date' :earnings_date ,'ticker' :ticker
#              ,'url' :url})
#
#         return summary_data
#
#     except:
#
#         print ("Failed to parse json response")
#
#         return {"error" :"Failed to parse json response"}
#
#
#
# def get_proxies():
#
#     url = 'https://free-proxy-list.net/'
#     response = requests.get(url)
#     parser = ElementTree.fromstring(response.text)
#     proxies = set()
#
#     for i in parser.xpath('//tbody/tr')[:10]:
#
#         if i.xpath('.//td[7][contains(text(),"yes")]'):
#
#             # Grabbing IP and corresponding PORT
#
#             proxy = ":".join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
#
#             proxies.add(proxy)
#
#     return proxies
#
#
#
# if __name__=="__main__":
#     proxies = get_proxies()
#     print('Free Proxies:', proxies)
#     proxy_pool = cycle(proxies)
#     url = 'https://httpbin.org/ip'
#
#     # for i in range(1,11):
#
#     #    proxy = next(proxy_pool)
#
#     # print("Request #%d" % i)
#
#     # proxy = next(proxy_pool)
#
#     # try:
#
#     #    response = requests.get(url,proxies={"http": proxy, "https": proxy})
#
#     #    print(response.json())
#
#     # except:
#
#     # Most free proxies will often get connection errors. You will have retry the entire request using another proxy to work.
#
#     # We will just skip retries as its beyond the scope of this tutorial and we are only downloading a single url
#
#     #    print("Skipping. Connnection error")
#
#     sys.exit(0)  # 'End Proxies Test')
#
#
#
#     ################################
#
#     argparser = argparse.ArgumentParser()
#
#     argparser.add_argument('ticker' ,help = '')
#
#     args = argparser.parse_args()
#
#     ticker = "GDX" #args.ticker
#
#     print ("Fetching data for %s " %(ticker))
#
#     scraped_data = parse(ticker)
#
#     print ("Writing data to output file")
#
#     with open('%s-summary.json ' %(ticker) ,'w') as fp:
#
#         json.dump(scraped_data ,fp ,indent = 4)
#
# from lxml import html
#
# import requests
#
# from time import sleep
#
# import json
#
# import argparse
#
# from collections import OrderedDict
#
# from time import sleep
#
#
# def parse(ticker):
#     url = "http://finance.yahoo.com/quote/%s?p=%s " % (ticker, ticker)
#
#     response = requests.get(url, verify=False)
#
#     print("Parsing %s " % (url))
#
#     sleep(4)
#
#     parser = html.fromstring(response.text)
#
#     summary_table = parser.xpath('//div[contains(@data-test,"summary-table")]//tr')
#
#     summary_data = OrderedDict()
#
#     other_details_json_link = "https://query2.finance.yahoo.com/v10/finance/quoteSummary/{0}?formatted=true&lang=en-US&region=US&modules=summaryProfile%2CfinancialData%2CrecommendationTrend%2CupgradeDowngradeHistory%2Cearnings%2CdefaultKeyStatistics%2CcalendarEvents&corsDomain=finance.yahoo.com".format \
#         (ticker)
#
#     summary_json_response = requests.get(other_details_json_link)
#
#     try:
#
#         json_loaded_summary = json.loads(summary_json_response.text)
#
#         print('json_loaded_summary', json_loaded_summary)
#
#         y_Target_Est = json_loaded_summary["quoteSummary"]["result"][0]["financialData"]["targetMeanPrice"]['raw']
#
#         earnings_list = json_loaded_summary["quoteSummary"]["result"][0]["calendarEvents"]['earnings']
#
#         eps = json_loaded_summary["quoteSummary"]["result"][0]["defaultKeyStatistics"]["trailingEps"]['raw']
#
#         datelist = []
#
#         for i in earnings_list['earningsDate']:
#             datelist.append(i['fmt'])
#
#         earnings_date = ' to '.join(datelist)
#
#         for table_data in summary_table:
#             raw_table_key = table_data.xpath('.//td[contains(@class,"C(black)")]//text()')
#
#             raw_table_value = table_data.xpath('.//td[contains(@class,"Ta(end)")]//text()')
#
#             table_key = ''.join(raw_table_key).strip()
#
#             table_value = ''.join(raw_table_value).strip()
#
#             summary_data.update({table_key: table_value})
#
#         summary_data.update \
#             ({'1y Target Est': y_Target_Est, 'EPS (TTM)': eps, 'Earnings Date': earnings_date, 'ticker': ticker
#                  , 'url': url})
#
#         return summary_data
#
#     except:
#
#         print("Failed to parse json response")
#
#         return {"error": "Failed to parse json response"}
#
#
# def get_proxies():
#     url = 'https://free-proxy-list.net/'
#
#     response = requests.get(url)
#
#     parser = fromstring(response.text)
#
#     proxies = set()
#
#     for i in parser.xpath('//tbody/tr')[:10]:
#
#         if i.xpath('.//td[7][contains(text(),"yes")]'):
#             # Grabbing IP and corresponding PORT
#
#             proxy = ":".join([i.xpath('.//td[1]/text()')[0], i.xpath('.//td[2]/text()')[0]])
#
#             proxies.add(proxy)
#
#     return proxies
#
#
# if __name__=="__main__":
#
#     proxies = get_proxies()
#
#     print('Free Proxies:', proxies)
#
#     proxy_pool = cycle(proxies)
#
#     url = 'https://httpbin.org/ip'
#
#     # for i in range(1,11):
#
#     #    proxy = next(proxy_pool)
#
#     # print("Request #%d" % i)
#
#     # proxy = next(proxy_pool)
#
#     # try:
#
#     #    response = requests.get(url,proxies={"http": proxy, "https": proxy})
#
#     #    print(response.json())
#
#     # except:
#
#     # Most free proxies will often get connection errors. You will have retry the entire request using another proxy to work.
#
#     # We will just skip retries as its beyond the scope of this tutorial and we are only downloading a single url
#
#     #    print("Skipping. Connnection error")
#
#     sys.exit(0)  # 'End Proxies Test')
#
#     ################################
#
#     argparser = argparse.ArgumentParser()
#
#     argparser.add_argument('ticker', help='')
#
#     args = argparser.parse_args()
#
#     ticker = args.ticker
#
#     print("Fetching data for %s " % (ticker))
#
#     scraped_data = parse(ticker)
#
#     print("Writing data to output file")
#
#     with open('%s-summary.json ' % (ticker), 'w') as fp:
#         json.dump(scraped_data, fp, indent=4)


import numpy as np
import scipy as sp
import keras as kr
import matplotlib as mp
import pandas as pd
import os

from tensorboard.notebook import display


def error(f, х, у):
    return sp.sum((f(x)-y)**2)


def polyfit(npx, npy, dim, full_mode=True, print_fit=True):
    fpl, residuals, rank, sv, rcond = sp.polyfit(npx, npy, dim, full=full_mode)
    if print_fit:
        print("Model %s parameters: %s" % (dim, fpl))
        print("%s Residuals: %s" % (dim, residuals))
        fe = sp.poly1d(fpl)
        error_fit = error(fe, npx, npy)
        print("%s Error: %s, avg: %s" % (dim, error_fit, error_fit/len(npy)))
    return fpl, residuals, rank, sv, rcond



# ticker = "GLD"
# #f = pd.read_csv("%s/%s.csv" % (os.pardir, ticker), sep=',') #, skiprows=[0, 1])
# # x = f.Date[1:]
# # y = f.changePercent[1:]
# from numpy import genfromtxt
# f = genfromtxt("%s/%s.csv" % (os.pardir, ticker), delimiter=',')
# x = f[:, 0][-100:-80] #[2:] [-20:]
# y = f[:, 8][-100:-80] #[2:] [-20:]
# print("%s tested points" % len(y))
#
# for i in range(1, 5):
#     npx = [i for i in range(len(x))]
#     assert len(npx) == len(y)
# #    polyfit(np.array(npx), np.array((y.replace("\n", ""))), dim=i)
#     polyfit(x, y, dim=i)
#
# from scipy.optimize import fsolve #todo solve for extrapolation/prediction
# fbt2 = sp.poly1d(sp.polyfit(x, y, 2))
# reached_max = fsolve(fbt2 - 20, x[0]+20)
# print("5percent move will be reached in %s " % reached_max[0])
#
#
# from sklearn.datasets import load_iris
# data = load_iris()
#
#
from yahoo_historical import Fetcher
ticker = "GLD"
##data = Fetcher(ticker, [2007, 1, 1], [2019, 10, 1]) #GLD
##history_data = data.getHistorical()
# history_data['change'] = history_data['Close'].diff()
# #history_data['changePercent'] = history_data['Close'].
##eodPrices = history_data['Close']
##history_data['changePercent'] = eodPrices.pct_change() * 100
# history_data['Date'] = pd.to_datetime(history_data['Date'])
# print(history_data.change)
# print(history_data.changePercent)
# print(history_data['Date'][0].dayofweek)
# import os
#history_data = history_data[~history_data["changePercent"].is]
##print("Saving to %s/%s.csv" % (os.pardir, ticker))
# #pd.read_csv("%s/%s.csv" % (os.pardir, ticker), skiprows=[0, 1])
##history_data.to_csv("%s/%s.csv" % (os.pardir, ticker))
# history_data.to_html("%s/%s.html" % (os.pardir, ticker))

def saveTicker(ticker, from_date_ymd_tuple, to_date_ymd_tuple, save_to_file, file_parent_dir=None):
    data = Fetcher(ticker, [from_date_ymd_tuple[0], from_date_ymd_tuple[1], from_date_ymd_tuple[2]],
                   [to_date_ymd_tuple[0], to_date_ymd_tuple[1], to_date_ymd_tuple[2]])
    history_data = data.getHistorical()
    save_dir = file_parent_dir if not file_parent_dir is None else os.pardir
    print("Saving to %s/%s.csv" % (save_dir, ticker))
    history_data.to_csv("%s/%s.csv" % (os.pardir, ticker))




import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pandas.plotting import lag_plot
from pandas import datetime
from statsmodels.tsa.arima_model import ARIMA
from statsmodels.tsa.arima_model import ARIMAResults
from sklearn.metrics import mean_squared_error
from pandas.plotting import autocorrelation_plot

def smape_kun(y_true, y_pred):
    return np.mean((np.abs(y_pred - y_true) * 200 / (np.abs(y_pred) + np.abs(y_true))))

ticker = "GLD"
step = 1 #20

df = pd.read_csv("../%s.csv" % ticker).fillna(0)
# #print(df.head())
# plt.figure(figsize=(10, 10))
# lag_plot(df['Close'], lag=5)
# plt.title('%s Autocorrelation plot' % ticker)
# #plt.show()
#
def parser(x):
    return datetime.strptime('190'+x, '%d-%m-%Y')


###pd.plotting.autocorrelation_plot(df["Close"].pct_change() * 100)
df["close_pct_change"] = df["Close"].pct_change() #1st element is pd.isna == np.nan
close_up_down = []
for p in df["close_pct_change"]:
    if str(p) == 'nan':
        close_up_down.append(np.nan) #bc np.nan_to_num == 0
        continue
    if p > 0.002:
        close_up_down.append(1)
    else:
        close_up_down.append(1)
df["close_up_down"] = close_up_down


predict_field = "Close" # close_pct_change
pd.plotting.autocorrelation_plot(df[predict_field]) #positive correlation 1.25-5lags > 99%
##plt.show()
#df = df[:-1000]
##pd.plotting.autocorrelation_plot(df["Close"].pct_change() * 100) #TODO? why no autocorrelation on pct_changes?
#plt.show()
#last peak downup swing 0.988
train_data, test_data = df[1:int(len(df)*0.995)], df[int(len(df)*0.995):] #0.8
print("len train_data", len(train_data))
startTime = datetime.now()
train_ar = train_data[predict_field].values ##Close
test_ar = test_data[predict_field].values ##Close
history = [x for x in train_ar]
#print(type(history))
predictions = list()
test_predictions_diff = list()
for t in range(len(test_ar)):
    model = ARIMA(history, order=(2, 1, 0)) #3, 1, 0  5.1.0
    model_fit = model.fit(disp=0)
    output = model_fit.forecast() ##steps=1 one-step out-of sample forecast ? default -forecast = model_fit.forecast()[0]
    yhat = output[0]
    #print("yhat", yhat, "test_ar[t]", test_ar[t])
    predictions.append(yhat)
    test_predictions_diff.append((yhat[0]-test_ar[t])/test_ar[t]*100)
    obs = test_ar[t]
    #print('predicted=%f, expected=%f' % (yhat, obs))
    history.append(obs)
    if t == len(test_ar)-1:
        # save model
        # model_fit.save('model.pkl')
        # # load model
        # loaded = ARIMAResults.load('model.pkl')
        print("Saving ARIMA model for %s" % ticker)
        model_fit.save('%s_arima_model3.pkl' % ticker)
        # print("Predicting future %s days/periods" % dummy_period)
        # dummy_predictions = model_fit.predict(len(train_data)+len(test_data), len(train_data)+len(test_data) + dummy_period, typ='levels')

#TODO change back from close_pct_values to original "Close" field
dummy_period = 3000
dummy_predictions = list()
model2 = ARIMA(history, order=(3, 1, 0)) #include test data - without it predicted on testData
model_fit2 = model2.fit(disp=0)
dummy_predictions = model_fit2.predict(len(history), len(history) + 16, typ='levels')
dummy_forecasts = model_fit2.forecast(steps=20)
error = mean_squared_error(test_ar, predictions)
print("Next Day Prediction for %s days" % len(predictions))
print('Testing Mean Squared Error: %.3f' % error)
error2 = smape_kun(test_ar, predictions)
print('Symmetric mean absolute percentage error: %.3f' % error2)

plt.figure(figsize=(12, 7))
plt.plot(df[predict_field], 'green', color='blue', label='Training Data')
plt.plot(test_data.index, predictions, color='green', marker='x', linestyle='dashed', label='Predicted Price')
plt.plot(test_data.index, dummy_predictions, color='orange', marker='x', linestyle='dashed', label='Dummy Predicted Price')
plt.plot(test_data.index, test_data[predict_field], color='red',  marker='o', label='Actual Price')
#plt.plot([i for range(3189 ,4189)], dummy_predictions, color='blue', marker='v', linestyle='dashed', label='Dummy %sd Price' % dummy_period)
plt.title('%s Prices Prediction' % ticker)
plt.xlabel('Dates')
plt.ylabel('Prices')
plt.xticks(np.arange(0, len(train_data)+len(test_data), step), df['Date'][0:len(train_data)+len(test_data):step])
plt.legend()
print("Test took: ",  datetime.now()-startTime)
#plt.show()
print("dummy_predictions", dummy_predictions)
#print(dummy_forecasts[0])
#print("Max Loss sMAPE error % from dummy prediction ", max(dummy_forecasts[1]))
#print("dummy_predictions", dummy_predictions)
print("Next Day Prediction for %s days" % len(predictions))
print("predictions", predictions)
print("test_predictions_diff %", (test_predictions_diff))
print("test_predictions_diff_MIN_MAX_DIF %", min(test_predictions_diff), max(test_predictions_diff))
plt.show()


# monkey patch around bug in ARIMA class
def __getnewargs__(self):
	return ((self.endog),(self.k_lags, self.k_diff, self.k_ma))
ARIMA.__getnewargs__ = __getnewargs__

# load model
#loaded = ARIMAResults.load('model.pkl')

#TODO Run 2,3lags for 50,100,200,500,1000 history training and update and refit observations
#use equation for binary advance/decline on smallest SMAPES, sMeans

#arima
#https://www.kaggle.com/hsankesara/time-series-analysis-and-forecasting-using-arima
#https://towardsdatascience.com/basic-principles-to-create-a-time-series-forecast-6ae002d177a4
#https://www.kaggle.com/leandrovrabelo/climate-change-forecast-sarima-model
#https://www.analyticsvidhya.com/blog/2018/10/predicting-stock-price-machine-learningnd-deep-learning-techniques-python/
#https://towardsdatascience.com/stock-market-analysis-using-arima-8731ded2447a
#https://machinelearningmastery.com/arima-for-time-series-forecasting-with-python/
#https://machinelearningmastery.com/make-sample-forecasts-arima-python/
#

#LSTM
#https://www.kdnuggets.com/2018/11/keras-long-short-term-memory-lstm-model-predict-stock-prices.html
#https://towardsdatascience.com/predicting-stock-price-with-lstm-13af86a74944
#
#
#
#
#


#2DO
#https://github.com/pierpaolo28/Artificial-Intelligence-Projects



from keras.models import Sequential
from keras.layers import Dense
from keras.layers import LSTM
from keras.layers import Dropout

#https://github.com/DarkKnight1991/Stock-Price-Prediction/blob/master/stock_pred_main.py



