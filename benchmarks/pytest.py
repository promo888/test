from datetime import datetime
from py.xml import html
import pytest
from selenium import webdriver

# @pytest.mark.optionalhook
# def pytest_html_results_table_header(cells):
#     cells.insert(2, html.th('Description'))
#     cells.insert(1, html.th('Time', class_='sortable time', col='time'))
#     cells.pop()
#
# @pytest.mark.optionalhook
# def pytest_html_results_table_row(report, cells):
#     cells.insert(2, html.td(report.description))
#     cells.insert(1, html.td(datetime.utcnow(), class_='col-time'))
#     cells.pop()
#
# @pytest.mark.hookwrapper
# def pytest_runtest_makereport(item, call):
#     outcome = yield
#     report = outcome.get_result()
#     report.description = str(item.function.__doc__)
#
# @pytest.mark.hookwrapper
# def pytest_runtest_makereport(item, call):
#     pytest_html = item.config.pluginmanager.getplugin('html')
#     outcome = yield
#     report = outcome.get_result()
#     extra = getattr(report, 'extra', [])
#     if report.when == 'call':
#         # always add url to report
#         extra.append(pytest_html.extras.url('http://www.example.com/'))
#         xfail = hasattr(report, 'wasxfail')
#         if (report.skipped and xfail) or (report.failed and not xfail):
#             # only add additional html on failure
#             extra.append(pytest_html.extras.html('<div>Additional HTML</div>'))
#         report.extra = extra


def sum(x1, x2):
   return x1 + x2

def test_sum():
   print('assert sum of 2+2')
   assert sum(2, 2) == 4


def test_fail():
    print('MyException')
    raise Exception

test_sum()