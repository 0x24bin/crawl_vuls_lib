#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# crawl_cve_detail


import os
import urllib2
import socket
from datetime import datetime
from random import randint
from bs4 import BeautifulSoup
from config import Config


BASE_URL = 'http://www.cvedetails.com/cve/'
log_time_out = 'missed_url.txt'


def get_missed_url():
    missed_url = []
    with open(log_time_out, 'r') as f:
        for line in f:
            missed_url.append(line)
    return missed_url

def write2log(cve_detail_url,note):
    """记录超时url"""
    with open(log_time_out, 'a+') as f:
        data = '[' + str(datetime.now()) + ']:' + '[' + note + ']:' + cve_detail_url
        missed_url = get_missed_url()
        if data not in missed_url:
            f.write(data)
            f.write('\n')

def get_html_data(cve_id):
    """根据cve_id获取相应的url响应"""

    if cve_id:
        cve_detail_url = BASE_URL + cve_id
        user_agent = Config.header_list[randint(0,len(Config.header_list)-1)]
        # proxy_ip = Config.proxy_pool[randint(0,len(Config.proxy_pool)-1)]
        print user_agent
        # print proxy_ip
        # headers = {'User-Agent' : user_agent, 'Referer' : BASE_URL}
        headers = {'User-Agent' : user_agent, "Referer": 'http://www.cvedetails/cve/'}
        request = urllib2.Request(cve_detail_url, '', headers)
        # proxy = urllib2.ProxyHandler({'http': proxy_ip})
        # opener = urllib2.build_opener(proxy)
        # urllib2.install_opener(opener)
        try:
            response = urllib2.urlopen(request, timeout=60)
            data = response.read() 
            if data:
                bsObj = BeautifulSoup(data)
                return bsObj
        except socket.timeout as e:
            write2log(cve_detail_url, str(e))
        except urllib2.HTTPError , e:
            write2log(cve_detail_url, str(e))
        except urllib2.URLError , e:
            write2log(cve_detail_url, str(e))
        except Exception as e:
            write2log(cve_detail_url, str(e))
            

def crawl_cve_detail(cve_id):
    """解析cve_id对应的响应，获取需要的字段，得到产品字典"""

    soup = get_html_data(cve_id)
    if soup:
        vulnprodstable = soup.select('table #vulnprodstable')
    else:
        vulnprodstable = None
    product_detail = {}
    if vulnprodstable:
        rows = vulnprodstable[0].find_all('tr')
        for row in rows[1:]:
            cols = row.find_all('td')
            if len(cols) == 1:
                return product_detail
            else:
                cols = [e.text.strip() for e in cols]
                if not product_detail.has_key(cols[2]):
                    product_detail[cols[2]] = {}
                    product_info = product_detail[cols[2]]
                if not product_info.has_key(cols[1]):
                    product_info[cols[1]] ={}
                    type_info = product_info[cols[1]]
                if not type_info.has_key(cols[3]):
                    type_info[cols[3]] = {}
                    subtype_info = type_info[cols[3]]
                if not subtype_info.has_key(u'version'):
                    subtype_info[u'version'] = []
                if not subtype_info.has_key(u'update'):
                    subtype_info[u'update'] = []
                # if cols[4] not in subtype_info[u'version']:
                subtype_info[u'version'].append(cols[4])
                # if cols[5] not in subtype_info[u'update']:
                subtype_info[u'update'].append(cols[5])
    return product_detail
