#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Project: crawl_cnnvd

import re
import json
from pyspider.libs.base_handler import *
from pyquery.pyquery import PyQuery
from config import Config
import cve_detail
from normalized import fuzzyfinder


class Handler(BaseHandler):
    """
    爬取cnvd漏洞库并解析所需字段
    """

    vendor_dict = Config.vendor_dict
    crawl_config = {
            "headers":{
                "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36"
            }
    }

    url_list = [
        'http://www.cnnvd.org.cn/vulnerability/index/vulcode2/Siemens/vulcode/Siemens/cnnvdid//fbsjs//fbsje/',
        'http://www.cnnvd.org.cn/vulnerability/index/vulcode2/Schneider/vulcode/Schneider/cnnvdid//fbsjs//fbsje/',
        'http://www.cnnvd.org.cn/vulnerability/index/vulcode2/Rockwell/vulcode/Rockwell/cnnvdid//fbsjs//fbsje/',
        'http://www.cnnvd.org.cn/vulnerability/index/vulcode2/Yokogawa/vulcode/Yokogawa/cnnvdid//fbsjs//fbsje/',
        'http://www.cnnvd.org.cn/vulnerability/index/vulcode2/Mitsubishi/vulcode/Mitsubishi/cnnvdid//fbsjs//fbsje/',
        'http://www.cnnvd.org.cn/vulnerability/index/vulcode2/Omron/vulcode/Omron/cnnvdid//fbsjs//fbsje/',
        'http://www.cnnvd.org.cn/vulnerability/index/vulcode2/Advantech/vulcode/Advantech/cnnvdid//fbsjs//fbsje/',
        'http://www.cnnvd.org.cn/vulnerability/index/vulcode2/Emerson/vulcode/Emerson/cnnvdid//fbsjs//fbsje/',
        'http://www.cnnvd.org.cn/vulnerability/index/vulcode2/General%20Electric/vulcode/General%20Electric/cnnvdid//fbsjs//fbsje/'
    ]
    @every(minutes=24 * 60)
    def on_start(self):
        """根据url_list启动爬虫，并将相应的结果传递给index_page进行解析"""

        self.crawl(self.url_list, retries=10, callback=self.index_page)

    @config(age= 24 * 60 * 60)
    def index_page(self, response):
        """获取所有漏洞url，并将相应的url相应传递给detail_page"""

        for each in response.doc('a[href^="http"]').items():
            if re.match("http://www.cnnvd.org.cn/vulnerability/show/cv_cnnvdid/CNNVD-\d+-\d+",each.attr.href):
                print each.attr.href
                self.crawl(each.attr.href, priority=9, retries=10, callback=self.detail_page)
        self.crawl(response.doc(".dispage >a").filter(lambda i:PyQuery(this).text() == u"下一页").attr.href, retries=10, callback=self.index_page)
    
    def detail_page(self, response):
        """解析漏洞详细信息"""

        leak_info = response.doc(".details tr")
        
        vul_name = leak_info.eq(0).children().eq(1).text()
        cnnvd_id = leak_info.eq(1).children().eq(1).text()
        release_time = leak_info.eq(2).children().eq(1).text()
        update_time = leak_info.eq(3).children().eq(1).text()
        danger_level = leak_info.eq(4).children().eq(1).text()
        cvss_score = ''
        vul_type = leak_info.eq(5).children().eq(1).text()
        if vul_type is None or vul_type == '':
            vul_type = u'其他类型'
        attack_path = leak_info.eq(6).children().eq(1).text()
        cve_id = leak_info.eq(7).children().eq(1).text()


        finder = leak_info.eq(8).children().eq(1).text()
        if not finder:
            finder = 'unknown'

        # 解析漏洞描述
        vul_des = ''
        description_list = response.doc(".cont_details")[1].xpath(".//text()")
        for item in description_list:
            if item:
                vul_des += item.strip()
        
        vul_solution = response.doc(".cont_details").eq(2).text().strip()
        
        ref_link = ''
        reference_link_list = response.doc("#top3 p a")
        tmp_link = []
        for rlink in reference_link_list:
            if PyQuery(rlink).text().startswith(u'http'):
                tmp_link.append(PyQuery(rlink).outerHtml())
        ref_link =  ';'.join(tmp_link)

        affect_product = ''
        impact_product_list= response.doc(".rht_cont span")
        tmp_product =[]
        for product in impact_product_list:
            tmp_product.append(PyQuery(product).attr.title)
        affect_product = ';'.join(tmp_product)
        
        if affect_product == u'暂无数据':
            affect_product = ''
        
        vul_exploit = ''
        vul_status = ''
        

        full_text = (vul_name +affect_product + vul_des).lower()
        # 解析产品厂商
        affect_vendor = 'other'
        # if cve_id:
        #     product_detail = cve_detail.crawl_cve_detail(cve_id)
        #     if product_detail:
        #         affect_vendor = ','.join(product_detail.keys())
        #     else:
        #         for define_vendor,ref_vendor in self.vendor_dict.items():
        #             for rv in ref_vendor:
        #                 if fuzzyfinder(rv, full_text):
        #                     affect_vendor = define_vendor
        #                     break
        #             if affect_vendor != 'other':
        #                 break
        # else:
        #     for define_vendor,ref_vendor in self.vendor_dict.items():
        #             for rv in ref_vendor:
        #                 if fuzzyfinder(rv, full_text):
        #                     affect_vendor = define_vendor
        #                     break
        #             if affect_vendor != 'other':
        #                 break
        # if affect_vendor:
        #     normalized_vendor = affect_vendor + '(' + affect_vendor + ')'  # default vendor
        #     for define_vendor, ref_vendor in self.vendor_dict.items():
        #         if define_vendor.lower() in affect_vendor.lower():
        #             normalized_vendor = ref_vendor[-1] + '(' + define_vendor.title() + ')'
        #             break
        
        result = {
            "vul_enname": '',
            "vul_chname": vul_name,
            "cnnvd_id": cnnvd_id,
            "cve_id":cve_id,
            "vul_type": vul_type,
            "danger_level": danger_level,
            "cvss_score": cvss_score,
            "attack_path": attack_path,
            "vul_des": vul_des,
            "affect_vendor": affect_vendor,
            "affect_product": affect_product,
            "vul_exploit": vul_exploit,
            "vul_solution": vul_solution,
            "ref_link": ref_link,
            "vul_status": vul_status,
            "finder": finder,
            "release_time": release_time,
            "update_time": update_time
        }
        return result
