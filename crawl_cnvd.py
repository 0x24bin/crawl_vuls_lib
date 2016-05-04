#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# crawl_cnvd

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

    all_vul_type = Config.vul_type_list
    vendor_dict = Config.vendor_dict
    
    crawl_config = {
        "headers":{
            "User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36"
        }
    }

    start_url = [
        'http://ics.cnvd.org.cn/'
    ]
    
    cve_base_url = 'http://www.cvedetails.com/cve/'
    
    @every(minutes=24 * 60)
    def on_start(self):
        """根据start_url启动爬虫，并将相应的结果传递给index_page进行解析"""

        self.crawl(self.start_url, retries=20, callback=self.index_page)

    @config(age= 24 * 60 * 60)
    def index_page(self, response):
        """获取所有漏洞url，并将相应的url相应传递给detail_page"""

        for each in response.doc('a[href^="http"]').items():
            if re.match("http://www.cnvd.org.cn/flaw/show/CNVD-\d+-\d+",each.attr.href):
                self.crawl(each.attr.href, priority=9, retries=20, callback=self.detail_page)
        self.crawl(response.doc(".nextLink").attr.href, retries=20, callback=self.index_page)
        
    def detail_page(self, response):
        """解析漏洞详细信息"""

        vul_name = response.doc("h1").text().strip()
        leak_info = response.doc(".tableDiv tr")
        cnvd_id = leak_info.eq(0).children().eq(1).text()
        release_time = leak_info.eq(1).children().eq(1).text()
        danger_level= leak_info.eq(2).children().eq(1).text()[0]
        cvss_score = response.doc("#showDiv div").eq(0).text().split(u'：')[1].strip()
        attack_path = response.doc("#showDiv td").eq(0).text().split(u'：')[1].strip()
        
        affect_product = ''
        affect_product_list = leak_info[3][1].xpath(".//text()")
        tmp_product = []
        for item in affect_product_list:
            if item.strip():
                tmp_product.append(item.strip())
        affect_product = ';'.join(tmp_product)

        cve_id = leak_info.eq(-12).children().eq(1).text()
        if not cve_id.startswith(u'CVE'):
            cve_id = ''
        
        vul_des = ''
        description_list = leak_info[-11][1].xpath('.//text()')
        for item in description_list:
            if item.strip():
                vul_des += item.strip()

        full_text = (vul_name + affect_product + vul_des).lower()

        # 解析影响厂商
        affect_vendor  = 'other'
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
        #         for rv in ref_vendor:
        #             if fuzzyfinder(rv, full_text):
        #                 affect_vendor = define_vendor
        #                 break
        #         if affect_vendor != 'other':
        #             break
        # if affect_vendor:
        #     normalized_vendor = affect_vendor + '(' + affect_vendor.title() + ')'
        #     for define_vendor, ref_vendor in self.vendor_dict.items():
        #         if define_vendor.lower() in affect_vendor.lower():
        #             normalized_vendor = ref_vendor[-1] + '(' + define_vendor.title() + ')'
        #             break


        ref_link = ''
        reference_link_list = leak_info.eq(-10).children().eq(1)('a')
        tmp_link = []
        for rlink in reference_link_list:
            tmp_link.append(PyQuery(rlink).outerHtml())
        ref_link =  ';'.join(tmp_link)
        
        vul_exploit = ''
        vul_solution = leak_info.eq(-9).children().eq(1).text().strip()
        finder = leak_info.eq(-8).children().eq(1).text().strip()       
        vul_status = leak_info.eq(-6).children().eq(1).text()       
        update_time = leak_info.eq(-3).children().eq(1).text().strip()
         
        # 解析漏洞类型
        vul_type = ''
        for tmp_type in self.all_vul_type[:-1]:
            if re.search(tmp_type.lower(), full_text):
                vul_type = tmp_type
                break
            else:
                vul_type = self.all_vul_type[-1]
                
        result = {
            "vul_enname": '',
            "vul_chname": vul_name,
            "cnvd_id": cnvd_id,
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
