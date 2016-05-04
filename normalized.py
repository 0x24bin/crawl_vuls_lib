# !/usr/bin/env python
# -*- encoding: utf-8 -*-


import re
import json
import MySQLdb
import cve_detail
from config import Config
import filter_leak_lib


vendor_dict = Config.vendor_dict
product_type_dict = Config.product_type_dict

db = MySQLdb.connect(
    	host = '127.0.0.1',
    	user = 'root',
    	passwd = '563120',
    	db = 'leak_lib',
    	charset = 'utf8')


def fetch_leak_info():
    """从漏洞库中获取漏洞信息"""

    cursor = db.cursor()
    sql = 'select vul_chname, cnvd_id, cnnvd_id, cve_id, vul_des, affect_vendor, affect_product from vuldb'
    cursor.execute(sql)
    result = cursor.fetchall()
    for r in result:
        tmp = {}
        tmp["vul_chname"] = r[0].encode('utf-8')
        tmp["cnvd_id"] = r[1].encode('utf-8')
        tmp["cnnvd_id"] = r[2].encode('utf-8')
        tmp["cve_id"] = r[3].encode('utf-8')
        tmp["vul_des"] = r[4].encode('utf-8')
        tmp["affect_vendor"] = r[5].encode('utf-8')
        tmp["affect_product"] = r[6].encode('utf-8')
        yield tmp
        # with open('leak_info.json', 'a+') as f:
        #     f.write(json.dumps(tmp, ensure_ascii=False))
        #     f.write('\n')


def fuzzyfinder(field, text):
    """模糊匹配，发现厂商和产品类型"""

    field_lower = field.lower()
    text_lower = text.lower()
    pattern = re.compile(field_lower)
    match = pattern.search(text_lower)
    if match:
        return True
    else:
        return False


def generate_product_detail(leak_info, vendor='other', product_type='ohter', version=[], update=[]):
    """如果cve_id为空或者cve_details返回的响应结果为空，则根据爬取的漏洞信息生成产品信息"""

    product_detail = {}
    full_text = leak_info['vul_chname'] + leak_info["vul_des"] + leak_info["affect_product"]
    for define_vendor,ref_vendor in vendor_dict.items():
        for rv in ref_vendor:
            if fuzzyfinder(rv, full_text):
                vendor = define_vendor
                break
        if vendor != 'other':
            break
    for define_product_type, ref_product_type in product_type_dict.items():
        for rpt in ref_product_type:
            if fuzzyfinder(rpt, full_text):
                product_type = define_product_type
                break
        if product_type !='other':
            break

    affect_product = leak_info["affect_product"].split(';')  # product list
    if not product_detail.has_key(vendor):
        product_detail[vendor] = {}
        product_info = product_detail[vendor]
    if not product_info.has_key(product_type):
        product_info[product_type] ={}
        type_info = product_info[product_type]
    for aproduct in affect_product:
        product = ' '.join(aproduct.split(' ')[1:])
        if not type_info.has_key(product):
            type_info[product] = {}
            subtype_info = type_info[product]
        if not subtype_info.has_key(u'version'):
            subtype_info[u'version'] = []
        if not subtype_info.has_key(u'update'):
            subtype_info[u'update'] = []
    return product_detail


def update_product_detail(product_detail, leak_info):
    """根据漏洞库中的信息更新爬取到的产品信息（主要更新产品的类型）"""

    if not product_detail:
        return product_detail

    full_text = leak_info['vul_chname'] + leak_info["vul_des"] + leak_info["affect_product"]
    updated_product_detail = {}
    for vendor in product_detail.keys():
        final_vendor = vendor.lower()
        for define_vendor,ref_vendor in vendor_dict.items():
            if final_vendor == define_vendor:
                break
            else:
                for rv in ref_vendor:
                    if fuzzyfinder(rv, full_text):
                        final_vendor = define_vendor
                        break
                if final_vendor != vendor.lower():
                    break
        updated_product_detail[final_vendor] = {}
        for product_type in product_detail[vendor].keys():
            final_type = product_type.lower()
            for define_product_type, ref_product_type in product_type_dict.items():
                if final_type == define_product_type:
                    break
                else:
                    for rpt in ref_product_type:
                        if fuzzyfinder(rpt, full_text):
                            final_type = define_product_type
                            break
                    if final_type != product_type.lower():
                        break
            print "--------------------------"+final_vendor,final_type +"--------------------------"
            updated_product_detail[final_vendor][final_type] = product_detail[vendor][product_type]
    return updated_product_detail


def fetch_product_detail(fetch_leak_info):
    """生成产品信息"""
    generate_fetch_leak_info = fetch_leak_info()
    for leak_info in generate_fetch_leak_info:
        cve_id = leak_info.get('cve_id')
        cnvd_id = leak_info.get('cnvd_id')
        cnnvd_id = leak_info.get('cnnvd_id')
        vdb_id = [cnvd_id, cnnvd_id]
        if cve_id:
            tmp_product_detail = cve_detail.crawl_cve_detail(cve_id)
            product_detail = update_product_detail(tmp_product_detail, leak_info)
            # print product_detail
            if not product_detail:
                # Here cve_id is exists,but the coresponse of the cve_detail is not exists
                product_detail = generate_product_detail(leak_info)
        else:
            product_detail = generate_product_detail(leak_info)
            # print product_detail
        with open('normalized.json','a+') as f:
            f.write(json.dumps(product_detail)+'\n')
        update_vendor(product_detail, vdb_id)
        create_product_table(product_detail, vdb_id)


def update_vendor(product_detail, index):
    cursor = db.cursor()
    vendor = product_detail.keys()
    vdb_id = index
    for v in vendor:
        normalized_v = v + '(' + v + ')'
        for define_vendor, ref_vendor in vendor_dict.items():
            if define_vendor.lower() in v.lower():
                normalized_v = ref_vendor[-1] + '(' + v.title() + ')'
                break
        update_sql = 'update vuldb set affect_vendor=%s where cnvd_id=%s and cnnvd_id=%s'
        values = [normalized_v] + vdb_id
        print values
        try:
            cursor.execute(update_sql,values)
            db.commit()
        except Exception, e:
            print e
            db.rollback()


def create_product_table(product_detail, vdb_id):
    """根据产品信息创建产品库"""

    print product_detail
    cursor = db.cursor()
    insert_sql = '''INSERT INTO products (
            vdb_id,
            unique_name,
            product_vendor,
            name,
            product_type,
            firmware_version,
            software_version,
            update_time) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)'''
    update_time = ''
    products = {}
    for pv in product_detail.keys():
        for pt in product_detail[pv].keys():
            for pn in product_detail[pv][pt]:
                firmware_version = product_detail[pv][pt][pn][u"version"]
                software_version = product_detail[pv][pt][pn][u"update"]
                for fv, sv in zip(firmware_version, software_version):
                    unique_name = '_'.join((pv, pt, pn, fv))
                    if not products.has_key(unique_name):
                        products[unique_name]=[]
                    for vid in vdb_id:
                        if vid not in products[unique_name] and vid != '':
                            products[unique_name].append(vid)

                    # normalized vendor e.g "西门子(siemens)"

                    # default vendor
                    normalized_pv = pv + '(' + pv + ')'
                    for define_vendor, ref_vendor in vendor_dict.items():
                        if define_vendor.lower() in pv.lower():
                            normalized_pv = ref_vendor[-1] + '(' + pv.title() + ')'
                            break
                    vdb_id_string = ','.join([i for i in vdb_id if i != ''])
                    insert_vaule = [vdb_id_string, unique_name.lower(), normalized_pv.title(), pn.lower(), pt.lower(), fv, sv, update_time]
                    try:
                        cursor.execute(insert_sql, insert_vaule)
                        db.commit()
                    except Exception, e:
                        print insert_vaule
                        print e
                        db.rollback()


def main():
    fetch_product_detail(fetch_leak_info)
    # filter_leak_lib.final_products(filter_leak_lib.filter_products)


if __name__ == '__main__':
    main()
