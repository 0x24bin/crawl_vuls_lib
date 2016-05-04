# !/usr/bin/env python
# -*- coding: utf-8 -*-

import MySQLdb
import normalized



def increase_product():
    
    cursor = normalized.db.cursor()
    vuldb_sql = "select vul_chname, vdb_id, cve_id, vul_des, affect_vendor, affect_product from vuldb"
    products_sql = "select vdb_id from vuldb" 
    try:
        cursor.execute(vuldb_sql)
        vuldb_result = cursor.fetchall()
        cursor.execute(products_sql)
        products_vdb_ids = cursor.fetchall() 
    except Exception as e:
        print e
    for item in vuldb_result:
        if not (item[2],) not in products_vdb_ids:
            # update productsdb
            tmp = {}
            tmp["vul_chname"] = item[0].encode('utf-8')
            tmp["vdb_id"] = item[1].encode('utf-8')
            tmp["cve_id"] = item[2].encode('utf-8')
            tmp["vul_des"] = item[3].encode('utf-8')
            tmp["affect_vendor"] = item[4].encode('utf-8')
            tmp["affect_product"] = item[5].encode('utf-8')
            yield tmp

def recrawl_missed_url():
    missed_cve_id = []
    with open('missed_url', 'r') as f:
        for line in f:
            m = line.split(r'/')[-1]
            missed_cve_id.append(m)
    products_sql = "select vdb_id from vuldb" 
    try:
        cursor.execute(products_sql)
        products_vdb_ids = cursor.fetchall() 
    except Exception as e:
        print e
        normalized.db.rollback()
    for cve_id in missed_cve_id:
        if (cve_id,) not in products_vdb_ids:
            # update productsdb
            sql = "select vul_chname, vdb_id, cve_id, vul_des, affect_vendor, affect_product from vuldb where cve_id=%s"
            cursor = db.cursor()
            try:
                cursor.execute(sql, [cve_id])
                item = cursor.fetchall()
            except Exception as e:
                print e
                normalized.db.rollback()
            tmp = {}
            tmp["vul_chname"] = item[0].encode('utf-8')
            tmp["vdb_id"] = item[1].encode('utf-8')
            tmp["cve_id"] = item[2].encode('utf-8')
            tmp["vul_des"] = item[3].encode('utf-8')
            tmp["affect_vendor"] = item[4].encode('utf-8')
            tmp["affect_product"] = item[5].encode('utf-8')
            yield tmp


def main():
    normalized.fetch_product_detail(increase_product)
    normalized.fetch_product_detail(recrawl_missed_url)

if __name__ == '__main__':
    main()