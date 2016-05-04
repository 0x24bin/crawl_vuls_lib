#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Project: crawl_cnnvd


from pyspider.result import ResultWorker
import MySQLdb
import json


class LeakResultWorker(ResultWorker):
    """
    对pyspider爬取的结果进行操作
    """

    def on_result(self,task,result):

        with open('crawl_result.json', 'a+') as f:
            f.write(json.dumps(result))
            f.write('\n')

        insert_value = [
            result.get('vul_enname') or '',
            result.get('vul_chname') or '',
            result.get('cve_id') or '',
            result.get('cnvd_id') or '',
            result.get('cnnvd_id') or '',
            result.get('vul_type') or '',
            result.get('danger_level') or '',
            result.get('cvss_score') or '',
            result.get('attack_path') or '',
            result.get('vul_des') or '',
            result.get('affect_vendor') or '',
            result.get('affect_product') or '',
            result.get('vul_exploit') or '',
            result.get('vul_solution') or '',
            result.get('ref_link') or '',
            result.get('vul_status') or '',
            result.get('finder') or '',
            result.get('release_time') or '',
            result.get('update_time') or ''
        ]


        db = MySQLdb.connect(
            host='localhost',
            user='root',
            passwd='563120',
            db='leak_lib',
            charset='utf8')
        cursor = db.cursor()
        insert_sql = '''INSERT INTO vuldb (
                    vul_enname,
                    vul_chname,
                    cve_id,
                    cnvd_id,
                    cnnvd_id,
                    vul_type,
                    danger_level,
                    cvss_score,
                    attack_path,
                    vul_des,
                    affect_vendor,
                    affect_product,
                    vul_exploit,
                    vul_solution,
                    ref_link,
                    vul_status,
                    finder,
                    release_time,
                    update_time) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'''
        query_sql = '''select cve_id from vuldb'''
        update_sql = '''update vuldb set cnnvd_id=%s where cve_id=%s'''
        update_values = [result.get('cnnvd_id'), result.get('cve_id')]
        try:
            # filter the same cve_id
            cursor.execute(query_sql)
            cve_id_list = cursor.fetchall()
            # if (result.get('cve_id') != '' and (result.get('cve_id'),) not in cve_id_list) or result.get('cve_id') == '' :
            if result.get('cve_id') != '' and (result.get('cve_id'),) in cve_id_list:
                # update cnvd/cnnvd
                try:
                    cursor.execute(update_sql,update_values)
                    db.commit()
                except Exception as e:
                    print "====================================================="
                    print e
                    print "====================================================="
                    db.rollback()
            else:
                try:
                    cursor.execute(insert_sql,insert_value)
                    db.commit()
                except Exception as e:
                    print "====================================================="
                    print e
                    print "====================================================="
                    db.rollback()
        except:
            db.rollback()
        db.close()
  

