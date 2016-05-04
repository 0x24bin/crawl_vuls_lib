# !/usr/bin/env python
# -*- coding: utf-8 -*-


import MySQLdb


def create_vul_product_relation():
    db = MySQLdb.connect(
        host = '127.0.0.1',
        user = 'root',
        passwd = '563120',
        db = 'leak_lib',
        charset = 'utf8')

    cursor = db.cursor()

    # vul VS product is like the relation of  1  to m
    join_sql = '''select unique_name, vuldb.id, products.update_time from vuldb right join products on find_in_set(vuldb.cnvd_id, products.vdb_id) or find_in_set(vuldb.cnnvd_id, products.vdb_id)'''
    insert_sql = '''insert into vulproduct_db (
        unique_name,
        vuldb_id,
        update_time
        ) values(%s,%s,%s)'''
    try:
        cursor.execute(join_sql)
        result = cursor.fetchall()
        for item in result:
            unique_name, vuldb_id, update_time = item
            insert_value = [unique_name or '', vuldb_id or '', update_time or '']
            cursor.execute(insert_sql, insert_value)
        db.commit()
    except Exception, e:
        print e
        db.rollback()

def main():
    create_vul_product_relation()


if __name__ == '__main__':
    main()
