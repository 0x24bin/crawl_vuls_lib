#!/usr/bin/env python
# -*- encoding:utf-8 -*-


import MySQLdb


db = MySQLdb.connect(
                host='127.0.0.1',
                user='root',
                passwd='563120',
                db='leak_lib',
                charset='utf8')
cursor = db.cursor()


def filter_products():  
    products = {}
    query_sql = "select * from products"
    try:
        cursor.execute(query_sql)
        result = cursor.fetchall()
        for product in result:
            vdb_id, unique_name, software_version, update_time = product[1], product[2], product[-2], product[-1]
            if not products.has_key(unique_name):
                products[unique_name] = {}
                products[unique_name]['vdb_id'] = []
                products[unique_name]['software_version'] = []
                products[unique_name]['update_time'] = update_time
            for i in vdb_id.split(','):
                if vdb_id not in products[unique_name]['vdb_id']:
            	    products[unique_name]['vdb_id'].append(vdb_id)
            if software_version not in products[unique_name]['software_version']:
        	    products[unique_name]['software_version'].append(software_version)
    
    except Exception, e:
        print e
        db.rollback()
    return products


def final_products(filter_product):
    products = filter_product()
    insert_sql = '''INSERT INTO unique_products (
            vdb_id,
            unique_name,
            product_vendor,
            name,
            product_type,
            firmware_version,
            software_version,
            update_time) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)'''
    for p in products.keys():
        product_vendor, product_type, name, firmware_version = p.split('_')
        if not products[p]['update_time']:
            products[p]['update_time'] = ''
        insert_value = (','.join(products[p]['vdb_id']), p, product_vendor, name, product_type, firmware_version, ','.join(products[p]['software_version']), products[p]['update_time'])
        try:
            cursor.execute(insert_sql, insert_value)
            db.commit()
        except Exception, e:
            print insert_value
            print e
            db.rollback()


def main():
    final_products(filter_products)


if __name__ == '__main__':
    main()