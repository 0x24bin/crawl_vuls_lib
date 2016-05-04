-- 清除pyspider自动建的库
DROP DATABASE IF EXISTS projectdb;
DROP DATABASE IF EXISTS resultdb;
DROP DATABASE IF EXISTS taskdb;

DROP DATABASE IF EXISTS leak_lib;
CREATE DATABASE leak_lib;
GRANT ALL ON leak_lib.* TO root@127.0.0.1 IDENTIFIED BY '563120';
FLUSH PRIVILEGES;
GRANT ALL ON leak_lib.* TO root@localhost IDENTIFIED BY '563120';
FLUSH PRIVILEGES;

USE leak_lib;

-- 指纹库
CREATE TABLE `fingerprints` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `fp_content` varchar(30) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '指纹内容：可以是||分开的多个模式串如plc||1200||v2.0.1',
  `is_used` tinyint(4) NOT NULL COMMENT '0=不启用 1=启用 生成指纹规则文件的时候只包括=1的',
  `description` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL COMMENT '指纹描述',
  `unique_name` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '产品全名：类似siemens_plc_1200_v2.0.0,厂家_产品类型_子类型_固件版本，通过这个唯一键关联所有功能',
  `update_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '更新时间：指纹更新时间，增删改等',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- 产品库
CREATE TABLE `products` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vdb_id` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '爬取的目标漏洞库自身的编号',
  `unique_name` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '产品全名：类似siemens_plc_1200_v2.0.0,厂家_产品类型_子类型_固件版本，通过这个唯一键关联所有功能，这个名字要写入到指纹规则文件里',
  `product_vendor` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '产品厂家：采用西门子(siemens)模式便于中英文对照，解析脚本要预处理一下',
  `name` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '产品名称：plc_1200',
  `product_type` varchar(30) NOT NULL DEFAULT '' COMMENT '产品分类：plc、dcs等，讨论确定一下',
  `firmware_version` varchar(30) NOT NULL DEFAULT '' COMMENT '产品固件版本：V2.0.1',
  `software_version` varchar(30) NOT NULL DEFAULT '' COMMENT '软件版本',
  `update_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '更新时间：比如固件升级时间，每个固件版本添加一条记录',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='产品列表';

-- 产品库
CREATE TABLE `unique_products` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vdb_id` varchar(1000) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '爬取的目标漏洞库自身的编号',
  `unique_name` varchar(1000) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '产品全名：类似siemens_plc_1200_v2.0.0,厂家_产品类型_子类型_固件版本，通过这个唯一键关联所有功能，这个名字要写入到指纹规则文件里',
  `product_vendor` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '产品厂家：采用西门子(siemens)模式便于中英文对照，解析脚本要预处理一下',
  `name` varchar(1000) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '产品名称：plc_1200',
  `product_type` varchar(100) NOT NULL DEFAULT '' COMMENT '产品分类：plc、dcs等，讨论确定一下',
  `firmware_version` varchar(30) NOT NULL DEFAULT '' COMMENT '产品固件版本：V2.0.1',
  `software_version` varchar(30) NOT NULL DEFAULT '' COMMENT '软件版本',
  `update_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '更新时间：比如固件升级时间，每个固件版本添加一条记录',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='产品列表';

-- 漏洞库
CREATE TABLE `vuldb` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vul_chname` varchar(100) NOT NULL DEFAULT '' COMMENT '中文名称',
  `vul_enname` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '英文名称',
  `cve_id` varchar(30) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  `cnvd_id` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '爬取的目标漏洞库自身的编号',
  `cnnvd_id` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '爬取的目标漏洞库自身的编号',
  `vul_type` varchar(30) NOT NULL DEFAULT '' COMMENT '漏洞类型',
  `danger_level` varchar(20) NOT NULL DEFAULT '' COMMENT '危险等级',
  `cvss_score` varchar(10) NOT NULL DEFAULT '' COMMENT '漏洞评分',
  `attack_path` varchar(30) NOT NULL DEFAULT '' COMMENT '攻击路径/方式',
  `vul_des` text NOT NULL COMMENT '漏洞描述',
  `affect_vendor` text NOT NULL COMMENT '影响到的厂商',
  `affect_product` text NOT NULL COMMENT '影响到的产品',
  `vul_exploit` text NOT NULL COMMENT '漏洞利用',
  `vul_solution` text NOT NULL COMMENT '解决方案',
  `ref_link` text NOT NULL COMMENT '补丁参考链接',
  `vul_status` varchar(30) NOT NULL DEFAULT '' COMMENT '漏洞状态',
  `finder` varchar(30) NOT NULL DEFAULT '' COMMENT '发现者',
  `release_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '发布时间',
  `update_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '更新时间',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- 漏洞库产品库关系库
CREATE TABLE `vulproduct_db` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `unique_name` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '产品全名：类似siemens_plc_1200_v2.0.0,厂家_产品类型_子类型_固件版本，通过这个唯一键关联所有功能',
  `vuldb_id` int(11) NOT NULL COMMENT '自有漏洞编号',
  `update_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '更新时间：比如固件升级时间，每个固件版本添加一条记录',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- 指纹识别结果库
CREATE TABLE `fingerprint_result` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `target_ip` varchar(20) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '目标IP:202.204.46.151',
  `unique_name` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '产品全名：类似siemens_plc_1200_v2.0.0,厂家_产品类型_子类型_固件版本，通过这个唯一键关联所有功能',
  `open_ports` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '目标打开的端口:21,23,102',
  `app_protocols` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '目标运行的协议:ftp,telnet,s7',
  `detail_path` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '' COMMENT '识别结果文件的路径:/scc/result/20160304.out',  
  `is_searched` tinyint(4) NOT NULL COMMENT '0=未核查 1=已核查 java做完漏洞核查搜索后置1，后面不再重复搜索漏洞关系库',
  `update_time` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '更新时间：指纹更新时间，增删改等',
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
