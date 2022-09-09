# Apache Solr

官方网站： https://solr.apache.org/

历史版本安装包和软件下载： http://archive.apache.org/dist/lucene/solr/

历史漏洞
|漏洞编号|漏洞类型|影响版本|
|:----:|:----:|:----:|
|CVE-2021-27905|SSRF|< 8.8.2 |
|CVE-2020-13957|RCE|<= 6.6.6、7.7.3、8.6.2 |
|CVE-2019-17558|RCE| 5.0.0-8.3.1|
|CVE-2019-0193|RCE|< 8.2.0|
|CVE-2019-0192|RCE|<= 5.5.5, 6.6.5|
|CVE-2017-12629|RCE|< 7.1|
|CVE-2017-12629|XXE|< 7.1|
|CVE-2017-3164|SSRF|<= 7.6|
|CVE-2017-3163|任意文件读取|< 6.4.1|

运行调试
```
// 以debug模式运行
solr.cmd -f -a "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5555" -p 8983

// 生成测试数据（生成路径为Solr文件夹下的example\example-DIH\solr）
solr.cmd -f -e dih

// 停止服务
solr.cmd stop -p 8983

// 以debug模式运行并执行测试数据
solr.cmd -f -a "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5555" -p 8983 -s "C:\Solr\solr-6.4.0\example\example-DIH\solr"

// 创建核心
solr.cmd create -c solr_sample

// 删除核心
solr.cmd delete -c solr_sample
```

## CVE-2017-3163

