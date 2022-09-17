# InfluxDB
InfluxDB是一个由InfluxData开发的开源时序型数据库 (Time Series Database，TSDB) ，由Go编写，用于处理和存储时序数据（随时间不断产生的一系列带时间戳的数据）被广泛应用于存储系统的监控数据，IoT行业的实时数据等场景。

历史版本源码下载： https://github.com/influxdata/influxdb/tags

Windows安装包下载（将后缀换成所需版本）： https://dl.influxdata.com/influxdb/releases/influxdb-1.7.4_windows_amd64.zip

Windows安装教程，按顺序执行如下三步（其中config后的路径改为自己influxdb的目录位置） 
```
influxd.exe config C:\influxdb-1.7.4\influxdb.conf
influxd.exe
influx.exe
```
influx正确启动后，可以看到如下显示，并可以在命令行中进行交互
```
Connected to http://localhost:8086 version 1.7.4
```

官方使用教程： https://docs.influxdata.com/influxdb/v2.4/get-started/


历史漏洞

|漏洞编号|漏洞类型|影响版本|
|:----:|:----:|:----:|
|CVE-2019-20933|身份验证绕过|< 1.7.6|
|CVE-2022-36640|RCE|< 1.8.10|


## CVE-2019-20933
Ref： https://www.komodosec.com/post/when-all-else-fails-find-a-0-day
