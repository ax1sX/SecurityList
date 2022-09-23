# Nginx

Nginx是HTTP和反向代理服务器、邮件代理服务器和通用TCP/UDP代理服务器，由C语言开发

官方漏洞列表： http://nginx.org/en/security_advisories.html

官方下载地址： https://nginx.org/en/download.html

Windows下安装，解压zip文件，更改/conf/nginx.conf，找到listen字段更改端口（一般默认的80端口都存在冲突无法启动）。双击nginx.exe启动
```xml
server {
    listen  8086;
}
```
关闭服务
```
nginx -s stop
nginx -s quit
```

历史漏洞
|漏洞编号|漏洞类型|影响版本|
|:----:|:----:|:----:|
|CVE-2013-4547|逻辑漏洞|0.8.41-1.5.6|
|CVE-2017-7529|越界读取缓存|0.5.6-1.13.2|

## CVE-2013-4547
Ref： https://blog.werner.wiki/file-resolution-vulnerability-nginx/
