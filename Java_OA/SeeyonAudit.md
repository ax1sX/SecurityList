# Seeyon致远OA

## 环境安装
*   （1）安装mysql数据库（针对A8版本）。创建一个新的数据库，字符集设置为UTF-8。如果是A6版本，如
`A6v6.1、A6v6.1sp1、A6v6.1sp2`，默认使用内嵌在安装包中的`postgresql`作为数据库，无需单独安装
*   （2）获取安装文件。`Seeyonxxx.zip`（安装包）、`jwycbjnoyees.jar`（破解补丁）
*   （3）在安装包中点击要安装版本`.bat`文件，如`SeeyonA8-1Install.bat`
*   （4）按照弹出的安装程序确认安装路径、配置数据库等（安装过程需要断网，否则检测到不是最新版无法进行下一步）。如果是A6版本，到数据库配置阶段可以修改`postgres`用户的密码。另外，针对A6版本，`postgresql`安装完成后不会设置`Windows`服务项，重启机器后再次启动会比较麻烦，可使用如下命令注册一个名为`pgsql`的服务项。后续可在`Windows`服务管理里启停`postgresql`服务

```text-plain
cd C:\Seeyon\A6V6.1SP2\pgsql9.2.5\bin pg_ctl.exe register -N "pgsql" -D "C:\Seeyon\A6\A6V6.1SP2\pgsql9.2.5\data"
```
*   （5）安装最后一步是账号密码设置。A6版本默认设置`system`账户的密码。A8版本可定义管理员账号、密码、普通用户初始密码、S1 Agent密码。
*   （6）安装破解补丁。如果服务已经启动，需要先关闭服务。首先备份安装目录`A6\ApacheJetspeed\webapps\seeyon\WEB-INF\lib`下的`jwycbjnoyees.jar`文件，然后将其替换成补丁文件后重启服务。补丁文件下载：https://github.com/ax1sX/SecurityList/blob/main/Java_OA/jwycbjnoyees.jar
*   （7）服务启动。A6在确保postgresql数据库服务是启动的状态下，点击“致远服务”图标来启动服务。A8是通过agent+server的形式来部署的。所以需要先启动`S1 Agent`，通过双击`Seeyon\A8\S1\start.bat`或点击`SeeyonS1Agent`图标都可以实现。然后再点击“致远服务”图标，在其“服务启动配置”中添加Agent。![致远服务部署Agent](https://github.com/ax1sX/SecurityList/blob/main/images/%E8%87%B4%E8%BF%9C%E6%9C%8D%E5%8A%A1%E9%85%8D%E7%BD%AEAgent.png)
*   （8）默认端口是80，可以在“致远服务”的“服务启动配置”中点击Agent的配置选项，对HTTP端口和JVM属性进行更改。想要对致远进行调试，可以在修改`/ApacheJetspeed/bin/catalina_custom.bat`文件，添加如下内容。
```
set JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"
```
*   （9）访问`http://127.0.0.1:8085/seeyon/main.do`



