# 普元应用服务器(PAS)

## 环境安装

系统环境为`Ubuntu20.04`
*   （1）安装JDK8，`sudo apt-get install openjdk-8-jdk`
*   （2）解压安装文件，进入解压后的目录
*   （3）赋予`install.sh`和`installer/bin`目录下的sh文件可执行权限，`chmod u+x *.sh`
*   （3）执行`install.sh`文件并根据引导进行安装
*   （4）下载[mysql-connector-java-5.1.40.jar](https://mvnrepository.com/artifact/mysql/mysql-connector-java/5.1.40)文件拷贝至`pas6/pas/domains/domain1/lib/`目录下
*   （5）进入`pas6/`目录,为sh脚步添加可执行权限。
*   （6）执行`startServer.sh`，启动服务
*   （7）访问`http://localhost:6888`，使用`admin/manager`进行登陆。

