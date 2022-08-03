# 安装说明

### 1. 安装包 ###
```
Ecology_setup_forWindows_v2.61.exe
Ecology9.00.1907.04.zip
Resin-4.0.58.zip
Ecology9注册机.exe
```
### 2. 安装前提 ###
Windows Server + Sql Server

### 3. 安装步骤 ###

（1）更改hosts  
为避免泛微自动更新，在windows配置文件`C:\Windows\System32\drivers\etc\`末尾增加如下内容。将泛微的更新地址指向本地。此步骤可选。
```
127.0.0.1 update.e-cology.cn
127.0.0.1 www.weaver.com.cn
```

（2）运行Ecology_setup_forWindows_v2.61.exe  
运行exe，选择全新安装，此步骤将Ecology和Resin压缩包解压到当前目录下  

（3）配置、启动Resin  
运行Resin目录下的setup.exe，创建服务。查看Resin目录下的resinstart.bat文件中Java的路径是否为Windows下配置的Java的路径，如果不是进行更改。运行resinstart.bat。  

（4）访问localhost:ip  
ip是第二步中配置的ip，默认为80。访问之后会进入到数据库配置界面。验证码一般为`wEAver2018`。在sql server数据库中创建名为ecology的数据库。然后回到数据库配置界面，点击初始化数据库。初始化完成后根据页面提示信息，重启Resin。  

（5）登入系统  
localhost:ip进入系统。会跳转到登陆界面。点击登录后可能弹出license验证。license验证时将识别码放入Ecology9.exe注册机中生成license文件，导入。验证码处依旧填入`wEAver2018`。验证success后。输入管理员用户名`sysadmin`，密码位于数据表`HrmResourceManager`，值md5加密方式。  

### 4. 其他问题 ###

（1）jsp编译报错  
如果没有能进入到登陆界面，一直显示加载中。并且在命令行终端看到jsp编译报错。查看Resin目录，`conf/resin.xml`中的以下内容所设路径正确，`javac compiler`路径和`root-directory`需要和系统中的配置保持一致。用Ecology_setup_forWindows_v2.61.exe生成的可能有误。

```
<javac compiler="C:\Program Files\Java\jdk1.8.0_65\bin\javac" args="-encoding UTF-8"/>

<web-app id="/" root-directory="C:\Users\Administrator\Desktop\e9\ecology">
  <servlet-mapping url-pattern='/weaver/*' servlet-name='invoker'/>
  <form-parameter-max>100000</form-parameter-max>
</web-app>
```
