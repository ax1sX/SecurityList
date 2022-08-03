# SecurityList

### 泛微Ecology ###

#### 补丁 ####
https://www.weaver.com.cn/cs/securityDownload.html?src=cn

#### 历史漏洞 ####
```
(1) BeanShell RCE
POST /weaver/bsh.servlet.BshServlet

(2) Soap XStream RCE: 
POST /services%20/WorkflowServiceXml
Ref: https://www.anquanke.com/post/id/239865

(3) 前台Zip文件上传
POST /weaver/weaver.common.Ctrl/.css?arg0=com.cloudstore.api.service.Service_CheckApp&arg1=validateApp
GET /cloudstore/xxx.jsp

(4) 文件上传
POST /weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image
Ref: https://mp.weixin.qq.com/s?__biz=MzkxMzIzNTU5Mg==&mid=2247483666&idx=1&sn=e70efe98c064e0f1df986e2b65c1a608&chksm=c1018af5f67603e39ce4d6e9375875e63e7b80633a1f99959f8d4652193ac3734765a99099ea&mpshare=1&scene=23&srcid=0414cqXy50udQOy19LYOMega&sharer_sharetime=1618332600979&sharer_shareid=d15208c7b27f111e2fe465f389ab6fac#rd

(5) 文件上传
POST /weaver/weaver.workflow.exceldesign.ExcelUploadServlet?method=uploadFile&savefile=pass.jsp
Ref:https://mp.weixin.qq.com/s?__biz=MzkxMzIzNTU5Mg==&mid=2247483674&idx=1&sn=ce1c56a670587df0a33201a62a4b6e2d&chksm=c1018afdf67603eb15bea96e668bc0279b63f241654beb000da3c7e7333d8545c4c3217d0576&scene=178&cur_album_id=1824092566640705544#rd

(6) 数据库配置文件读取
POST /mobile/DBconfigReader.jsp

(7) Oracle注入
/mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333

(8) 日志泄漏
/hrm/kq/gethrmkq.jsp?filename=1

(9) 文件上传
POST /workrelate/plan/util/uploaderOperate.jsp
POST /OfficeServer

(10) 文件上传
POST /page/exportImport/uploadOperation.jsp

(11) Cookie泄露
POST /mobile/plugin/VerifyQuickLogin.jsp

(12) SQL注入
GET /api/ec/dev/locale/getLabelByModule

(13) 代码执行
POST /api/integration/workflowflow/getInterfaceRegisterCustomOperation
```

#### 代码审计特点 ####

(1) jsp访问路径均为ecology根目录到该jsp的路径，例如jsp的绝对路为`D:/ecology/addressbook/AddressBook.jsp`，那么该jsp的访问路径为`http://ip:port/addressbook/AddressBook.jsp`

(2) 管理员账号位于表HrmResourceManager，密码为md5加密

(3) 泛微E9版本开始新增了/api路由，与@Path注解对应，在旧版本中，该路由存在大小写绕过鉴权的漏洞。

#### 安全策略 ####

泛微的安全策略与如下过滤器有关

```xml
<filter>
    <filter-name>SecurityFilter</filter-name>
    <filter-class>weaver.filter.SecurityFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>SecurityFilter</filter-name>
    <url-pattern>/*</url-pattern>
</filter-mapping>
```

安全策略的具体内容分为两种，规则形式的`xml`文件（位于`WEB-INF/securityRule`），和实现`weaver.security.rules.BaseRule`接口的类（位于`WEB-INF/myclasses/weaver/security/rules/ruleImp`）。




#### 安装注意事项 ####
安装包包含如下：

```
Ecology_setup_forWindows_v2.61.exe
Ecology9.00.1907.04.zip
Resin-4.0.58.zip
Ecology9注册机.exe
```

安装前提，Windows下已经安装sql server。

（1）更改hosts

为避免泛微自动更新，更改windows配置文件`C:\Windows\System32\drivers\etc\`。将泛微的更新地址指向本地。此步骤可选。

```
127.0.0.1 update.e-cology.cn
127.0.0.1 www.weaver.com.cn
```

（2）运行Ecology_setup_forWindows_v2.61.exe

选择全新安装，exe会将Ecology和Resin压缩包解压到当前目录下。跟着控制台的提示进行下一步。

（3）配置、启动Resin

运行Resin目录下的setup.exe，创建服务。查看Resin目录下的resinstart.bat文件中Java的路径是否为Windows下配置的Java的路径，如果不是进行更改。运行resinstart.bat。

（4）访问localhost:ip

ip是第二步中配置的ip，默认为80。访问之后会进入到数据库配置界面。验证码一般为`wEAver2018`。在sql server数据库中创建名为ecology的数据库。然后回到数据库配置界面，点击初始化数据库。初始化完成后根据页面提示信息，重启Resin。

（5）登入系统

Ip:port，进入系统。会跳转到登陆界面。管理员账号位于表HrmResourceManager，密码为md5加密。如果没有能进入到登陆界面，一直显示加载中。并且在命令行终端看到jsp编译报错。查看Resin目录，`conf/resin.xml`中的以下内容所设路径正确，`javac compiler`路径和`root-directory`需要和系统中的配置保持一致。但是Ecology_setup_forWindows_v2.61.exe生成的可能有误。

```
<javac compiler="C:\Program Files\Java\jdk1.8.0_65\bin\javac" args="-encoding UTF-8"/>

<web-app id="/" root-directory="C:\Users\Administrator\Desktop\e9\ecology">
  <servlet-mapping url-pattern='/weaver/*' servlet-name='invoker'/>
  <form-parameter-max>100000</form-parameter-max>
</web-app>
```

成功看到登陆界面后，点击登录，会弹出license验证，将识别码放入Ecology9.exe注册机中生成license文件，导入。验证码处依旧填入`wEAver2018`。验证success后。输入用户名`sysadmin`和md5解密后的密码。
