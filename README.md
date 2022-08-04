# SecurityList

## 泛微Ecology ##

### 补丁 ###

**官方补丁下载**  
https://www.weaver.com.cn/cs/securityDownload.html?src=cn  
**老补丁下载方式**     
根据官网中补丁发布的时间和版本，拼接成`日期_版本.zip?v=日期03`，访问url进行下载，如：  
https://www.weaver.com.cn/cs/package/Ecology_security_20220731_v10.52.zip?v=2022073103  
**补丁解压密码**  
```
v10.39-46: Weaver@Ecology201205
<v10.38: 未知
old version: Weaver#2012!@#
``` 

### 历史漏洞 ###
```
(1) BeanShell RCE (2019.09.17修复)
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

(6) 数据库配置文件读取 (2019.10.24修复)
POST /mobile/DBconfigReader.jsp

(7) Oracle注入 (2019.10.10修复)
/mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333

(8) 日志泄漏
/hrm/kq/gethrmkq.jsp?filename=1

(9) 文件上传 （2022.06.18修复）
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

### 代码审计特点 ###

(1) 管理员账号位于表HrmResourceManager，密码为md5加密

(2) 泛微E9版本开始新增了/api路由，与@Path注解对应，在旧版本中，该路由存在大小写绕过鉴权的漏洞。

(3) 环境信息查看：`/security/monitor/Monitor.jsp`

(4) 代码调试    
Resin目录下/conf/resin.properties文件中找到`jvm_args`参数，在参数值中加入
```
-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005
```

### 路由特点 ###
（1）`/weaver`    
服务器为resin，查看resin.xml。它配置了invoker servlet，即一种默认访问servlet的方式，可以运行没有在web.xml中配置的servlet。访问路径为`/weaver/*`，`*`后是被访问的Java类，该类需要满足两个要求 a.采用完全限定名 b.实现servlet或HttpServlet相关接口。
```
<web-app id="/" root-directory="C:\Users\Administrator\Desktop\Ecology1907\ecology">
    <servlet-mapping url-pattern='/weaver/*' servlet-name='invoker'/>
    <form-parameter-max>100000</form-parameter-max>
</web-app>
```
所以lib目录下的bsh-2.0b4.jar可以按照全限定类名`/bsh.servlet.BshServlet`访问`BshServlet`类，该类实现了`HttpServlet`接口
```
public class BshServlet extends HttpServlet {
    public void doGet(HttpServletRequest var1, HttpServletResponse var2) throws ServletException, IOException {
        String var3 = var1.getParameter("bsh.script");
        ...
        var8 = this.evalScript(var3, var10, var7, var1, var2);
    }
}
```
`/ecology/classbean/`目录下均为Java类，想要访问该目录下的类都采用`/weaver`的方式

（2）`xx.jsp`     
jsp访问路径均为ecology根目录到该jsp的路径，例如jsp的绝对路为`D:/ecology/addressbook/AddressBook.jsp`，那么该jsp的访问路径为`http://ip:port/addressbook/AddressBook.jsp`

（3）`/services/*`
`/services/*`的服务配置由`org.codehaus.xfire.transport.http.XFireConfigurableServlet`读取`classbean/META-INF/xfire/services.xml`文件进行加载创建。配置文件各服务节点结构大致如下

```xml
    <service> 
        <name>DocService</name>  
        <namespace>http://localhost/services/DocService</namespace>  
        <serviceClass>weaver.docs.webservices.DocService</serviceClass>  
        <implementationClass>weaver.docs.webservices.DocServiceImpl</implementationClass>  
        <serviceFactory>org.codehaus.xfire.annotations.AnnotationServiceFactory</serviceFactory> 
    </service>
```

那么可以通过`/services/DocService`的方式访问该接口。

（4）`/api/*`

由`@Path`注解定义的一系列`REST`接口，可以在`ecology/WEB-INF/Api.xls`文件中查看所有的`api`接口路径和相关类。

### 安全策略 ###

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





