## 泛微Ecology ##

### (1) 漏洞指纹 ###
`Set-Cookie: ecology_JSessionId=`

### (2) 调试方法 ###  
Resin目录下/conf/resin.properties文件中找到`jvm_args`参数，在参数值中加入
```
-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005
```

### (3) 关键数据 ###
* 环境安装验证码: `/ecology/WEB-INF/code.key`文件中        
* 管理员账号: 位于数据表`HrmResourceManager`，密码为`md5`加密，无法解码的情况下，可通过`/api/ec/dev/locale/getLabelByModule`路径的sql注入漏洞修改密码     
* 环境信息查看: 访问`http://ip:port/security/monitor/Monitor.jsp`，包含操作系统版本、ecology版本、web中间件版本、JVM版本、客户端软件和规则库版本
* 编译后的class文件: `/ecology/classbean/ `文件夹下
* 系统运行依赖的jar: `/ecology/WEB-INF/lib/` 文件夹下

### (4) 路由特点 ###
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

（2）`/xx.jsp`     
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
由`@Path`注解定义的一系列`REST`接口，可以在`ecology/WEB-INF/Api.xls`文件中查看所有的`api`接口路径和相关类。泛微E9版本开始新增了/api路由，在旧版本中，该路由存在大小写绕过鉴权的漏洞。

（5）`/*.do`      
由实现了`weaver.interfaces.workflow.action.Action`接口的`action`，由ecology/WEB-INF/service/\*.xml所配置
```xml
<action path="/getProcess" type="com.weaver.action.EcologyUpgrade" parameter="getProcess" >
</action>
```
可通过/<path>.do的方式访问。

### (5) 安全策略 ###

安全过滤器(防火墙)
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

安全策略的加载位于`SecurityMain#initFilterBean`方法，加载顺序如下

* 加载WEB-INF/weaver_security_config.xml
* 加载WEB-INF/weaver_security_rules.xml
* 加载WEB-INF/securityRule/{Ecology_Version}/*.xml，并将这些文件作为参数调用ruleImp中实现了BaseRule接口的自定义规则的init函数
* 从数据库表weaver_security_rules中加载（如果配置文件中fromDB=db）
* 调用ruleImp中实现了BaseRule接口的自定义规则的initConfig函数
* 加载WEB-INF/securityRule/Rule/*.xml
* 加载WEB-INF/securityXML/*.xml

安全补丁的日志: `/ecology/WEB-INF/securitylog`   

安全策略生效特征:

(1) URL访问404，响应头部包含`errorMsg: securityIntercept`

(2) 访问后弹窗，提示登录或出错，或响应体中包含`<script type='text/javascript'>try{top.location.href='/login/Login.jsp?af=1&_token_=`

参数名称过滤策略

`ecology/WEB-INF/securityRule/Rule/weaver_security_custom_rules_for_20180411.xml`
```
<param-key>^(?!.*(&lt;|&gt;|&amp;|'|"|\(|\)|\r|\n|%0D%0A)).*$</param-key>
```

SQL注入过滤策略       
`/ecology/WEB-INF/securityRule/Rule/weaver_security_for_sqlinjection_rules.xml`
```
<rules>
    <!--破坏性sql语句检查-->
    <rule>exec[^a-zA-Z]|insert[^a-zA-Z]into[^a-zA-Z].*?values|delete[^a-zA-Z].*?from|update[^a-zA-Z].*?set|truncate[^a-zA-Z]</rule>
    <!--常见注入字符检查-->
    <rule>[^a-zA-Z]count\(|[^a-zA-Z]chr\(|[^a-zA-Z]mid\(|[^a-zA-Z]char[\s+\(]|[^a-zA-Z]net[^a-zA-Z]user[^a-zA-Z]|[^a-zA-Z]xp_cmdshell[^a-zA-Z]|\W/add\W|[^a-zA-Z]master\.dbo\.xp_cmdshell|net[^a-zA-Z]localgroup[^a-zA-Z]administrators|DBMS_PIPE\.|[^a-zA-Z]len\s*\(|[^a-zA-Z]left\s*\(|[^a-zA-Z]right\s*\(|str(c|ing)?\s*\(|ascii\s*\(|UNION([^a-zA-Z]ALL[^a-zA-Z])?SELECT[^a-zA-Z]NULL|[a-zA-Z0-9_\-]+\s*=\s*0x(2D|3[0-9]|4[1-F1-f]|5[1-A1-a]|6[1-F1-f]|7[1-A][1-a])|UTL_HTTP\s*\(|MAKE_SET\s*\(|ELTs*\(|IIF\s*\(|(PG_)?SLEEP\s*\(|DBMS_LOCK\s*\.|USER_LOCK\s*\.|[LR]LIKE\s*\(|CONCAT(_WS)?\s*\(|GREATEST\s*\(|IF(NULL)?\s*\(|EXTRACTVALUE\s*\(|UPDATEXML\s*\(|WAITFOR\s*DELAY|ANALYSE\s*\(|UNION\s+(ALL\s+)?SELECT</rule>
    <!--typical SQL injection detect-->
    <rule>\w*((\%27))((\%6F)|(\%4F))((\%72)|(\%52))</rule>
    <rule>((\%27)|('))union</rule>
    <rule>substrb\(</rule>
</rules>
```

    
### (6) 补丁 ###
官方网址: https://www.weaver.com.cn/cs/securityDownload.html?src=cn  
老补丁下载方式: 根据官网中补丁发布的时间和版本，拼接成`日期_版本.zip?v=日期03`，访问url进行下载，如：  
https://www.weaver.com.cn/cs/package/Ecology_security_20220731_v10.52.zip?v=2022073103  
补丁解压密码
```
v10.39-46: Weaver@Ecology201205
<v10.38: 未知
old version: Weaver#2012!@#
``` 
补丁安装: 补丁解压后，替换ecology文件夹中的对应内容

### (7) 历史漏洞 ###
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

(14) 文件读取
GET /weaver/org.springframework.web.servlet.ResourceServlet?resource=/WEB-INF/prop/weaver.properties

(15) SQL注入
/cpt/manage/validate.jsp
```
