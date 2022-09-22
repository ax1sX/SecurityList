# Tomcat

版本下载： http://archive.apache.org/dist/tomcat/

官方漏洞声明： https://tomcat.apache.org/security-7.html

历史漏洞

|漏洞编号|漏洞类型|影响版本|
|:----:|:----:|:----:|
|CVE-2017-12615|写文件|7.0.0 to 7.0.79|
|CVE-2020-1938|文件读取/文件包含|< 9.0.31, 8.5.51 or 7.0.100|
|CVE-2019-0232|RCE|9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93|
|无|后台弱密码+GetShell|7+|

**windows远程调试**

设置IDEA Remote JVM Debug: `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5555`

修改Tomcat目录/bin/catalina.bat，找到`set JAVA_OPTS=`代码行，设置如下
```
set JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5555"
```
Windows下命令行运行`catalina.bat start`，即可开启调试


## CVE-2017-12615
漏洞描述，发现和readonly配置有关，并且可以通过PUT方法上传jsp文件
> When running Apache Tomcat 7.0.0 to 7.0.79 on Windows with HTTP PUTs enabled (e.g. via setting the readonly initialisation parameter of the Default to false) it was possible to upload a JSP file to the server via a specially crafted request

更改`/conf/web.xml`文件中的配置，原配置如下
```xml
<!--   readonly   Is this context "read only", so HTTP      -->
<!--              commands like PUT and DELETE are      -->
<!--              rejected?  [true]      -->
<servlet>
    <servlet-name>default</servlet-name>
    <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
    <init-param>
        <param-name>debug</param-name>
        <param-value>0</param-value>
    </init-param>
    <init-param>
        <param-name>listings</param-name>
        <param-value>false</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
</servlet>
```
增加一行readonly属性，并赋值为false
```
    <init-param>
        <param-name>readonly</param-name>
        <param-value>false</param-value>
    </init-param>
```

一些payload
```
PUT /test.jsp::$DATA
PUT /test2.jsp%20
PUT /test1.jsp/
```
对于第一个payload，可以参考Windows NTFS流： https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3?redirectedfrom=MSDN

对于第二个payload，Windows不允许空字符作为文件名结尾，所以会去掉空字符

对于第三个payload，是java.io.File的特性，在new File时，会去掉末尾的/

根据/conf/web.xml中的配置，jsp文件的解析是由JspServlet来执行的，而其他的默认由DefaultServlet来解析。DefaultServlet的doPut方法是漏洞触发的入口。上述在jsp后缀后面加特殊字符都是为了绕过JSPServlet，让DefaultServlet来解析
```
    <servlet>
        <servlet-name>jsp</servlet-name>
        <servlet-class>org.apache.jasper.servlet.JspServlet</servlet-class>
    </servlet>
    
    <servlet>
        <servlet-name>default</servlet-name>
        <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
    </servlet>
    
    <!-- The mapping for the default servlet -->
    <servlet-mapping>
        <servlet-name>default</servlet-name>
        <url-pattern>/</url-pattern>
    </servlet-mapping>

    <!-- The mappings for the JSP servlet -->
    <servlet-mapping>
        <servlet-name>jsp</servlet-name>
        <url-pattern>*.jsp</url-pattern>
        <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>
```

DefaultServlet的doPut方法
```
protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
    if (this.readOnly) { // readOnly为true，就403禁止
        resp.sendError(403);
    } else {
        String path = this.getRelativePath(req);
        boolean exists = true;

        try {
            this.resources.lookup(path); // 从资源中查找路径下的文件是否存在
        } catch (NamingException var11) {
            exists = false;
        }

        boolean result = true;
        File contentFile = null;
        DefaultServlet.Range range = this.parseContentRange(req, resp); // 判断请求头是否包含"Content-Range"
        InputStream resourceInputStream = null;
        if (range != null) {
            contentFile = this.executePartialPut(req, range, path);
            resourceInputStream = new FileInputStream(contentFile);
        } else {
            resourceInputStream = req.getInputStream();
        }

        try {
            Resource newResource = new Resource((InputStream)resourceInputStream);
            if (exists) {
                this.resources.rebind(path, newResource);
            } else {
                this.resources.bind(path, newResource); // 
            }
        } catch (NamingException var10) {
            result = false;
        }

        if (result) {
            if (exists) {
                resp.setStatus(204);
            } else {
                resp.setStatus(201);
            }
        } else {
            resp.sendError(409);
        }

    }
}
```
当资源不存在时，会调用FileDirContext类
```
public void bind(String name, Object obj, Attributes attrs) throws NamingException {
    File file = new File(this.base, name);
    if (file.exists()) {
        throw new NameAlreadyBoundException(sm.getString("resources.alreadyBound", new Object[]{name}));
    } else {
        this.rebind(name, obj, attrs); // 如果该文件不存在，调用rebind
    }
}
```
rebind方法是明显的写文件函数
```
public void rebind(String name, Object obj, Attributes attrs) throws NamingException {
    File file = new File(this.base, name); // new File的时候会调用java.io.WinNTFileSystem .resolve() 会去掉末尾的/
    InputStream is = null;
    if (obj instanceof Resource) {
        is = ((Resource)obj).streamContent();
    } ...
    else {
        FileOutputStream os = null;
        byte[] buffer = new byte[2048];
        boolean var8 = true;

        try {
            os = new FileOutputStream(file);

            while(true) {
                int len = is.read(buffer);
                if (len == -1) {
                    return;
                }

                os.write(buffer, 0, len);
            }
        } ...
    }
}
```

## CVE-2020-1938
Tomcat对于协议的解析包括：HTTP/1.1、AJP、HTTP/2。这个漏洞的是Tomcat AJP协议中的缺陷，攻击者可以读取或包含Tomcat的webapp目录中的任何文件

漏洞利用脚本： https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi/blob/master/CNVD-2020-10487-Tomcat-Ajp-lfi.py

漏洞调试时需要添加如下pom.xml
```
<dependency>
    <groupId>org.apache.tomcat</groupId>
    <artifactId>tomcat-coyote</artifactId>
    <version>7.0.79</version>
</dependency>
```

这个漏洞的触发点也是DefaultServlet，CVE-2017-12615执行的doPut而这个漏洞则执行的doGet
```
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
    this.serveResource(request, response, true);
}
```
serveResource的具体实现如下
```
protected void serveResource(HttpServletRequest request, HttpServletResponse response, boolean content) throws IOException, ServletException {
    boolean serveContent = content;
    String path = this.getRelativePath(request, true); // 获取文件路径

    if (path.length() == 0) { this.doDirectoryRedirect(request, response);} 
    else {
        CacheEntry cacheEntry = this.resources.lookupCache(path); // path和resource根目录拼接，得到资源实体
        boolean isError = DispatcherType.ERROR == request.getDispatcherType();
        String contentType;
        if (!cacheEntry.exists) {...
        } else if (cacheEntry.context == null && (path.endsWith("/") || path.endsWith("\\"))) { ...
        } else {
            contentType = cacheEntry.attributes.getMimeType();
            ...
            ServletOutputStream ostream = null;
            PrintWriter writer = null;
            if (serveContent) {
                try {
                    ostream = response.getOutputStream(); // 获取输出流
                } ...
            }
            ServletResponse r = response;
            long contentWritten;
            for(contentWritten = 0L; r instanceof ServletResponseWrapper; r = ((ServletResponseWrapper)r).getResponse()) {}
            if (r instanceof ResponseFacade) {
                contentWritten = ((ResponseFacade)r).getContentWritten();
            }

            if (cacheEntry.context == null && !isError && (ranges != null && !ranges.isEmpty() || request.getHeader("Range") != null) && ranges != FULL) { ...} 
            else {
                if (contentType != null) {
                    response.setContentType(contentType);
                }

                if (cacheEntry.resource != null && contentLength >= 0L && (!serveContent || ostream != null)) {
                    if (contentWritten == 0L) {
                        if (contentLength < 2147483647L) {
                            response.setContentLength((int)contentLength);
                        }...
                    }
                }

                InputStream renderResult = null;
                if (serveContent) {
                    ...
                    if (ostream != null) {
                        if (!this.checkSendfile(request, response, cacheEntry, contentLength, (DefaultServlet.Range)null)) {
                            this.copy(cacheEntry, renderResult, ostream); // 将文件实体的内容写入到输出流
                        }
                    } else {
                        this.copy(cacheEntry, renderResult, writer);
                    }
     ...
}
```
getRelativePath会得到路径`servletPath+pathInfo`。如果`request.getAttribute("javax.servlet.include.request_uri") `值不为空，路径的值都是从属性`javax.servlet.include.path_info`和`javax.servlet.include.servlet_path`中获取的。
<details>
    <summary>getRelativePath</summary>
    <pre><code>
protected String getRelativePath(HttpServletRequest request, boolean allowEmptyPath) {
    String servletPath;
    String pathInfo;
    if (request.getAttribute("javax.servlet.include.request_uri") != null) {
        pathInfo = (String)request.getAttribute("javax.servlet.include.path_info");
        servletPath = (String)request.getAttribute("javax.servlet.include.servlet_path");
    } else {
        pathInfo = request.getPathInfo();
        servletPath = request.getServletPath();
    }
    StringBuilder result = new StringBuilder();
    if (servletPath.length() > 0) {
        result.append(servletPath);
    }
    if (pathInfo != null) {
        result.append(pathInfo);
    }
    if (result.length() == 0 && !allowEmptyPath) {
        result.append('/');
    }
    return result.toString();
}
    </code></pre>
</details>

## 弱密码
查看用户权限配置文件`conf/tomcat-users.xml`，示例如下，可以根据官网进行配置： https://tomcat.apache.org/tomcat-8.5-doc/manager-howto.html
```
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">

    <role rolename="manager-gui"/>
    <role rolename="manager-script"/>
    <role rolename="manager-jmx"/>
    <role rolename="manager-status"/>
    <role rolename="admin-gui"/>
    <role rolename="admin-script"/>
    <user username="tomcat" password="tomcat" roles="manager-gui,manager-script,manager-jmx,manager-status,admin-gui,admin-script" />

</tomcat-users>
```
访问`http://ip:8080/manager/html`输入弱密码，进入后台，上传war包
