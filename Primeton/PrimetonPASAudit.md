# 普元应用服务器(PAS)

## 环境安装

系统环境为`Ubuntu20.04`
*   （1）安装JDK8，`sudo apt-get install openjdk-8-jdk`
*   （2）解压安装文件，进入解压后的目录
*   （3）赋予`install.sh`和`installer/bin`目录下的sh文件可执行权限，`chmod u+x *.sh`
*   （3）执行`install.sh`文件并根据引导进行安装
*   （4）下载[mysql-connector-java-5.1.40.jar](https://mvnrepository.com/artifact/mysql/mysql-connector-java/5.1.40)文件拷贝至安装目录中的`pas6/pas/domains/domain1/lib/`目录下
*   （5）进入安装目录下的`pas6/`目录,为sh脚步添加可执行权限。
*   （6）执行`startServer.sh`，启动服务
*   （7）访问`http://localhost:6888`，使用`admin/manager`进行登陆。

## 使用方式

### 远程调试
以如下方式启动服务，默认端口为`9009`

```
startServer.sh -d
```

### 应用部署

随意构建一个war包，通过管理页面的前台进行部署，如下图

![image](https://user-images.githubusercontent.com/62204882/201556701-1e05ef24-ead4-4f28-bbc4-24d3148fd8d8.png)

部署后的文件位于pas6/pas/domains/domain1/applications/web目录

## 历史漏洞

* [PAS安全： CNVD-C-2022-122084 Primeton AppServer管理控制台存在弱口令漏洞的修复方法 - 00_信创产品知识库 - 普元技术文档库（官方）](http://doc.primeton.com/pages/viewpage.action?pageId=61902745)

## 路由分析

`web.xml`配置文件中暴露的路由有如下部分

### /download/*

对应类`com.primeton.appserver.admingui.common.servlet.DownloadServlet`，它有如下初始化参数
```xml
<init-param>
    <param-name>ContentSources</param-name>
    <param-value>
            com.primeton.appserver.admingui.common.servlet.LBConfigContentSource,
            com.primeton.appserver.admingui.common.servlet.ClientStubsContentSource,
            com.primeton.appserver.admingui.common.servlet.LogFilesContentSource
            com.primeton.appserver.admingui.common.servlet.LogViewerContentSource
    </param-value>
</init-param>
<init-param>
    <param-name>contentSourceId</param-name>
    <param-value>LBConfig</param-value>
</init-param>
```
这4个类都实现了`ContentSource`接口，关注`getInputStream`方法。

使用如下路由访问
```
/download/a?contentSourceId=(LBConfig|LogFiles|LogViewer|ClientStubs)
```

它们会根据指定的参数，内部访问REST接口来获取所需数据，但不能直接进行访问。

### /resources/*

由javax.faces.webapp.FacesServlet进行处理。

有两种方式访问资源
```
/resources/<资源路径>
/resources/javax.faces.resources/<资源名>?ln<library-name>&loc<locale-prefix>
```
尝试了目录穿越，但是代码中检查的很严格
```java
# com.sun.faces.application.resource.ResourceManager
private static boolean nameContainsForbiddenSequence(String name) {
    boolean result = false;
    if (name != null) {
        name = name.toLowerCase();
        result = name.startsWith(".") || name.contains("../") || name.contains("..\\") || name.startsWith("/") || name.startsWith("\\") || name.endsWith("/") || name.contains("..%2f") || name.contains("..%5c") || name.startsWith("%2f") || name.startsWith("%5c") || name.endsWith("%2f") || name.contains("..\\u002f") || name.contains("..\\u005c") || name.startsWith("\\u002f") || name.startsWith("\\u005c") || name.endsWith("\\u002f");
    }

    return result;
}

private boolean libraryNameIsSafe(String libraryName) {
    assert null != libraryName;

    boolean result = !libraryName.startsWith(".") && !libraryName.startsWith("/") && !libraryName.contains("/") && !libraryName.startsWith("\\") && !libraryName.contains("\\") && !libraryName.startsWith("%2e") && !libraryName.startsWith("%2f") && !libraryName.contains("%2f") && !libraryName.startsWith("%5c") && !libraryName.contains("%5c") && !libraryName.startsWith("\\u002e") && !libraryName.startsWith("\\u002f") && !libraryName.contains("\\u002f") && !libraryName.startsWith("\\u005c") && !libraryName.contains("\\u005c");
    return result;
}
```

### /html/*

### /faces/*

### *.jsf

### jsf文件的解析执行，由javax.faces.webapp.FacesServlet处理。

### /theme/*

获取URI路径信息（`/theme/<resourceName>`）并调用
```java
this.getClass().getResourceAsStream(resourceName)
```
读取内容并返回。

### 鉴权

默认配置如下，所有/*的路由都需要admin权限才能访问，
```xml
<!-- only user from admin realm can access any URL pattern -->
<security-constraint>
    <web-resource-collection>
        <web-resource-name>protected</web-resource-name>
        <url-pattern>/*</url-pattern>
    </web-resource-collection>
    <auth-constraint>
        <role-name>admin</role-name>
    </auth-constraint>
</security-constraint>
```
除了下面这部分
```xml
<security-constraint>
    <web-resource-collection>
        <web-resource-name>public</web-resource-name>
        <url-pattern>/theme/com/*</url-pattern>
        <url-pattern>/theme/org/*</url-pattern>        
        <url-pattern>/resource/*</url-pattern>
        <url-pattern>/theme/META-INF/*</url-pattern>
        <http-method>GET</http-method>
    </web-resource-collection>
</security-constraint>
```
