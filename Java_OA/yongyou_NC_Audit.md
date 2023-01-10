## 环境搭建
Windows Server虚拟机，安装SQL Server（推荐2008），并创建一个数据库，如nc65。

解压用友NC的安装包，从NC6.5文件夹中找到yongyou_nc文件夹。找到文件夹中的setup.bat开始安装过程，需要注意

* NCHome目录路径中不能包含中文、空格或特殊字符。
* Windows环境变量中的JDK路径也不能包含空格等。

安装后，打开用友UAP配置工具：`C:\yonyou\home\bin\sysConfig.bat`，双击SysConfig.bat启动。

服务器选项可以配置JDK版本（需要与windows环境变量中的一致），还可以配置调试参数（点击读取应用服务器，在虚拟机参数后加入如下内容，再点击保存）

```
Xdebug -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5555
```

并同时配置Web服务器，点击保存。

![yongyou](https://user-images.githubusercontent.com/62204882/202337674-b501e085-5c15-4ca7-87ae-74252cc19fc8.jpg)

UAP配置工具的数据源选项则是配置数据库，选取上述创建的nc65即可。数据源名称和OID可随意设置

![yongyou1](https://user-images.githubusercontent.com/62204882/202337958-146c3bed-b762-4bad-968c-d4cc3b36c13d.jpg)

配置完成后，在home目录下找到startServer.bat，双击启动服务，服务启动成功后，访问127.0.0.1，端口为环境搭建时配置的端口。

安装步骤具体可参考： https://blog.csdn.net/weixin_38766356/article/details/103983787

## 路由分析
核心路由都位于`/home/webapps/nc_web/WEB-INF/web.xml`，内容如下
```
	<servlet>
		<servlet-name>ProvisionServlet</servlet-name>		
		<servlet-class>nc.bs.framework.provision.server.ProvisionServlet</servlet-class>
		<load-on-startup>5</load-on-startup>
	</servlet>
	
	<servlet> 
	 <servlet-name>NCInvokerServlet</servlet-name>
	  <servlet-class>nc.bs.framework.server.InvokerServlet</servlet-class>
	</servlet>
	
	<servlet>
	 <servlet-name>NCFindWebServlet</servlet-name>
	  <servlet-class>nc.bs.framework.server.FindWebResourceServlet</servlet-class>
	</servlet>

<servlet-mapping>
		<servlet-name>ProvisionServlet</servlet-name>
		<url-pattern>/provision</url-pattern>
	</servlet-mapping>
	
	<servlet-mapping>
	  <servlet-name>NCInvokerServlet</servlet-name>
	  <url-pattern>/service/*</url-pattern>
	</servlet-mapping>
	
	<servlet-mapping>
	  <servlet-name>NCInvokerServlet</servlet-name>
	  <url-pattern>/servlet/*</url-pattern>
	</servlet-mapping>

	<servlet-mapping>
		<servlet-name>NCFindWebServlet</servlet-name>
		<url-pattern>/NCFindWeb</url-pattern>
	</servlet-mapping>
```
总的来说有三个入口，（1）`/service/*`和`/servlet/*` （2）`/NCFindWeb` （3）`/provision`

对于第二个入口，出现过目录遍历漏洞`/NCFindWeb?service=IPreAlertConfigService&filename=`；对于第一个入口，实际处理类都是InvokerServlet，其doGet和doPost方法，也是路由转发的核心，
```
private void doAction(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String pathInfo = request.getPathInfo(); // /Servlet Path/ or Null
        try {
            if (pathInfo == null) {
                throw new ServletException("Service name is not specified, pathInfo is null");
            }

            pathInfo = pathInfo.trim(); // 删除字符串的头尾空白符
            String moduleName = null;
            String serviceName = null;
            int beginIndex;
            if (pathInfo.startsWith("/~")) { /~xx/xxxx，xx被截取为moduleName，xxxx被截取为serviceName
                moduleName = pathInfo.substring(2);
                beginIndex = moduleName.indexOf("/");
                if (beginIndex >= 0) {
                    serviceName = moduleName.substring(beginIndex);
                    if (beginIndex > 0) {
                        moduleName = moduleName.substring(0, beginIndex);
                    } else {
                        moduleName = null;
                    }
                } else {
                    moduleName = null;
                    serviceName = pathInfo;
                }
            } else {
                serviceName = pathInfo;
            }

            if (serviceName == null) {
                throw new ServletException("Service name is not specified");
            }

            beginIndex = serviceName.indexOf("/");
            if (beginIndex < 0 || beginIndex >= serviceName.length() - 1) {
                throw new ServletException("Service name is not specified");
            }

            serviceName = serviceName.substring(beginIndex + 1);
            Object obj = null;

            String msg;
            try {
                obj = this.getServiceObject(moduleName, serviceName);
            }...
            if (obj instanceof Servlet) {
                Logger.init(obj.getClass());

                try {
                    if (obj instanceof GenericServlet) {
                        ((GenericServlet)obj).init();
                    }

                    this.preRemoteProcess();
                    ((Servlet)obj).service(request, response);
                    this.postRemoteProcess();
                } ...
            } ...

    }
```
核心逻辑是截取出`moduleName`和`serviceName`，然后反射调用对应的Servlet。`moduleName`可以从`/home/modules`中查找。如果所调用的Servlet位于`/home/lib`的某个jar文件中，那么`moduleName`可以是modules中的任意一个。

访问路径如`http://172.16.165.146:8089/servlet/~uapss/com.yonyou.ante.servlet.FileReceiveServlet`，就调用的uapss模块下的FileReceiveServlet类。

这些模块的位于安装目录下的`home/modules`目录中。

## 已知漏洞
```
# 反序列化漏洞
http://172.16.165.146:8089/servlet/mxservlet
http://172.16.165.146:8089/service/~uapss/nc.search.file.parser.FileParserServlet
http://172.16.165.146:8089/servlet/~uapss/com.yonyou.ante.servlet.FileReceiveServlet
http://172.16.165.146:8089/servlet/~aert/com.ufida.zior.console.ActionHandlerServlet
http://172.16.165.146:8089/servlet/~ic/uap.framework.rc.controller.ResourceManagerServlet
http://172.16.165.146:8089/servlet/~baseapp/nc.document.pub.fileSystem.servlet.DeleteServlet
http://172.16.165.146:8089/servlet/~baseapp/nc.document.pub.fileSystem.servlet.DownloadServlet
http://172.16.165.146:8089/servlet/~baseapp/nc.document.pub.fileSystem.servlet.UploadServlet
http://172.16.165.146:8089/service/~xbrl/XbrlPersistenceServlet

/ServiceDispatcherServlet -> 参考：https://drea1v1.github.io/2020/06/17/%E7%94%A8%E5%8F%8Bnc%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/

# 目录遍历
http://172.16.165.146:8089/NCFindWeb?service=IPreAlertConfigService&filename=

# RCE
http://172.16.165.146:8089/servlet/~ic/bsh.servlet.BshServlet
```


