安装步骤
----

### v8.0之前的版本

从

`\\10.128.154.26\share\01-组件源码安装包\Z-致远OA\V6.1sp2`

获取压缩包文件和破解补丁

`\\10.128.154.26\share\01-组件源码安装包\Z-致远OA\V6.1\破解补丁\jwycbjnoyees.jar`

解压后进入

`V6.1sp2\V6.1sp2\SeeyonInstall`

目录

其中有多个版本的安装脚本，包括企业版和集团版，`A6`和`A8`，以下介绍A6版本的安装步骤

`A6v6.1、A6v6.1sp1、A6v6.1sp2`版本默认使用`postgresql`作为数据库，而且是内嵌在安装包中的，无需单独下载。

直接运行

`SeeyonA6-V5企业版Install.bat`

按提示下一步即可，到数据库配置阶段时，可以修改`postgres`用户的密码。

继续下一步等待安装完成即可，安装完成后，设置`system`账户的密码。

安装完成后桌面会有致远控制中心的图标。

#### 破解补丁安装

在安装补丁前，如果服务已经启动，需要先关闭。

首先备份安装目录

`A6\ApacheJetspeed\webapps\seeyon\WEB-INF\lib`

下的`jwycbjnoyees.jar`文件

再将补丁文件`jwycbjnoyees.jar`拷贝替换进去并重启服务。

#### 数据库服务设置

`postgresql`安装完成后不会设置`Windows`服务项，所以下次重启了机器的话想再次启动会比较麻烦。

可使用如下命令注册一个名为`pgsql`的服务项。

```text-plain
cd C:\Seeyon\A6V6.1SP2\pgsql9.2.5\bin pg_ctl.exe register -N "pgsql" -D "C:\Seeyon\A6\A6V6.1SP2\pgsql9.2.5\data"
```

后续可在`Windows`服务管理里启停`postgresql`服务

#### 服务启动

首先确保`postgresql`数据库服务是启动状态，初次安装未关机的情况下，`postgresql`是启动的。否则可以通过前面设置的`pgsql`服务来启动它。

之后点击致远服务，进入主界面点击服务启停

点击启动`A6-V5`企业版即可。

### v8.0及之后的版本

`A8 v8.0`以上需要自行安装数据库，推荐使用`mysql`。并且它采用agent+server+控制台的形式进行部署，安装步骤略麻烦。

首先安装`mysql`，打开`mysql`的配置文件`C:\ProgramData\MySQL\MySQL Server 5.7\my.ini`，

修改如下字段，设置数据库字符集为`utf8`。

```text-plain
default-character-set=utf8 
character-set-server=utf8
```

之后与前面的步骤类似，运行`bat`文件进行安装。

安装后设置管理员账户名，密码以及`S1 Agent`密码。

安装完成后会自动启动`S1 Agent`服务，并等待致远服务启动。先打开桌面的致远服务控制台，点击`Agent`设置，点击添加行输入`ip`地址和之前设置的密码并点击解析。

![](api/images/NBmiubw26uIC/image.png)

解析后会识别`Agent`支持的类别。

之后点击左侧导航栏的服务启动配置，启动服务即可。

![](api/images/GWnyM5OnoWX8/image.png)

#### 破解补丁安装

与前面类型，备份替换文件后重启服务。

### Tips

*   致远服务的启动过程比较长，当然也可能是`hci`或`vdi`太辣鸡

### 常用数据

*   管理员账户位于`org_principal`表中，密码的存储方式是加密的而不是哈希值。加密方式因版本而异，所以不太好收集。
*   配置文件位于`WEB-INF/cfgHome`目录
*   官方补丁链接，[致远服务 (seeyon.com)](https://service.seeyon.com/patchtools/tp.html#/patchList?type=%E5%AE%89%E5%85%A8%E8%A1%A5%E4%B8%81&id=1)

### 调试

致远OA默认使用Tomcat进行部署，只需修改bin/catalina\_custom.bat文件，在`JAVA_OPTS`中添加如下内容

```text-plain
-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005
```

组件分析
----

以下分析过程，针对致远A8 v8.1集团版。

### 路由

从`web.xml`中获取的路由结构

##### \*.do

Spring框架下的Controller

##### \*.jsp

静态jsp文件

##### \*.psml

##### /rest/\*

使用Jersey开发的REST API接口

##### /webOffice/\*

调用第三方exe文件处理office文件

##### /services/\*

基于`SOAP`开发的接口，和泛微类似，相关配置文件位于

`WEB-INF/cfgHome/component/webservice`

但是默认是不开启，密码为空

```text-plain
<?xml version="1.0" encoding="utf-8"?>
<ctpConfig>
	<webservice>
        <enabled mark="{option,0,1} {VE}" desc="是否启用webservice插件  0--不启用  1--启用">0</enabled>
        <password mark="{password}" desc="webservice用户的密码"></password>
        <wadl>
        	<enabled mark="{option,true,false} {VE}" desc="是否启用REST接口的wadl，禁用后将无法访问application.wadl  false--不启用  true--启用">false</enabled>
        </wadl>
	</webservice>
</ctpConfig>
```

##### /apps\_res/m3/images/appIcon/\*

##### /office/cache/\*

##### /m-signature/\*

##### /rest/authentication/ucpcLogin/\*

##### /login/sso

##### /login/ssologout

##### /isignaturehtmlH5servlet

##### /org/\*

##### /g/\*

短URL映射，Hibernate技术下的Java对象映射

##### /configObtain

##### /serverStatusCheck

##### Servlet

```text-xml
<servlet>
    <servlet-name>officeservlet</servlet-name>
    <servlet-class>
        com.seeyon.ctp.common.office.OfficeServlet
    </servlet-class>
</servlet>
<servlet>
    <servlet-name>wpsAssistServlet</servlet-name>
    <servlet-class>
        com.seeyon.ctp.common.wpsassist.WpsAssistServlet
    </servlet-class>
</servlet>
<servlet>
    <servlet-name>pdfservlet</servlet-name>
    <servlet-class>
        com.seeyon.ctp.common.office.PdfServlet
    </servlet-class>
</servlet>
<servlet>
    <servlet-name>ofdServlet</servlet-name>
    <servlet-class>
        com.seeyon.ctp.common.office.OfdServlet
    </servlet-class>
</servlet>

<servlet>
    <servlet-name>htmlofficeservlet</servlet-name>
    <servlet-class>
        com.seeyon.ctp.common.office.HtmlOfficeServlet
    </servlet-class>
</servlet>
```

##### **/getAjaxDataServlet**

```text-plain
<servlet>
    <servlet-name>AJAXDataServlet</servlet-name>
    <servlet-class>
        com.seeyon.v3x.common.ajax.AJAXDataServlet
    </servlet-class>
</servlet>
```

##### **/axis2/\* /services/\***

```text-plain
<servlet>
    <servlet-name>axis2</servlet-name>
    <servlet-class>com.seeyon.ctp.common.ws.CtpAxis2Servlet</servlet-class>
    <!-- <load-on-startup>1</load-on-startup> -->
</servlet>
```

##### **/services/downloadService**

```text-plain
<servlet>
    <servlet-name>downloadService</servlet-name>
    <servlet-class>com.seeyon.ctp.services.FileOutputService</servlet-class>
</servlet>
```

### 过滤器（Filter）

`web.xml`中配置的过滤器有以下几个

```text-xml
# /*
<filter>
    <filter-name>spring-session</filter-name>
    <filter-class>org.springframework.session.web.http.CTPDelegatingFilterProxy</filter-class>
    <init-param>
        <param-name>targetBeanName</param-name>
        <param-value>springSessionRepositoryFilter</param-value>
    </init-param>
</filter>

# /apps_res/m3/images/appIcon/*
<filter>
    <filter-name>ExpiresFilter</filter-name>
    <filter-class>com.seeyon.ctp.common.web.filter.ExpiresFilter</filter-class>
    <init-param>
        <param-name>ExpiresByType image</param-name>
        <param-value>access plus 3 month</param-value>
    </init-param>
</filter>

# *.do *.jsp
<filter>
    <filter-name>CSRFGuard</filter-name>
    <filter-class>com.seeyon.ctp.common.web.filter.CTPCsrfGuardFilter</filter-class>
</filter>

# *.do /rest/*
<filter>
    <filter-name>PandaGuardFilter</filter-name>
    <filter-class>com.seeyon.ctp.panda.CTPPandaGuardFilter</filter-class>
</filter>

# *.do *.jsp *.jspx /rest/* /webOffice/* /services/* *.psml 
# /getAjaxDataServlet
# /getAJAXMessageServlet
# /getAJAXOnlineServlet
# /htmlofficeservlet
# /isignaturehtmlH5servlet
# /isignaturehtmlservlet
# /login/sso
# /login/ssologout
# /m-signature/*
# /ofdServlet
# /office/cache/*
# /officeservlet
# /wpsAssistServlet
# /pdfservlet
# /sursenServlet
# /verifyCodeImage.jpg
<filter>
    <filter-name>SecurityFilter</filter-name>
    <filter-class>com.seeyon.ctp.common.web.filter.CTPSecurityFilter</filter-class>
</filter>

# *.do
<filter>
    <filter-name>encodingFilter</filter-name>
    <filter-class>com.seeyon.ctp.common.web.filter.CharacterEncodingFilter</filter-class>
</filter>

# *.do *.jsp /office/cache/*
<filter>
    <display-name>GenericFilter</display-name>
    <filter-name>GenericFilter</filter-name>
    <filter-class>com.seeyon.ctp.common.web.GenericFilter</filter-class>
</filter>

# /m-signature/*
<filter>
    <filter-name>global</filter-name>
    <filter-class>com.kg.web.GlobalFilter</filter-class>
</filter>

# /rest/authentication/ucpcLogin/*
<filter>
    <filter-name>restFilter</filter-name>
    <filter-class>com.seeyon.ctp.common.web.filter.RestFilter</filter-class>
</filter>

# /isignaturehtmlH5servlet
<filter>
    <filter-name>kgh5filter</filter-name>
    <filter-class>com.seeyon.apps.common.isignaturehtml.filter.IsignatureFilter</filter-class>
</filter>

# /org/*
<filter>
    <filter-name>LoginIndependentPageURLFilter</filter-name>
    <filter-class>com.seeyon.ctp.login.controller.LoginPageURLFilter</filter-class>
</filter>
```

关系可见下图

![Filter Layer](filter.png)

从图中可看出`CTPSecurityFilter`覆盖的内容是最多的，并且_**大部分**_验证都在这里进行。

#### CTPSecurityFilter

目标：从这个过滤器观察是如何做鉴权的。

该过滤器有uri黑名单机制`./ ; .jspx .;jsessionid= /;jsessionid`，具体见如下函数

```text-x-java
    private static boolean isUnAttackUri(String uri) {
        if (StringUtils.isBlank(uri)) {
            return true;
        } else {
            try {
                uri = URLDecoder.decode(uri, "UTF-8");
            } catch (UnsupportedEncodingException var4) {
                logger.error("", var4);
            }

            uri = uri.toLowerCase().replace(";jsessionid=", "##");

            for(String attackStr : Arrays.asList("./", ";", ".jspx", ".##", "/##")) {
                if (uri.contains(attackStr)) {
                    return false;
                }
            }

            return true;
        }
    }
```

此时验证类型会被设置为`attackURIAuthenticator`

```text-x-java
CTPSecurityFilter.Result result = new CTPSecurityFilter.Result();
result.setAuthenticator(attackURIAuthenticator);
```

如果不包含上面的内容，验证类型会根据路由类型进行变化，一共有下面几种

*   defaultAuthenticator
*   controllerAuthenticator
*   tokenAuthenticator
*   restAuthenticator
*   v3xAjaxAuthenticator
*   soapAuthenticator
*   servletAuthenticator
*   jspAuthenticator
*   webOfficeAuthenticator

相关代码如下

```text-x-java
private static Authenticator controllerAuthenticator = new SpringControllerAuthenticator();
private static Authenticator restAuthenticator = new RestAuthenticator();
private static Authenticator tokenAuthenticator = new TokenAuthenticator();
private static Authenticator webOfficeAuthenticator = new WebOfficeAuthenticator();
private static Authenticator ajaxAuthenticator = new AjaxAuthenticator();
private static Authenticator v3xAjaxAuthenticator = new V3xAjaxAuthenticator();
private static Authenticator soapAuthenticator = new SOAPAuthenticator();
private static Authenticator servletAuthenticator = new ServletAuthenticator();
private static Authenticator jspAuthenticator = new JSPAuthenticator();
private static Authenticator attackURIAuthenticator = new AttackURIAuthenticator();
private static String contextName;
private static Authenticator defaultAuthenticator = new AbstractAuthenticator() {
    public boolean authenticate(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String uri = request.getRequestURI();
        return uri.startsWith(SystemEnvironment.getContextPath());
    }

    public boolean validate(String uri, HttpServletRequest req) {
        return true;
    }
};
```

当根据路由类型设置好验证器后，会调用

```text-x-java
result.authenticate(req, resp);
```

进行验证。

##### SpringControllerAuthenticator

当`URI`满足如下条件时会进入该验证器

```text-x-java
private static boolean isSpringController(String uri, HttpServletRequest request) {
    boolean result = uri.endsWith(".do");
    return !result && uri.indexOf(".do;jsessionid=") > 0 ? true : result;
}
```

这个验证器有一个白名单，当某个`Controller`的方法使用注解`@NeedlessCheckLogin`时，它就会在这个白名单中。在测试环境下，它的内容为

`NeedlessCheckLoginAnnotationAware.needlessUrlMap`

```text-plain
/media/media.do: mediaShow, 
portalManager: sendSMSLoginCode, smsLoginEnabled, 
/fileDownload.do: showRTE, 
loginUserManager: getLockTime, 
/main.do: login4Ucpc, index, changeLocale, main, login, logout4Vjoin, hangup, headerjs, logout4Session, updateLoginSeed, logout, qrCodeHelp, login4Ucpc3, login4Vjoin, logout4ZX, 
/trustdo/A8/XRD.do: getLoginAccount, webLogin, getLoginAcctoken, 
/share.do: index, 
/edoc/edocUpgradeControllor.do: download, upgrade, 
/m3/mClientBindController.do: bindApply, 
/uploadService.do: processUploadService, 
/uc/rest.do: sendsms, isQrLogin, getLoginsecurityMsg, smsrequired, commonPierce, getBgTimeStamp, getDigitalCodeInfo, downloadImage, testIp, 
/m3/homeSkinController.do: getSkinImageUrl, downloadImage, 
/colView.do: index, 
/autoinstall.do: ieSetDown, downloadAssistant, regInstallDown64, regInstallDown, 
/caAccountManagerController.do: findKeyNumByLoginName, 
/elearning.do: pcRedirect, error, m3Redirect, message, 
/wechat/miniprogram.do: bindMemberPhone, bind, unbind, a8home, login, 
/portal/spaceController.do: showThemSpace, 
/identification.do: getSessionId, 
/fddCallbackController.do: synch, asynch, 
m3ProductManager: productStatus, productInfo, 
/ocipEdoc.do: index, 
/m3/loginController.do: transLogin, getProfile, transLogout, 
/fileUpload.do: showRTE, 
qrCodeLoginManager: isLogin, 
/form/formUpgrade.do: viewUpgrade, toUpgrade, upgrade, 
/seeyonReport/seeyonReportController.do: redirectSeeyonReport, 
formtalkFormMapperController.do: importFormtalkData, 
/thirdpartyController.do: access, mailAuth, show, index, logoutNotify, 
/m3/transModeController.do: getTransModeForMobile, 
/genericController.do: index, 
/personalBind.do: retrievePassword, sendVerificationCodeToBindEmail, getBindTypeByLoginName, validateVerificationCode, isCanUse, sendVerificationCodeToBindNum, 
/commonimage.do: showImage, 
/individualManager.do: resetPassword, 
meetingAjaxManager: meetingPanelData, meetingPanelDisplay, 
/wechat/dingding.do: newMain, binding, index, main, viewh5Message, newIndex, 
```

当路由包含这个`hash`表的`key`值，并且所调用的方法在对应的`value`（类型`HashSet`）中，则表示无需验证即可访问的.。

```text-x-java
if (user == null) {
    AppContext.removeThreadContext("SESSION_CONTEXT_USERINFO_KEY");
    isAnnotationNeedlessLogin = this.isNeedlessCheckLogin(context);
    LoginTokenUtil.checkLoginToken(request);
    if (!isAnnotationNeedlessLogin) {
        isAnnotationNeedlessLogin = this.isSocialAuth(request, context);
    }
}
```

如果即没有有效的cookie表明用户身份，也不在前面的范围，则会进入`isSocialAuth()`。这部分也有一个白名单

```text-x-java
static {
    socialUrls.put("/wechat/feishu.do", new HashSet(Arrays.asList("newMain", "viewh5Message")));
    socialUrls.put("/wechat/pcapp.do", new HashSet(Arrays.asList("transferPageFromWxCoreServer", "gotoPcApp")));
    socialUrls.put("/wechat/feishu/approvalData.do", new HashSet(Arrays.asList("index")));
    socialUrls.put("/zhifei/feishu.do", new HashSet(Arrays.asList("newMain", "viewh5Message")));
    socialUrls.put("/zhifei/pcapp.do", new HashSet(Arrays.asList("transferPageFromWxCoreServer", "gotoPcApp")));
    socialUrls.put("/zhifei/feishu/approvalData.do", new HashSet(Arrays.asList("index")));
}
```

##### RestAuthenticator

当路由满足如下条件，进入该类型验证器

```text-x-java
private static boolean isRest(String uri, HttpServletRequest request) {
    return uri.startsWith(request.getContextPath() + "/rest/");
}
```

该验证器的`authenticate`方法的所有`return`语句返回的都是`true`，那它后续是怎么判断一个请求是否真的验证了呢？

首先，如果某个请求无法通过验证，它进一步调用

```text-x-java
this.unauthorized(request, "错误信息" + path);
```

把错误信息放入全局context中

```text-x-java
AppContext.putThreadContext("REST_UNAUTHORIZED_MESSAGE", message);
```

而对该请求的后续验证会交给`glassfish.jersey`库中设置的`Filter`，`AuthorizationRequestFilter`，除此之外还有`3`个，在`web.xml`中的配置如下

```text-xml
<servlet>
<servlet-name>rest</servlet-name>
<servlet-class>org.glassfish.jersey.servlet.ServletContainer</servlet-class>
<init-param>
    <param-name>jersey.config.server.provider.packages</param-name>
    <param-value>
        com.seeyon.ctp.rest.resources,com.fasterxml.jackson.jaxrs,com.fasterxml.jackson.jaxrs.json,com.fasterxml.jackson.jaxrs.xml,com.seeyon.ctp.rest.filter
    </param-value>
</init-param>
<init-param>
    <param-name>jersey.config.server.provider.classnames</param-name>
    <param-value>com.seeyon.ctp.rest.filter.AuthorizationRequestFilter,com.seeyon.ctp.rest.filter.ResponseFilter,com.seeyon.ctp.rest.filter.WebOfficeLogFilter,org.glassfish.jersey.media.multipart.MultiPartFeature,com.seeyon.ctp.rest.filter.ResourceCheckRoleAccessFilter</param-value>
</init-param>
<init-param>
    <param-name>jersey.config.server.provider.scanning.recursive</param-name>
    <param-value>false</param-value>
</init-param>
<load-on-startup>4</load-on-startup>
</servlet>
```

这个过滤器在发现`AppContext.getThreadContext("REST_UNAUTHORIZED_MESSAGE")`不为`null`时，就会把当前请求的状态标记为`UNAUTHORIZED`，导致无法未授权访问。

```text-plain
void unauthorized(Object req, String message) {
    ((ContainerRequestContext)req).abortWith(this.error(Status.UNAUTHORIZED, message));
}
```

回过头看`RestAuthenticator#authenticate`，当`uri`以如下白名单为开头或等于它时，则可以未授权访问

```text-plain
private static List<String> anonymousWhiteList = Arrays.asList(
    "token",
    "application.wadl",
    "jssdk",
    "getRestCompare",
    "authentication",
    "cap4/form/pluginScripts",
    "orgMember/avatar",
    "orgMember/groupavatar",
    "m3/appManager/getAppList",
    "m3/appManager/download",
    "m3/message/unreadCount/",
    "m3/login/refresh",
    "m3/login/verification",
    "m3/theme/homeSkin",
    "m3/theme/homeSkinDownload",
    "m3/common/service/enabled",
    "uc/systemConfig",
    "product/hasPlugin",
    "product/dongle/data",
    "password/retrieve",
    "m3/appManager/checkEnv",
    "m3/security/device/apply",
    "meeting/meetingInviteCard",
    "microservice",
    "media/verify",
    "ocip/forwardTo"
);
```

##### TokenAuthenticator

进入这个验证器的逻辑代码如下，满足如下条件就会调用它

```text-plain
if (isSpringController(uri, req)) {
    result.setAuthenticator(controllerAuthenticator);
    result.authenticate(req, resp);
    if (result.getResult()) {
        if (tokenAuthenticator.validate(uri, req)) {
            result.setAuthenticator(tokenAuthenticator);
            result.authenticate(req, resp);
            return result;
        }

        if (isAjax(uri, req)) {
            result.setAuthenticator(ajaxAuthenticator);
            result.authenticate(req, resp);
        }
    }
} else if (tokenAuthenticator.validate(uri, req)) {
    result.setAuthenticator(tokenAuthenticator);
    result.authenticate(req, resp);
}
```

里面的内容涉及到特定的参数值，先不看，感觉没啥用。

##### WebOfficeAuthenticator

##### AjaxAuthenticator

进入条件

```text-plain
private static boolean isAjax(String uri, HttpServletRequest request) {
    return uri.endsWith("ajax.do");
}
```

首先，不允许通过ajax请求直接访问dao接口

未授权可访问的白名单和前面的`needless`一样

##### V3xAjaxAuthenticator

进入条件

```text-plain
private static boolean isV3xAjax(String uri, HttpServletRequest request) {
    return uri.endsWith("getAjaxDataServlet");
}
```

方法白名单如下

```text-plain
private static final Set<String> WHITE_LIST = new HashSet(
    Arrays.asList(
        "ajaxColManager_colDelLock",
        "ajaxEdocSummaryManager_deleteUpdateObj",
        "ajaxEdocManager_ajaxCheckNodeHasExchangeType",
        "ajaxEdocSummaryManager_deleteUpdateRecieveObj"
    )
);
```

##### SOAPAuthenticator

进入条件

```text-plain
private static boolean isSOAP(String uri, HttpServletRequest request) {
    return uri.startsWith(request.getContextPath() + "/services/");
}
```

一律返回true，不作判定。

因为正常来讲，SOAP服务，也就是webservice是需要通过密码进行验证的，除非配置文件中的密码为空。

##### ServletAuthenticator

当uri以.psml结尾时，或以如下内容为前缀时

```text-plain
private static List<String> servlets = Arrays.asList(
    "getAJAXMessageServlet",
    "getAJAXOnlineServlet",
    "htmlofficeservlet",
    "isignaturehtmlH5servlet",
    "isignaturehtmlservlet",
    "login/sso",
    "login/ssologout",
    "m-signature/",
    "ofdServlet",
    "office/cache/",
    "officeservlet",
    "pdfservlet",
    "sursenServlet",
    "verifyCodeImage.jpg"
);
```

进入该验证器，未授权白名单如下，`uri`以如下内容为前缀即可。

```text-plain
private static List<String> anonymousWhiteList = Arrays.asList("login/sso", "verifyCodeImage.jpg", "getAJAXOnlineServlet");
```

##### JSPAuthenticator

需`uri`满足如下后缀

```text-plain
return lowUri.endsWith(".jsp")
    || lowUri.endsWith(".jspa")
    || lowUri.endsWith(".jsw")
    || lowUri.endsWith(".jsv")
    || lowUri.endsWith(".jtml")
    || lowUri.endsWith(".jspf")
    || lowUri.endsWith(".jhtml");
```

这里会检查`jsp`文件的时间戳，若被修改则拒绝访问，但是只对如下文件进行检查，时间戳存储在`HashMap`中的`value`中

```text-plain
result = {HashMap@36263}  size = 15
 "ssoproxy/jsp/ssoproxy.jsp" -> {Long@36301} 1663557294681
 "main/login/default/login.jsp" -> {Long@36303} 1663557294608
 "common/print/printForm.jsp" -> {Long@36305} 1663557204938
 "colsso.jsp" -> {Long@36307} 1663556952308
 "index.jsp" -> {Long@36309} 1663557041643
 "common/print/print.jsp" -> {Long@36311} 1663557204937
 "common/print/govdocPrint.js.jsp" -> {Long@36313} 1663556947910
 "thirdpartysso/listVoucherA8Form.jsp" -> {Long@36315} 1663556952512
 "common/js/addDate/date.jsp" -> {Long@36317} 1663557204736
 "apps_res/print/print.jsp" -> {Long@36319} 1663557041784
 "indexOpenWindow.jsp" -> {Long@36321} 1663557041647
 "main/common/login_header.jsp" -> {Long@36323} 1663557294613
 "common/detail.jsp" -> {Long@36325} 1663557204737
 "common/form/common/print/printForm.jsp" -> {Long@36327} 1663557239192
 "common/print/captPrintForm.jsp" -> {Long@36329} 1663557204705
```

未授权白名单如下

```text-plain
result = {HashSet@36330}  size = 10
 0 = "pc2a8.jsp"
 1 = "ssoproxy/jsp/ssoproxy.jsp"
 2 = "gke.jsp"
 3 = "pc.jsp"
 4 = "colsso.jsp"
 5 = "gke2a8.jsp"
 6 = "index.jsp"
 7 = "thirdpartysso/listVoucherA8Form.jsp"
 8 = "lightweightsso.jsp"
 9 = "cache_clear_pending.jsp"
```

##### AttackURIAuthenticator

一律返回false

### Clazz文件的反编译

如果遇到了clazz或无法反编译的class文件，请参考 [致远A8 v8.1 clazz文件的反编译](clazzDecompile.md)

Refernece
---------

1.  [https://guage.cool/seeyon/](https://guage.cool/seeyon/)
