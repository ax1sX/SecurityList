# TRS_WCM（内容协作平台）

TRS北京拓尔思信息技术股份有限公司，旗下产品包含WCM（内容管理系统）、WAS（文本检索系统）、IDS（身份管理系统）等。

WCM安装，（以WCM7为例）双击`TRSWCMV7_Build1015_6612_20130506_Windows.exe`，按照提示一直进行下一步即可。完成后访问`http://ip:8086/wcm`。端口根据安装时的设定进行更改。登录时默认的用户名密码如下
```
admin trsadmin
```

帮助文档： https://hd.gov.cn/bz/201906/P020190620365727503462.pdf


## 架构分析

核心文件都位于Tomcat目录下`/TRS2013/Tomcat/webapps/wcm/`，wcm下主要包含功能模块（jsp）和`/WEB-INF`文件夹。jsp的访问路径是到wcm的相对路径

web.xml中的定义的不参与过滤的jsp和路径
```
	<filter>
		<filter-name>LoginCheckFilter</filter-name>
		<filter-class>com.trs.servlet.LoginCheckFilter</filter-class>
		<init-param>
			<param-name>notFilterJsp</param-name>
			<param-value>
				login.jsp,login_dowith.jsp,loginpage.jsp,reg_newuser.jsp,reg_newuser_dowith.jsp,user_exist.jsp,license_edit.jsp,license_edit_dowith.jsp,govcenter.do,govfileuploader.do,infoview.do,deployerlogin.jsp,deployerlogin_dowith.jsp,index.jsp,receiveMAS.jsp
			</param-value>
		</init-param>
		<init-param>
			<param-name>notFilterPath</param-name>
			<param-value>
				WCMV6/gkml/sqgk,app/interview,app/special/design_for_interview.jsp,app/infoview/gateway
			</param-value>
		</init-param>
  </filter>
```
web.xml中定义的路由和对应类
```
/clusterservice -> com.trs.cluster.ext.wcm.servlet.AutoRestartServlet
/center.do -> com.trs.webframework.controler.servlet.ServiceControler
/verifycode.do -> com.trs.weblet.util.verfiycode.VerifyCodeServlet
/infoview.do -> com.trs.components.infoview.filter.InfoviewDataImportFilter
/govcenter.do -> com.trs.webframework.controler.servlet.NoLoginServiceControler
/fileuploader.do -> com.trs.webframework.controler.servlet.FileUploader
/govfileuploader.do -> com.trs.webframework.controler.servlet.NoLoginServiceControler
/app/video/ReceiveMASServlet -> com.trs.components.video.ReceiveMASServlet
```

