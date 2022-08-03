# SecurityList

### 泛微Ecology ###

#### 补丁 ####
https://www.weaver.com.cn/cs/securityDownload.html?src=cn

#### 历史漏洞 ####
```
(1) BeanShell RCE
POST /weaver/bsh.servlet.BshServlet

(2) Soap XStream RCE: 
POST /services%20/WorkflowServiceXml
Ref: https://www.anquanke.com/post/id/239865

(3) 前台Zip文件上传
POST /weaver/weaver.common.Ctrl/.css?arg0=com.cloudstore.api.service.Service_CheckApp&arg1=validateApp
GET /cloudstore/xxx.jsp

(4) 文件上传
POST /weaver/com.weaver.formmodel.apps.ktree.servlet.KtreeUploadAction?action=image
Ref: https://mp.weixin.qq.com/s?__biz=MzkxMzIzNTU5Mg==&mid=2247483666&idx=1&sn=e70efe98c064e0f1df986e2b65c1a608&chksm=c1018af5f67603e39ce4d6e9375875e63e7b80633a1f99959f8d4652193ac3734765a99099ea&mpshare=1&scene=23&srcid=0414cqXy50udQOy19LYOMega&sharer_sharetime=1618332600979&sharer_shareid=d15208c7b27f111e2fe465f389ab6fac#rd

(5) 文件上传
POST /weaver/weaver.workflow.exceldesign.ExcelUploadServlet?method=uploadFile&savefile=pass.jsp
Ref:https://mp.weixin.qq.com/s?__biz=MzkxMzIzNTU5Mg==&mid=2247483674&idx=1&sn=ce1c56a670587df0a33201a62a4b6e2d&chksm=c1018afdf67603eb15bea96e668bc0279b63f241654beb000da3c7e7333d8545c4c3217d0576&scene=178&cur_album_id=1824092566640705544#rd

(6) 数据库配置文件读取
POST /mobile/DBconfigReader.jsp

(7) Oracle注入
/mobile/browser/WorkflowCenterTreeData.jsp?node=wftype_1&scope=2333

(8) 日志泄漏
/hrm/kq/gethrmkq.jsp?filename=1

(9) 文件上传
POST /workrelate/plan/util/uploaderOperate.jsp
POST /OfficeServer

(10) 文件上传
POST /page/exportImport/uploadOperation.jsp

(11) Cookie泄露
POST /mobile/plugin/VerifyQuickLogin.jsp

(12) SQL注入
GET /api/ec/dev/locale/getLabelByModule

(13) 代码指向
POST /api/integration/workflowflow/getInterfaceRegisterCustomOperation
```

#### 代码审计特点 ####

(1) jsp访问路径均为ecology根目录到该jsp的路径，例如jsp的绝对路为`D:/ecology/addressbook/AddressBook.jsp`，那么该jsp的访问路径为`http://ip:port/addressbook/AddressBook.jsp`
(2) 管理员账号位于表HrmResourceManager，密码为md5加密

