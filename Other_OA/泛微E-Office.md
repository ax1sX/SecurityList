# 泛微E-Office

## 环境配置
### 环境下载
https://service.e-office.cn/download

https://pan.baidu.com/s/1mi6OFUS#list/path=%2F&parentPath=%2FEo-9.0pc%E7%AB%

环境安装为一体安装包，直接双击点exe，设定完安装目录安装（例如C:\E-office_Server）即可自动安装。源码在web根目录（v9系列是webroot，v10系列是www）。

### 解密与调试
v9系列使用php Zend（v9.5对应php Zend 5.x，低版本对应的Zend版本更低）进行加密该目录的文件，使用**SeayDzend工具**或者百度**php zend解密在线网站**进行解密即可（EOffice低版本需用在线解密）。由于zend解密不完全，不能直接用解密的webroot目录替换原来的webroot目录。只能通过替换单个页面，自行设定断点，dump出来变量的内容。

v10系列使用ioncube 10加密，使用[easytoyou.com](https://easytoyou.eu/)（月付费80+RMB，需挂代理访问）解密。p牛在`https://govuln.com/tool/phpdec/`提供了对该网站的免费批量解密通道，搭建了一个sase（仅限代码审计星球的小伙伴使用）。

### 账户密码

开启后默认访问路径：http://127.0.0.1:8081，默认的用户名密码如下
```
v10系列
admin 123456

v9系列
admin 密码默认为空，首次登陆后不会强制修改用户密码
```

### 版本查询
```
v10
http://ip:8010/eoffice10/server/public/api/empower/get-system-version -> 查询版本
http://ip:8010/eoffice10/server/public/api/empower/{pc|mobile}-empower -> pc｜mobile的版本和授权信息

v9
/inc/reg.php ｜ /inc/reg_check.php ｜ /inc/reg_look.php ｜ /inc/oa_type.php  -> 查询版本
```

### 补丁安装
v10可以通过服务管理平台直接在线更新；手动更新，直接把补丁包内的所有内容替换原安装目录和web目录即可。

v9更新需要手动将补丁包的webroot目录覆盖原webroot目录，然后登录系统，系统会自动进行检测，切记不能关闭登录窗口，检测完毕后会提示申请更新的对话框，点击更新即可。如更新失败，重复上述操作。


## 架构分析

### 安装目录
E-Office采用php 7.4.30 + apache 2.4.41 + mysql 5.5.53 + redis 3.0.504 + node.js 13.14.0。由于是一体化安装，相关配置都在安装目录下，安装目录内容如下
```
｜—apache
   ｜—conf/httpd.conf（http默认端口8010）
｜—attachment（附件上传地址）
｜—bin
｜—logs
｜—mysql
   ｜—my.ini（端口3310，默认账户root/weoffice10）
｜—nodejs
｜—php
   ｜—php.ini
｜—redis
    ｜—redis.windows.conf（redis端口6379，默认只能本地访问`bind 127.0.0.1`，默认密码：eoffice10redis）
｜—temp
｜—www（源码，\eoffice10\version.json中包含版本）
｜—config.ini
｜—uninst.exe
```

E-Office整体架构采用laravel lumen框架（laravel的轻量版），查看`/www/eoffice10/server`下的目录结构（类似laravel，但有精简）
```
app: 程序核心源码
bootstrap: 包含框架启动文件app.php
config: 配置文件
database: 数据库文件
ext: 扩展
nodejs: js文件
public: 包含index.php,进入应用程序的请求入口
resources: 视图和未编译的资源文件
routes: 路由定义，包含web.php（有的程序包含api.php、console.php等）
storage: 包含由Balde框架生成的基于目录的模板、文件和缓存
vendor: 包含composer依赖
```
其中app下的目录结构，核心如下
```
Console: 包含应用自定义的Artisan命令
EofficeApp: Eoffice功能模块
EofficeCache: Eoffice缓存
Helpers: 方法定义
Http: 包含控制器、中间件以及表单请求等。几乎所有通过Web进入应用的请求处理在这进行
Listeners: 监听器处理触发事件
Providers: 服务提供者，在容器中绑定服务、注册事件等。
Utils: 工具类，加解密、编码等
```
Laravel框架的相关审计，值得关注的点如下
```
网站路由（routes/web.php）
控制器（app/Http/Controllers）
中间件（app/Http/Middleware）
Model（app/Models）
网站配置（config）
第三方扩展（composer.json）
```

### 路由特点

参考laravel框架，路由配置位于`routes/web.php`，请求入口位于`/eoffice10/server/public/index.php`。由于web.php中定义了路由前缀为`api`。所以E-Office的路由访问为`/eoffice10/server/public/api/`加上访问的模块，模块可以在web.php中查询对应的路由，如果没有查到，在每个模块文件夹的内部还设置了routes.php。这部分参见web.php的第一个路由组
```php
$router->group(["namespace"  => "App\\EofficeApp",
                "middleware" => "decodeParams|authCheck|ModulePermissionsCheck|menuPower|openApiMiddleware|syncWorkWeChat|verifyCsrfReferer",
                "prefix"     => "/api"], function ($router) {
    register_routes($router, $moduleDir, $modules);
}
```
路由组中配置了中间件。所谓中间件是一种过滤HTTP请求的机制，进行身份验证、CSRF保护、执行任务等，这些都位于`app/Http/Middleware`。类似于Java中的Filter过滤器。

第二个路由组，定义为`$noTokenApi`，在访问时不会校验api_token，点击展开`$noTokenApi`变量

<details>
   <summary>$noTokenApi</summary>
   <pre>
   <code>
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
   </code>
   </pre>
</details>



**api token（令牌）获取**

需要api token验证的路由，在请求内附上token才能正常请求。传递方式有两种：api_token参数和header头Authorization字段`Authorization:Bearer 令牌`。令牌需要用户登录后生成，可以通过chrome浏览器f12-应用-本地存储空间搜索`loggedUsersIMToken`密钥字段获取。令牌传输的相关错误和异常码，可以在api文档中查看。	


## 历史漏洞

|漏洞名称|访问路径|影响版本|
|:---:|:---:|:---:|
|detail.php 未授权sql注入漏洞|`/general/crm/linkman/query/detail.php`|<=9.0_141103|
|index.php sql注入漏洞|`/E-mobile/App/System/UserSelect/index.php`|<=9.5_20220113|
|UploadFile.php 文件上传漏洞|`/webroot/general/index/UploadFile.php`|<=9.5|
|OfficeServer2.php 未授权文件上传漏洞|`/iWebOffice/OfficeServer.php和/iWebOffice/OfficeServer2.php`|<=8|
|IWebOfficeService.php 未授权文件上传漏洞|`eoffice10/server/app/EofficeApp/IWebOffice/Services/IWebOfficeService.php`|<10|
|gotoeoffice.php 未授权文件包含漏洞|`/gotoeoffice.php`|<=v9.5_20220113|
|登录绕过+文件上传漏洞|`/general/hrms/manage/hrms.php`|<9.5_20220113|
|main.php 信息泄漏漏洞|`/UserSelect/main.php`|<=9.5|

