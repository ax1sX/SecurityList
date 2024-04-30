# Thinkphp框架鉴权分析

php框架鉴权方式很多和路由相关，框架与框架之间的鉴权方式类似，以thinkphp为例。thinkphp路由基本上是支持普通模式、混合模式（rewrite默认）和强制路由模式。这三种路由模式可以通过设置`app.php`进行配置。选择不同的路由模式可以相应配合不同形式的鉴权进行验证。

## 1. Route类动态参数

利用Route类option方法配置rule参数进行角色访问校验。

```php
Route::get('view/:name$', 'News/read')->option('rule', 'admin');
```

在`application`目录下不同 `module`目录里面通过`route.php`在针对个别或特定模块的路由进行路由规则的设定的同时，不仅可以设置请求方式是get还是post等，可以通过option方法`option("rule", '指定的角色')`设置什么用户角色可以访问路由。同样也可以在全局的`route.php`设置角色校验。

这里容易出现开发错误，option和append方法都可以进行Route参数配置，但不同的是，option 方法会覆盖已有的参数，而 append 方法会追加参数。因此开发过程中，不恰当使用后者append方法可能导致未授权访问的漏洞。

同样`rule()`也可以进行校验：

```
Route::get('view/:name$', 'News/read')->rule('admin');
```

p.s. [thinkphp 5.1 路由参数](https://www.kancloud.cn/manual/thinkphp5_1/353965)

## 2. 设置鉴权中间件（路由白名单）

配合Route类强制设定某些类比如通过鉴权中间件后才行：

```php
Route::rule('hello/:name','hello')->middleware('Auth');
```

也可以分组`group`后进行`middleware`校验。但该情况需要`thinkphp >= 5.1.6`。

进行全局中间件权限校验可以进行`middleware.php`配置：

```php
<?php
  return [
    \app\http\Authorization::class
  ];
```

和route.php一样也可以针对模块目录建立middleware.php文件进行部分鉴权。

p.s. [thinkphp 5.1 中间件](https://www.kancloud.cn/manual/thinkphp5_1/564279)

其实这种和建立白名单、黑名单类似的。程序动态加载所有类之后，解析完路由，通过比对模块和调用的controller，从而判定是否进行鉴权。将配合比对的路由需要建立某个配置文件或存储在服务器的数据库中，动态获取存放在代码数组中，然后进行比对。只不过thinkphp在官方手册中指明通过路由中间件完成。

## 3. 前后置行为检测：beforeAction和afterAction

[thinkphp api token](https://juejin.cn/s/thinkphp api token)

[HTTP Token 使用方式: Basic Token（淘汰）v.s Bearer Token（Auth2.0更安全）](https://xiang753017.gitbook.io/zixiang-blog/security/http-token-shi-yong-fang-shi-basic-token-v.s-bearer-token)

类似中间件，对请求流进行拦截后进行检测、过滤和处理。在这里通常检测http请求报文中header的token是否有效。

整体的鉴权逻辑是：

1. 在用户登录成功后，生成一个Token，并将Token保存到用户表（数据库或redis）中的Token字段中，同时将Token返回给客户端。
2. 客户端在后续的API请求中携带该Token，一般可以将Token作为请求头信息中的Authorization字段进行传递。
3. 服务器端接收到API请求后，从请求头中获取Token，并根据Token查询用户表，判断该Token是否有效。
4. 如果Token有效，允许API请求继续执行；如果Token无效，返回401 Unauthorized错误。

beforeAction和afterAction分别是前置方法检测和后置方法检测。 一般鉴权在beforeAction中检测，主要针对api检测，设置ApiAuth类的beforeAction方法。其他Api的Controller继承该ApiAuth类即可。

```php
class ApiAuth extends \think\Controller
{
    public function beforeAction()
    {
        $token = $this->request->header('Authorization');
        $user = User::where('token', $token)->find();
        if (!$user) {
            $this->error('Unauthorized', null, null, 401);
        }
    }
}
```

这种token校验方式可以是自己编写的校验方式，也可以利用jwt token校验，还可以是Oauth 2.0令牌等等。在header中形式多为`Authoritarian: Bear xxxxx`（http默认用于传递token的形式），也可以在代码中添加header头自定义token传递模式。

## 4. 验证码登录

验证码配合登录主要还是验证作用，实际情况中相对于其他方式来说不对，因此简单说一下。但是遇到过两种情况：其一，用户输入验证码错误，后台不会清空session，该session在获取的时候是生成后就存放在服务器上了（可能是放在数据库也能redis或者文件格式也有）。由于session一般是全局使用的，某些模块判断当前session不为空，就允许访问该功能。乌云库有一个漏洞案例，说的是thinkphp没有重置session导致验证码可以爆破，但是衍生出更大的影响也可以绕过登录，获取一个低权限：[【wooyun-2015-0110497】ThinkPHP 默认配置导致验证码暴力破解（验证码错误session不重置）](https://wy.zone.ci/bug_detail.php?wybug_id=wooyun-2015-0110497)。

其二，由于测试原因，代码中会固定一个验证码，或者直接硬编码了一个验证码，比对输入的验证码是否等于该验证码。如果输入的预设好的验证码就可以获得一个低权限session。

```php
//captcha.php 自定义获取验证码
<?php
  ...
  $captcha = input('captcha');
  $obj = new \app\common\System\Captcha();
  $code = '123456';  
  if ($captcha != $code){
      if ($obj->check($code, $captcha)){
        return 0;
      }
  } else {
    session_start();
    session_id(code);
    ... //进一步保存session到具体配置的形式中
  }

//book.php 某功能php页面
<?php 
  if (empty($_SESSION)){
    return 0;
  } else {
    ...
    //具体功能代码
  }
```

## 5. 实现auth类和基于RBAC的第三方鉴权库

思路大致是在形如`applicaiton/admin/controller`admin模块的controller目录下实现AuthController，其他类通过继承该类完成权限校验。特别是用于api接口，Common登录鉴权写于initialize方法或者直接写login方法进行鉴权。

1. 实现`application/admin/controller/AuthController.php`的`initialize`方法，方便后续继承的类自动调用该方法。

```php
<?php

namespace app\admin\controller;

use think\Controller;
use think\Db;

class AuthController extends Controller
{
    public function initialize()
    {
        header('Access-Control-Allow-Origin: *');
        $login_token = input('login_token', 0);
        $reslut = model('Admin')->check_login_token($login_token);
        if ($reslut['code']) {
            return $reslut;
        } else {
            return "login first!";              
        }
      ......
```

2. `admin`模块需要鉴权的controller直接继承`AuthController`即可：

```php
<?php

namespace app\admin\controller;

use think\Controller;

class Admin extends AuthController //直接继承，后面直接写功能代码。不用再写鉴权代码
{

    public function get_admin_list()
    {
        ......
```

除了判断是否有权限访问模块，如果认为自我实现代码进行鉴权麻烦，还可以使用框架官方推荐的第三方库或者官方库。官方在thinkphp 3.x代码库中存在过一个[auth代码](https://github.com/top-think/thinkphp/blob/master/ThinkPHP/Library/Think/Auth.class.php)，不过后来没有了。后来基于tp5开发了类似的auth类：[5ini99/think-auth](https://github.com/5ini99/think-auth)。在thinkphp社区也有介绍：[基于thinkphp5的auth权限认证扩展](https://www.thinkphp.cn/extend/873.html)。还有一种不同于auth的方式，`thinkphp-auth`（github很多同名库）是基于RBAC建立的一种给thinkphp鉴权的系统。RABC鉴权是一种基于角色的访问控制机制，它通过将权限分配给角色，再将角色分配给用户来管理系统资源的访问权限。目前官方没有写过鉴权库，github上能找到的都是第三方。
