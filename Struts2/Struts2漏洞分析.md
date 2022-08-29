## 漏洞分析

### 简介
Struts2是一个MVC（Model View Controller）框架。如果利用Struts2写一个简单的demo。需要定义一个`Action类 + 视图.jsp + struts.xml`。Action类响应用户请求，视图.jsp文件控制页面上显示的内容。struts.xml匹配Action类和视图.jsp。在jsp的头部加入`<%@ taglib prefix="s" uri="/struts-tags" %>`，用于表明Struts2框架。这样就可以引入很多标签来控制视图。   

常用标签包括：控制标签(`<s:if>, <s:iterator>，控制判断、循环等`)、数据标签(`<s:action>,<s:bean>,<s:property>,<s:set>, <s:url>, <s:a>`)、UI标签(`<s:textfield>, <s:textarea>, <s:select> 代表文本框、字段域、下拉框等页面布局内容`)

Struts2的架构处理请求的流程：`Dispatcher(ActionMapper+FilterDispatcher) -> ActionProxy -> ActionInvocation -> 多个Interceptor -> Action -> Result`。其中ActionProxy的内容是从struts.xml中读取的配置。这个流程属于控制流体系。   

Struts2还有个数据流体系： `ActionContext和ValueStack`。其中ValueStack是ActionContext的一个组成部分。 ActionContext是数据载体，负责数据存储和共享。ValueStack则负责计算，提供了表达式引擎计算的场所。

Struts2漏洞的入口是`OgnlUtil.getValue()`会对表达式进行解析，攻击者可以通过OGNL特性和语法构造恶意表达式。从不同的Interceptor或者标签入手最终触发`OgnlUtil.getValue()`。

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


### S2-003













