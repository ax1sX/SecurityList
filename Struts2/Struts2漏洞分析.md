## 漏洞分析

Struts2是一个MVC（Model View Controller）框架。如果利用Struts2写一个简单的demo。需要定义一个`Action类 + 视图.jsp + struts.xml`。Action类响应用户请求，视图.jsp文件控制页面上显示的内容。struts.xml匹配Action类和视图.jsp。在jsp的头部加入`<%@ taglib prefix="s" uri="/struts-tags" %>`，用于表明Struts2框架。这样就可以引入很多标签来控制视图。   

常用标签包括：控制标签(`<s:if>, <s:iterator>，控制判断、循环等`)、数据标签(`<s:action>,<s:bean>,<s:property>,<s:set>, <s:url>, <s:a>`)、UI标签(`<s:textfield>, <s:textarea>, <s:select> 代表文本框、字段域、下拉框等页面布局内容`)

Struts2的架构处理请求的流程：`Dispatcher(ActionMapper+FilterDispatcher) -> ActionProxy -> ActionInvocation -> 多个Interceptor -> Action -> Result`。其中ActionProxy的内容是从struts.xml中读取的配置。这个流程属于控制流体系。   

Struts2还有个数据流体系： `ActionContext和ValueStack`。其中ValueStack是ActionContext的一个组成部分。 ActionContext是数据载体，负责数据存储和共享。ValueStack则负责计算，提供了表达式引擎计算的场所。

**Struts2历史漏洞**   

| 漏洞名 | 问题定位 | POC格式 |
|:----:|:----:|:----:|
| S2-001 | `<s:textfield>` | `%{#a,#b,...,#c}` |
| S2-003, S2-005 | `ParametersInterceptor` | `('\u0023')(bla)(bla)&(a)(('\u0023')(bla))` |
| S2-009 | `ParametersInterceptor` | `(#a,#b,...,#c)(meh)&z[(name)('meh')]` |
| S2-007 | `ConversionErrorInterceptor` | `'+(#a,#b,...,#c)+'` |
| S2-008 | `CookieInterceptor` | `(#a,#b,...,#c)` |
| S2-012 | `<result type="redirect">/x.jsp?name=${name}</result>` | `%{#a,#b,...,#c}` |
| S2-013, S2-014 | `<s:a>,<s:url> & includeParams=all` | `${(#a,#b,...,#c)}` |
| S2-015 | `<action name="*"><result>{1}.jsp</result></action>` | `${#a,#b,...,#c}` |
| S2-016, S2-017 | `"action:", "redirect:" or "redirectAction:` | `${#a,#b,...,#c}` |
| S2-019 | `DebuggingInterceptor` | `(#a,#b,...,#c)` |
| S2-029 | `<s:textfield name="%{xxx}">` | `((#a)(@m)) or (#a,#b...,#c) or (#a,#b...,@m)` |
| S2-032, S2-033, S2-037 | `"method:"` | `#a,#b,...,#c` |
| S2-045 | `content-type："multipart/form_data"` | `%{(#a).(#b).(#c)}` |
| S2-046 | `Content-Disposition / Content-Length` | `%{(#a).(#b).(#c)}` |
| S2-052, S2-055 | `ContextTypeInterceptor` | |
| S2-059, S2-061 | `<s:a>,<s:url> & id="%{Name}"` |  | 


















