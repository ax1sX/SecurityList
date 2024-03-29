Struts2常见的配置文件包括：`struts.xml、struts-config.xml、struts.properties`等。Struts2首先要在`web.xml`中进行配置。

## web.xml

```xml
<filter>
	<filter-name>struts2</filter-name>
	<filter-class>
org.apache.struts2.dispatcher.filter.StrutsPrepareAndExecuteFilter
	</filter-class>
</filter>
<filter-mapping>
	<filter-name>struts2</filter-name>
	<url-pattern>/*</url-pattern>
</filter-mapping>
```

**`<url-pattern>`** 还有一种常见的写法如下。

```xml
<url-pattern>.action</url-pattern>
```

当值为`/*`时，所有的路由都由Struts2进行解析，此时路由扩展名默认为`.action`。当值为`.action`时，只解析特定`.action`后缀的路由。

需要注意，Struts2扩展名默认为`.action`，Struts1扩展名默认为`.do`。

**`<filter-class>`**

另外，如果是Struts版本`<2.1.3`，`<filter-class>`标签的值如下。`2.1.3`之后的版本值是`StrutsPrepareAndExecuteFilter`

```xml
<filter-class>
	org.apache.struts2.dispatcher.FilterDispatcher
</filter-class>
```

**`init-param`属性**

如果filter标签添加了如下的`init-param`属性，那么扩展名为`.json`。和在`properties`文件中添加配置信息`struts.action.extension=json`效果一样。

```xml
<filter>
    <filter-name>struts2</filter-name>
    <filter-class> org.apache.struts2.dispatcher.FilterDispatcher </filter-class>
    <init-param>
        <param-name>struts.action.extension</param-name>
        <param-value>json</param-value>
    </init-param>
</filter>
```



## struts.xml

`struts.xml`用于开发配置，可用于覆盖默认配置`default.properties`。`struts.xml`包含`action、result、interceptor、constant、package、global-results`等配置。大概的配置文件形式如下

```xml
<struts>
   <constant name="struts.devMode" value="true" />
   <package name="helloworld" extends="struts-default">
      <action name="hello" class="xx.HelloWorldAction" method="execute">
            <result name="success">/HelloWorld.jsp</result>
      </action>
   </package>
</struts>
```



### constant

常量配置定义了很多全局的配置，例如文件上传的大小限制、编码方式等。如下几个配置和路由相关。配置扩展名为`action`。用Convention插件，指定了只在类路径下查找结尾为`Action`的类。这样就无需在配置文件中配置每个`Action`。

```xml
<struts>
  <!--启用Struts2的动态方法调用功能，访问方式为action!method。允许在Actin中直接调用方法而不需要在struts.xml中配置-->
  <constant name="struts.enable.DynamicMethodInvocation" value="true"/>
  <!--指定使用 Spring 框架作为对象工厂。集成Struts2和Spring-->
  <constant name="struts.objectFactory" value="spring" />
  <!--请求Action的url后缀为.action-->
  <constant name="struts.action.extension" value="action, do"/>
	<!--Action的类名以Action为后缀-->
	<constant name="struts.convention.action.suffix" value="Action" />
	<!--Action中没有@Action注解也创建映射-->
	<constant name="struts.convention.action.mapAllMatches" value="true" />
  <!--配置查找Action类的包定位器，只在名为action的包及其子包中查找Action类-->
	<constant name="struts.convention.package.locators" value="action" />
</struts>
```

### package

`package`标签声明了不同的包，将组件进行模块化。示例如下。只有name属性是必须的，作为package的唯一标识。`extends`代表继承某个package的所有配置。struts最基础的package是`extends="struts-default"`。`namespace`是Actions的唯一命名空间，也是该模块的**根路由**。

```xml
<package name="login-package" extends="itc-default" namespace="/">
  <action name="login_*" class="loginAction" method="{1}">
    <result name="input">/pages/login/login.jsp</result>
  </action>
</package>
```

**PS：有的`namespace`的值可能为`/a`，那么该package下的所有路由前缀都要加上`/a`**

可以看到上述packge继承自`itc-default`，`itc-default`内容如下，作为基础包定义了全局的拦截器、异常跳转等内容。

```xml
<package name="itc-default" extends="struts-default">
		<interceptors>
			<interceptor-stack name="myStack">
				<!--必须配置默认拦截器否则action表单中的参数将为null-->
				<interceptor-ref name="defaultStack" />
			</interceptor-stack>
			<interceptor name="interceptor" class="com.dahua.dssc.common.aop.Interceptor" />
		</interceptors>
		<!--定义全局异常跳转（PS:global-results必须在global-exception-mappings之前定义）-->
		<global-results>
			<result name="403Error">/common/403.jsp</result>
			<result name="500Error">/common/500.jsp</result>
			<result name="exception">/common/exception.jsp</result>
			<result name="timeout">/common/timeout.jsp</result>
		</global-results>
		<!--指定全局异常-->
		<global-exception-mappings>
			<exception-mapping result="exception" exception="java.lang.Exception" />
		</global-exception-mappings>
	</package>
```

另外，如果模块过多，Struts2配置时一般将配置文件拆分成多个xml文件，将`struts.xml`作为所有xml文件的入口，如下。具体的上述配置就要在`struts.xml`中的引入的某个xml中查看。

```xml
<struts>
	<include file="struts/struts-base.xml" />
	<include file="struts/struts-core.xml" />
	...
</struts>
```

### action

每个url对应了一个特定的Action。Action有三种实现方式

```java
public class TestAction{
	public String login() throws Exception { // 包含一个无参数方法返回String或Result对象
      return "success";
   }
}

public class TestAction implements Action{
  @Override
  public String execute() throws Exception {...} // 实现Action接口重写execute方法
}

public class TestAction extends ActionSupport{ 
  public String list() { // 实现ActionSupport接口，不用重写execute方法
    return "list";
  }
}
```

这些定义的Action配置在`struts.xml`中也有三种形式

1是将要调用的Action和方法都配置。2是用通配符`*`替换Action的名字或方法名。3是动态调用，只需要在`struts.xml`中配置`DynamicMethodInvocation`为true。就可以通过`action!method`的形式来调用

```xml
# 1
<action name="list" class="com.action.TestAction" method="list" />
  
# 2
<action name="login_*" class="loginAction" method="{1}">
  <result name="input">/pages/login/login.jsp</result>
</action>

<action name="*_*" class="{1}Action" method="{2}">
	<result name="j_{1}_{2}" type="json">
		<param name="root">returnMessage</param>
	</result>
</action>

<action name="/edit*" class="org.apache.struts.webapp.example.Edit{1}Action">
    <result name="failure">/mainMenu.jsp</result>
    <result>{1}.jsp</result>
</action>

<package name="default" namespace="/" extends="struts-default">
  <global-allowed-methods>login,register</global-allowed-methods>
  <action name="user_*" class="action.TestAction" method="{1}">
    <result name="login">/success.jsp</result>
  </action>
</package>

# 3
<action name="ccsAction!*" class="ccsShareAction" method="{1}"></action>
```

另外，还有个需要注意的地方。`class`的值可以省略的，如果省略了默认为`com.opensymphony.xwork2.ActionSupport`类。以如下的案例为例，实际访问的就是result标签中的jsp文件。

```xml
<action name="dishConfig">
	<result>/modules/ccs/dishConfig.jsp</result>
</action>
```

关于正则通配符的用法可以参考官网：https://struts.apache.org/core-developers/wildcard-mappings.html

