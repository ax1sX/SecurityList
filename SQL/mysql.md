## MySQL注入

创建
```
// 数据库
create database test;
// 数据表
create table users (id int, username varchar(255), password varchar(255));
```

查询库、表
```
// 查询数据库
show databases;

// 查询数据表
use test;
show tables;

// 查询数据表
select table_name from information_schema.tables where table_schema=0x74657374; // "test" 或 "test"的十六进制表示

// 查询列
select column_name from information_schema.columns where table_name=0x7573657273;  // "users" 或 "users"的十六进制表示

// 具体查询某数据库、某表的列
select column_name from information_schema.columns where table_name=0x7573657273 and table_schema=0x74657374;
```
`information_schema`是用于存储数据库元数据的表，它保存了数据库名，表名，列名等信息。`SCHEMATA`表保存所有数据库信息；`TABLES`表保存数据库中的表信息。`COLUMNS`表保存了表的列信息

查询字段
```
select * from users where id = 1;
select * from users where id = '1';
select * from users where id = "1";
select * from users where id = (1);
select * from users where id = ('1');
select * from users where id = ("1");
select * from users where username  like '%adm%';
select * from users where username  like ('%adm%');
```

查询数据库版本
```
select @@version;
select version();
select /*!40000 version()*/
```
`/*!`后面跟的是版本，表示在X版本之上执行。上面表示的是在mysql4以上版本执行

信息查询
```
select @@datadir;  // 查询数据库所在路径
select @@version_compile_os;  //查询操作系统
select system_user() //系统用户名 
select user() //用户名 
select current_user() //当前用户名 
select session_user() //连接数据库的用户名
select 1,host,user from mysql.user; //查询host与user

```

注释
```
# 
/*xxxx*/  
/*/*xxxx*/
--空格
;%00
```



附录（sqli-labs环境搭建）
```
docker search sqli-labs  //搜索sqli-labs
docker pull acgpiano/sqli-labs  //拉取镜像
docker images  //查看镜像
docker run -dt --name sqli-labs -p 8081:80 --rm acgpiano/sqli-labs  //后台运行镜像，docker端口映射到主机端口，执行后会返回一个ID号
docker exec -it ID号 /bin/bash  //进入docker容器
//参数解释：-dt  后台运行； --name  命名；-p 80:80  将后面的docker容器端口映射到前面的主机端口。
docker start sqli-labs  //启动
```



