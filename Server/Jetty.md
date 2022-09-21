# Jetty

版本下载： https://repo1.maven.org/maven2/org/eclipse/jetty/jetty-distribution/

相关漏洞： https://github.com/eclipse/jetty.project/security/advisories

历史漏洞

|漏洞编号|漏洞类型|影响版本|
|:----:|:----:| :----:|
|CVE-2021-28164|信息泄漏|9.4.37.v20210219 to 9.4.38.v20210224|
|CVE-2021-28169|信息泄漏|<= 9.4.40, <= 10.0.2, <= 11.0.2|
|CVE-2021-34429|信息泄漏|9.4.37-9.4.42, 10.0.1-10.0.5 & 11.0.1-11.0.5|
|CVE-2021-28165|DoS|7.2.2 to 9.4.38, 10.0.0.alpha0 to 10.0.1, and 11.0.0.alpha0 to 11.0.1|



## CVE-2021-28164
官方声明： https://github.com/eclipse/jetty.project/security/advisories/GHSA-v7ff-8wcx-gmc5

在官方声明中可以看到9.4.37版对URI引入了RFC3986。默认允许%编码。POC如下，可以读取/WEB-INF/下的文件
```
GET /%2e/WEB-INF/web.xml
```

因为涉及到URL解析，就需要看一下Jetty处理请求的流程，在这个过程中对URL进行了哪些处理，并且为什么会加载文件。

### Jetty请求处理流程
Jetty分为两大类部分: Connector（处理Socket）和Handler（处理请求）。因为路径是HTTP请求的问题，所以这里并不关注Socket是怎么处理的。直接从Connector和Handler连接处入手开始看。二者的连接是由Connection组件完成的，它会解析读到的数据，生成请求对象并交给Handler组件去处理。
```
HttpConnection.onFillable
  HttpConnection.parseRequestBuffer
    HttpParser.parseNext
      HttpParser.parseLine
        HttpURI.parse -> !
      HttpParser.parseFields
        HttpChannel.onRequest  -> Request.setMetaData() 会对路径进行一次url解码
          HttpChannel.handle
            HttpChannel.dispatch
              Server.handle
                HandlerWrapper.handle
```
<details>
    <summary>Request.setMetaData</summary>
    <pre><code>
public void setMetaData(org.eclipse.jetty.http.MetaData.Request request) {
    if (uri.isAmbiguous()) {
        if (!uri.hasAmbiguousSeparator() || compliance != null && !compliance.sections().contains(HttpComplianceSection.NO_AMBIGUOUS_PATH_SEPARATORS)) {
            if (!uri.hasAmbiguousParameter() || compliance != null && !compliance.sections().contains(HttpComplianceSection.NO_AMBIGUOUS_PATH_PARAMETERS)) {
                break label128;
            }

            throw new BadMessageException("Ambiguous path parameter in URI");
        }
    }
    ...
    String encoded = uri.getPath(); // 截取ip:port后的路径
    if (encoded == null) {
        path = uri.isAbsolute() ? "/" : null;
        uri.setPath(path);
    } else if (encoded.startsWith("/")) { 
        path = encoded.length() == 1 ? "/" : uri.getDecodedPath(); // 路径以/开头，并且长度部位1，进行URL解码
    } else if (!"*".equals(encoded) && !HttpMethod.CONNECT.is(this.getMethod())) {
        path = null;
    } else {
        path = encoded;
    }...
}
    </code></pre>
</details>

Jetty是通过HandlerWrapper来实现责任链设计。Handler链式调用的流程大致如下
```
ContextHandler.doScope
  ScopedHandler.nextScope
    SessionHandler.doScope
      ServletHandler.doScope
        ScopedHandler.nextScope
          ContextHandler.doHandle  -> `ContextHandler.isProtectedTarget()`判断路径是否以/web-inf或/meta-inf开头(不区分大小写)，如果是则禁止访问
            ScopedHandler.nextHandle
              SessionHandler.doHandle
                ServletHandler.doHandle
                  ServletHolder.handle
                    HttpServlet.service
                      DefaultServlet.doGet
```

<details>
    <summary>ContextHandler.isProtectedTarget()</summary>
    <pre><code> 
public boolean isProtectedTarget(String target) {
    if (target != null && this._protectedTargets != null) { // this._protectedTargets: ["/web-inf", "/meta-inf"]
        while(target.startsWith("//")) {
            target = URIUtil.compactPath(target);
        }
        for(int i = 0; i < this._protectedTargets.length; ++i) {
            String t = this._protectedTargets[i];
            if (StringUtil.startsWithIgnoreCase(target, t)) {
                if (target.length() == t.length()) {
                    return true;
                }
                char c = target.charAt(t.length());
                if (c == '/' || c == '?' || c == '#' || c == ';') {
                    return true;
                }
            }...
    }
    </code></pre>
</details>

### 文件加载
至于为什么会加载文件，就要看链式调用最后`DefaultServlet.doGet`到底怎么实现的。几个关键方法如下：
```java
// DefaultServlet
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException { // DefaultServlet.doGet
    if (!this._resourceService.doGet(request, response)) {
        response.sendError(404);
    }
}

// ResourceService
public boolean doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    content = this._contentFactory.getContent(pathInContext, response.getBufferSize()); // 从_cache中获取Context，如果_cache中没有就调用Resource resource = this._factory.getResource(pathInContext);再加载对应的context
    if (content != null && content.getResource().exists()) {
        if (content.getResource().isDirectory()) { ... } 
        else if (!included && endsWithSlash && pathInContext.length() > 1) { ... }
        else {
            releaseContent = this.sendData(request, response, included, content, reqRanges);
        }
    }
}

// ResourceHandler
public Resource getResource(String path) throws MalformedURLException {
    if (path != null && path.startsWith("/")) {
        if (this._baseResource == null) {
            return null;
        } else {
            try {
                path = URIUtil.canonicalPath(path); // 将/./转换为 /
                Resource resource = this._baseResource.addPath(path); // file:///JettyMemShell/out/artifacts/DebugJetty_war_exploded/WEB-INF/web.xml
                return this.checkAlias(path, resource) ? resource : null;
            } ...
    } ...
}
```

`URIUtil.canonicalPath`是用于规范化路径的方法，具体代码点击展开
<details>
    <summary>URIUtil.canonicalPath</summary>
    <pre><code>
public static String canonicalPath(String path) {
    if (path != null && !path.isEmpty()) {
        int end = path.length();
        int i = 0;
        byte dots;
        label77:
        for(dots = 0; i < end; ++i) {
            char c = path.charAt(i);
            switch(c) {
            case '.':
                if (dots == 0) {  // 如果有. 就跳出循环
                    dots = 1;
                    break label77;
                }
                dots = -1;
                break;
            case '/':
                dots = 0;
                break;
            default:
                dots = -1;
            }
        }
        if (i == end) {
            return path;
        } else { // 刚进入else时dots为1
            StringBuilder canonical = new StringBuilder(path.length());
            canonical.append(path, 0, i);
            ++i;
            for(; i <= end; ++i) { // 对. 后的内容进行判断
                char c = i < end ? path.charAt(i) : 0;
                switch(c) {
                case '\u0000':
                    if (dots == 2) { //如果出现空字符就将空字符去掉
                        if (canonical.length() < 2) {
                            return null;
                        }
                        canonical.setLength(canonical.length() - 1);
                        canonical.setLength(canonical.lastIndexOf("/") + 1);
                    }
                    break;
                case '.':
                    switch(dots) {
                    case 0:
                        dots = 1;
                        continue;
                    case 1:
                        dots = 2;
                        continue;
                    case 2:
                        canonical.append("...");
                        dots = -1;
                        continue;
                    default:
                        canonical.append('.');
                        continue;
                    }
                case '/':
                    switch(dots) {
                    case 1:
                        break; // 跳过此字符
                    case 2:
                        if (canonical.length() < 2) {
                            return null;
                        }
                        canonical.setLength(canonical.length() - 1);
                        canonical.setLength(canonical.lastIndexOf("/") + 1);
                        break;
                    default:
                        canonical.append(c); 
                    }
                    dots = 0;
                    break;
                default:
                    switch(dots) {
                    case 1:
                        canonical.append('.');
                        break;
                    case 2:
                        canonical.append("..");
                    }
                    canonical.append(c); // 直接将字符添加到末尾
                    dots = -1;
                }
            }
            return canonical.toString();
        }
    } else {
        return path;
    }
}
    </code></pre>
</details>
    
### POC构造思路
ContextHandler.doHandle方法在执行时，会调用isProtectedTarget()判断路径是否以`/web-inf`或`/meta-inf`开头(不区分大小写)，如果是则禁止访问。想要绕过这个限制，就需要路径为`/xxx/WEB-INF/`来绕过，并且`/xxx/`能被Jetty处理掉。常见的路径处理思路包括`/../`、`/./`、`/;/`等。Jetty中能处理哪些就需要在上述代码中找到会被路径处理的特殊字符。

上述过程中有两个地方值得注意（1）请求处理时`Request.setMetaData()`会对路径进行一次url解码 (2) 文件加载时，getResource会调用`URIUtil.canonicalPath(path)`，这一步会将`/./`转换为`/`。所以payload`/%2e/WEB-INF/web.xml`经过url解码变为`/./WEB-INF/web.xml`绕过了isProtectedTarget判断，并且在加载文件时`/./`被转换为`/`。最终加载的资源就是`/WEB-INF/web.xml`

那么对payload就会有几个问题：（1）`/./WEB-INF/web.xml` 行不行？（2）还有没有其他方式？

**（1）`/./WEB-INF/web.xml` 为何不行**
当对`/./WEB-INF/web.xml`进行测试时，会发现响应码404。具体调试会发现在上述请求流程的`HttpURI.parse`时进行如下操作。在canonicalPath时直接将`/./`转换成了`/`。这样进入到后续的请求target就是`/WEB-INF/web.xml`。后续ContextHandler.doHandle方法在执行时，无法通过isProtectedTarget()判断，响应码返回404
```
private void parse(HttpURI.State state, String uri, int offset, int end) {
    for(int i = offset; i < end; ++i) {
        case PATH:
            switch(c) {
            case '#':
                this.checkSegment(uri, segment, i, false);
                this._path = uri.substring(pathMark, i);
                mark = i + 1;
                state = HttpURI.State.FRAGMENT;
                continue;
            case '%':
                encoded = true;
                escapedSlash = 1;
                continue;
            case '.':
                dot |= segment == i;
                continue;
            case '/':
                this.checkSegment(uri, segment, i, false);
                segment = i + 1;
                continue;
            case '2':
                escapedSlash = escapedSlash == 1 ? 2 : 0;
                continue;
            case ';':
                this.checkSegment(uri, segment, i, true);
                mark = i + 1;
                state = HttpURI.State.PARAM;
                continue;
            case '?':
                this.checkSegment(uri, segment, i, false);
                this._path = uri.substring(pathMark, i);
                mark = i + 1;
                state = HttpURI.State.QUERY;
                continue;
            case 'F':
            case 'f':
                if (escapedSlash == 2) {
                    this._ambiguous.add(HttpURI.Ambiguous.SEPARATOR);
                }

                escapedSlash = 0;
                continue;
            default:
                escapedSlash = 0;
                continue;
            }
    ...
    else if (this._path != null) {
        String canonical = URIUtil.canonicalPath(this._path);
        if (canonical == null) {
            throw new BadMessageException("Bad URI");
        }
        this._decodedPath = URIUtil.decodePath(canonical);
    }
}
```
这部分解析时还会进行decodePath处理，具体代码点击展开
<details>
    <summary>URIUtil.decodePath</summary>
    <pre><code>
    public static String decodePath(String path, int offset, int length) {
        try {
            Utf8StringBuilder builder = null;
            int end = offset + length;
            label67:
            for(int i = offset; i < end; ++i) {
                char c = path.charAt(i);
                switch(c) {
                case '%':
                    if (builder == null) {
                        builder = new Utf8StringBuilder(path.length());
                        builder.append(path, offset, i - offset);
                    }
                    if (i + 2 >= end) {
                        throw new IllegalArgumentException("Bad URI % encoding");
                    }
                    char u = path.charAt(i + 1);
                    if (u == 'u') {
                        builder.append((char)('\uffff' & TypeUtil.parseInt(path, i + 2, 4, 16)));
                        i += 5;
                    } else {
                        builder.append((byte)(255 & TypeUtil.convertHexDigit(u) * 16 + TypeUtil.convertHexDigit(path.charAt(i + 2))));
                        i += 2;
                    }
                    break;
                case ';':
                    if (builder == null) {
                        builder = new Utf8StringBuilder(path.length());
                        builder.append(path, offset, i - offset); 
                    }
                    do {
                        ++i;
                        if (i >= end) {
                            continue label67;
                        }
                    } while(path.charAt(i) != '/');
                    builder.append('/');
                    break;
                default:
                    if (builder != null) {
                        builder.append(c);
                    }
                }
            }
            if (builder != null) {
                return builder.toString();
            } else if (offset == 0 && length == path.length()) {
                return path;
            } else {
                return path.substring(offset, end);
            }
        } ...
    }
    </code></pre>
</details>

**（2）`/.;/WEB-INF/web.xml`为何不行**
如果是常见的`/.;/WEB-INF/web.xml`这种形式的payload，在`HttpURI.parse()`时，`;`作为特殊字符会执行`this.checkSegment(uri, segment, i, true);`
```
private void checkSegment(String uri, int segment, int end, boolean param) {
    if (!this._ambiguous.contains(HttpURI.Ambiguous.SEGMENT)) {
        Boolean ambiguous = (Boolean)__ambiguousSegments.get(uri, segment, end - segment);
        if (ambiguous == Boolean.TRUE) {
            this._ambiguous.add(HttpURI.Ambiguous.SEGMENT);
        } else if (param && ambiguous == Boolean.FALSE) {
            this._ambiguous.add(HttpURI.Ambiguous.PARAM); // _ambiguous 被赋值为PARAM
        }
    }
}
    
static {
    __ambiguousSegments.put("%2e", Boolean.TRUE);
    __ambiguousSegments.put("%2e%2e", Boolean.TRUE);
    __ambiguousSegments.put(".%2e", Boolean.TRUE);
    __ambiguousSegments.put("%2e.", Boolean.TRUE);
    __ambiguousSegments.put("..", Boolean.FALSE);
    __ambiguousSegments.put(".", Boolean.FALSE);
}
```
后续执行到`Request.setMetaData()`时，由于_ambiguous不为空，会进入到`if (uri.isAmbiguous()) `判断中，进而抛出异常`"Ambiguous path parameter in URI"`
```
public boolean isAmbiguous() {
    return !this._ambiguous.isEmpty();
}
```

##  CVE-2021-34429
CVE-2021-34429是对CVE-2021-28164的补丁绕过。CVE-2021-28164的修复补丁参考： https://github.com/eclipse/jetty.project/commit/e412c8a15b3334b30193f40412c0fbc47e478e83

setMetaData处作了修改，当ambiguous为true时（增加了是否为歧义路径的判断），并且是在路径解码之后再次进行歧义路径判断，然后才执行上述过程中的代码
```
public void setMetaData(org.eclipse.jetty.http.MetaData.Request request) {
-if (uri.isAmbiguous())
+boolean ambiguous = uri.isAmbiguous();
+if (ambiguous) {
+    else if (encoded.startsWith("/")){
        path = (encoded.length() == 1) ? "/" : uri.getDecodedPath();
+       if (ambiguous)
+           path = URIUtil.canonicalPath(path);
     }
}
``` 
也就是说uri中不能包含`.`与`%2e`的各类组合。能利用的还是URL解码、`URIUtil.canonicalPath(path)`将`/./`转换为`/`这两个条件。那么一个切入点就是decodePath方法。%2e的payload是走的else分支。那么如果%后面跟的是字符u，就会走if分支，解析unicode字符。那么`%u002e`就会被解析为`.`从而绕过`.`与`%2e`的各类组合的限制。后续`/./`解析与上述漏洞一致。
```
for(int i = offset; i < end; ++i) {
    char c = path.charAt(i);
    switch(c) {
    case '%':
        builder.append(path, offset, i - offset);
        char u = path.charAt(i + 1);
        if (u == 'u') {
            builder.append((char)('\uffff' & TypeUtil.parseInt(path, i + 2, 4, 16)));
            i += 5;
        } else {
            builder.append((byte)(255 & TypeUtil.convertHexDigit(u) * 16 + TypeUtil.convertHexDigit(path.charAt(i + 2))));
            i += 2;
        }
    }
```
                            
然后就出现了关于payload的三个变形来绕过此补丁
```
/%u002e/WEB-INF/web.xml
/.%00/WEB-INF/web.xml
/a/b/..%00/WEB-INF/web.xml
```
第二个payload`/.%00/WEB-INF/web.xml`和`%2e`类似，都是利用decodePath方法的else分支，`%00`会被解码为空字符。后续再执行到`URIUtil.canonicalPath(path)`时代码
```java
case '\u0000':
    if (dots == 2) { //如果出现空字符就将空字符去掉
        if (canonical.length() < 2) {
            return null;
        }
        canonical.setLength(canonical.length() - 1); // 将/a/b/最后一位去掉 -> /a/b
        canonical.setLength(canonical.lastIndexOf("/") + 1); // 取最后一位/ -> /a/
    }
    break;
case '/':
    switch(dots) {
    case 1:
        break; // 跳过此字符
    case 2:
        if (canonical.length() < 2) {
            return null;
        }
        canonical.setLength(canonical.length() - 1); // 将/a/最后一位去掉 -> /a
        canonical.setLength(canonical.lastIndexOf("/") + 1); // 取最后一位/ -> /
        break;
    default:
        canonical.append(c); 
    }
    dots = 0;
    break;
```
`case '\u0000'`会将空字符直接去掉。这样payload最终又变为`/./WEB-INF/web.xml`
    
第三个payload和第二个payloady也很类似，只是在`case '\u0000'`，进入了`dots==2`的分支。然后将前部分payload处理为`/a/`。由于dots值并没有发生变化，又进入了`case '/'`分支，将`/a/`处理为了`/`。这样最终路径就将`/a/b/`全部去掉了，只剩`/WEB-INF/web.xml`。这个payload也是很巧妙

## CVE-2021-28169
Ref： https://bugs.eclipse.org/bugs/show_bug.cgi?id=573389
  
## CVE-2021-28165
Ref： https://security.snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-1090340
  

  
