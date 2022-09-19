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
本身Jetty在进行链条处理时`ContextHandler.doScope()`会调用到`ContextHandler.isProtectedTarget()`判断路径是否以/web-inf或/meta-inf开头，如果是则禁止访问
```java
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
            }
        }

        return false;
    } else {
        return false;
    }
}
```
想要绕过这个限制，就需要路径为`/xxx/WEB-INF/`，并且`/xxx/`能正常被Jetty处理。跟进Jetty的路径请求处理流程。
（1）Jetty在对请求进行协议处理时，会调用Request类对URI进行处理（会进行一次url解码）
```java
public void setMetaData(org.eclipse.jetty.http.MetaData.Request request) {
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
```
（2）请求处理完，会分发到容器类ContextHandler进行解析，再经过Handler处理链，逐步走到对应的Servlet：`ServletHandler.doFilter -> HttpServlet.service() -> DefaultServlet.doGet`
```java
protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException { // DefaultServlet.doGet
    if (!this._resourceService.doGet(request, response)) {
        response.sendError(404);
    }
}

public boolean doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    content = this._contentFactory.getContent(pathInContext, response.getBufferSize());
    if (content != null && content.getResource().exists()) {
        if (content.getResource().isDirectory()) { ... } 
        else if (!included && endsWithSlash && pathInContext.length() > 1) { ... }
        else {
            releaseContent = this.sendData(request, response, included, content, reqRanges);
        }
    }
}


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
                if (dots == 0) {
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
        } else {
            StringBuilder canonical = new StringBuilder(path.length());
            canonical.append(path, 0, i);
            ++i;

            for(; i <= end; ++i) {
                char c = i < end ? path.charAt(i) : 0;
                switch(c) {
                case '\u0000':
                    if (dots == 2) {
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
                        break;
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

                    canonical.append(c);
                    dots = -1;
                }
            }

            return canonical.toString();
        }
    } else {
        return path;
    }
}
```

##  CVE-2021-34429
CVE-2021-34429是对CVE-2021-28164的补丁绕过。CVE-2021-28164的修复补丁参考： https://github.com/eclipse/jetty.project/commit/e412c8a15b3334b30193f40412c0fbc47e478e83


## CVE-2021-28165
Ref： https://security.snyk.io/vuln/SNYK-JAVA-ORGECLIPSEJETTY-1090340
