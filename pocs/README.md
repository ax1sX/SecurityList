整体格式参考[Xray](https://docs.xray.cool/#/guide/poc/v2)，简化版本。
### 示例
如下是一个`poc`示例：
```yaml
name: poc-yaml-example-com
# 脚本部分
transport: http
rules:
    r1:
        request:
            method: GET
            path: "/"
        expression: |
            response.status==200 && response.body.bcontains(b'Example Domain')
expression:
    r1()
# 信息部分
detail:
    author: name(link)
    links: 
        - http://example.com

```
整个`poc`分为`3`个部分

- 名称部分：`poc`名称，类型为`string`
- 脚本逻辑部分：`poc`规则，描述`poc`的主要构成
- 描述信息部分：其它描述
### 脚本部分
分为`4`个部分

- 传输协议，仅支持`http`
- 变量定义（`set`）
- 规则描述（`rules`）
- 规则表达式（`expression`）
#### 传输协议
用于指定所用协议，目前只支持http。`transport: http`
#### 变量定义
可定义在规则或表达式中需要使用的变量，例如字符串或随机数，格式如下
```yaml
set:
    a: 1
```
#### 规则描述
定义具体规则`rules`
```yaml
rules:
    # 规则可以有多个，r0 r1 r2...
    r1:
        # 此处为一个 http request 的例子
        request:
            method: GET
            path: "/"
        expression: |
            response.status==200 && response.body.bcontains(b'Example Domain')
```
每一个`rule`包含以下内容

- 唯一的`key`值，如`r1`
- `request`：用于构造请求，也就是`poc`
- `expression`：用于判断返回结果，检查响应内容

`request`完整支持的字段如下
```yaml
# 请求方法
method: GET
# URI，可携带参数
path: /
# 请求头字段
headers:
    Content-Type: application/xml
# 请求体内容
body: aaaa
```
`expression`用于检查`poc`的执行结果
```yaml
expression: |
    response.status==200 && response.body.bcontains(b'Example Domain')
```
#### 规则表达式
规则表达式也以`expression`为标记，`expression: string`。
定义规则间的执行逻辑，如
```yaml
expression: |
    r1() || r2()
```
### Expression编写
`expression`使用[Common Expression Language (CEL)](https://github.com/google/cel-spec)表达式语法，类似于`spel`或`ognl`，用于在`golang`中执行语句。
目前支持的对象类型有，request和response
request包含的字段如下：

| **变量名** | **类型** | **说明** |
| --- | --- | --- |
| request.raw | []byte | 原始请求 |
| request.url | urlType | 自定义类型 urlType, 请查看下方 urlType 的说明 |
| request.method | string | 原始请求的方法 |
| request.headers | map[string]string | 原始请求的HTTP头，是一个键值对（均为小写），我们可以通过headers['server']来获取值。如果键不存在，则获取到的值是空字符串。注意，该空字符串不能用于 == 以外的操作，否则不存在的时候将报错，需要先 in 判断下。详情参考下文常用函数章节。 |
| request.content_type | string | 原始请求的 content-type 头的值, 等于request.headers["Content-Type"] |
| request.raw_header | []byte | 原始的 header 部分，需要使用字节流相关方法来判断。 |
| request.body | []byte | 原始请求的 body，需要使用字节流相关方法来判断。如果是 GET， body 为空。 |

response包含的字段如下：

| **变量名** | **类型** | **说明** |
| --- | --- | --- |
| response.raw | []byte | 原始响应 |
| response.url | urlType | 自定义类型 urlType, 请查看下方 urlType 的说明 |
| response.status | int | 返回包的status code |
| response.raw_header | []byte | 原始的 header 部分，需要使用字节流相关方法来判断。 |
| response.body | []byte | 返回包的Body，因为是一个字节流（bytes）而非字符串，后面判断的时候需要使用字节流相关的方法 |
| response.body_string | string | 返回包的Body，是一个字符串 |
| response.headers | map[string]string | 返回包的HTTP头，类似 request.headers。 |
| response.content_type | string | 返回包的content-type头的值 |

