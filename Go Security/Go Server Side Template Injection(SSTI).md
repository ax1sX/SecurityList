# Go Server Side Template Injection(SSTI)

Golang的标准库中，支持使用使用模板来定义输出文件的格式和内容，它们分别是[text/template]()和 [html/template]()。它们都支持将变量或方法与模板绑定在一起，从而实现View于Data的分离。

## Template 介绍

两者有一点不同的是，前者不带过滤器，对于在模板中展示的内容，不会进行编码或转义。但后者由于在web场景中使用，增加了[安全机制](https://rawgit.com/mikesamuel/sanitized-jquery-templates/trunk/safetemplate.html#problem_definition)，会对内容进行转义。下面看示例：

```go
package main

import (
	"fmt"
	"html/template"
	"net/http"
)

func main() {
	payload := "<script>alert(1)</script>"
	var tmpl = `{{ . }}`

	t := template.Must(template.New("").Parse(tmpl))

	t.Execute(os.Stdout, &payload)
}
```
输出内容如下
```html
&lt;script&gt;alert(1)&lt;/script&gt;
```
将`html/template`替换为`text/tempalte`后，输出如下
```
<script>alert(1)</script>
```
根据文档的说明，对于模版
```html
<a href="/search?q={{.}}">{{.}}</a>
```
实际解析过程中会被替换为如下内容
```html
<a href="/search?q={{. | urlescaper | attrescaper}}">{{. | htmlescaper}}</a>
```
所以，实际上解析器会根据上下文的不同，调用对应方法将内容进行转义。而Golang中的模板注入，根据注入的方式不同，会造成不同的影响。一种情况是，模板内容可控，另一种是注入目标的数据对象可控。
```go
var tmpl = fmt.Sprintf(`{{ . }} %s`, injected_tempalte) 
// or
var tmpl = `{{ .Payload }}`
t := template.Must(template.New("").Parse(tmpl))
t.Execute(os.Stdout, injected_data_object)
```

### 函数调用

Go中的模板语法还支持其它功能，变量声明，条件判断，循环，函数调用等。模板的全局上下文有如下函数：
| function             | description                                                                                                                                                |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `and`                  | 返回参数逻辑与的结果，直到遇到第一个空的参数，或最后一个参数的结果。如`and x y`，执行逻辑为`if x then y else x`                                            |
| `call`                 | 返回被调用方法的结果，被调用方法需要返回一个或两个返回值，且第二个返回值为`error`，若`error`不为空则停止后续执行。如`call .X.Y 1 2`，执行逻辑为`.X.Y(1,2)` |
| `html`                 | 返回HTML转义后的内容，`html/tempalte`包中不可用                                                                                                            |
| `index`                | 返回给定参数索引后的值，`index x 1`，等价于`x[1]`                                                                                                          |
| `slice`                | 返回给定参数的切片                                                                                                                                         |
| `print/printf/println` | `fmt.print/fmt.printf/fmt.println`                                                                                                                         |

>更详细的内容见，https://pkg.go.dev/text/template#hdr-Functions

## 安全隐患

### XSS

`html/template`的主要目的之一就是为了防止`XSS`漏洞的产生，所以它具备较完善的安全机制，会对渲染的内容进行转义。如果能让注入的内容不被转义，那么就可能导致`XSS`。一种方法是，使用如下模板语法，进行注入
```go
{{ define "T" }}<script>alert(1)</script>{{ end }}{{template "T"}}
```
> 这段语句的意思是，定义一个模板，并通过`{{template "T"}}`使用它。

下面是一段示例代码
```go
package main

import (
	"fmt"
	"html/template"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()["q"][0]
		tmp := fmt.Sprintf(`
<h1> Hi {{ . }} %s </h1>`, q)
		tmpl := template.Must(template.New("page").Parse(tmp))
		tmpl.Execute(w, "")
	})
	http.ListenAndServe(":80", nil)
}
```
发送如下请求
```http
localhost?q={{%20define%20"T"%20}}<script>alert(1)</script>{{%20end%20}}{{template%20"T"}}
```
成功弹窗，当然这里需要假设**模板可控**。
![](../images/Pasted%20image%2020230307105828.png)

### 代码执行
>这部分内容是最为鸡肋的，现实中应该很难碰到。

除了内嵌的函数，模板中还能调用传入对象所具有的方法。具体见下面的例子
```go
package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
)

type Todo struct {
	Title string
	Done  bool
}

type TodoPageData struct {
	PageTitle string
	Todos     []Todo
}

func (t *Todo) TodoFunc(content string) string {
	b := bytes.Buffer{}
	fmt.Fprintln(&b, t.Done, content)
	return b.String()
}

func main() {
	tmpl := template.Must(template.ParseFiles("layout.html"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := TodoPageData{
			PageTitle: "My TODO list",
			Todos: []Todo{
				{Title: "Task 1", Done: false},
				{Title: "Task 2", Done: true},
				{Title: "Task 3", Done: true},
			},
		}
		tmpl.Execute(w, data)
	})
	http.ListenAndServe(":80", nil)
}
```
`layout.html`
```html
<h1>{{.PageTitle}}</h1>
<ul>
    {{range .Todos}}
        {{if .Done}}
            <li class="done">{{.TodoFunc .Title}}</li>
        {{else}}
            <li>{{.Title}}</li>
        {{end}}
    {{end}}
</ul>
```
结果如下。
![](../images/Pasted%20image%2020230310210247.png)
如果此方法是一个危险的方法，例如可执行命令或者读取文件，那就会导致危险行为的产生。对代码进行修改：
```go
func main() {
	tmpl := template.Must(template.ParseFiles("layout.html"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		todo := r.URL.Query()["q"][0]
		data := TodoPageData{
			PageTitle: "My TODO list",
			Todos: []Todo{
				{Title: todo, Done: true},
			},
		}
// ...
func (t *Todo) TodoFunc(content string) string {
	out, _ := exec.Command(content).CombinedOutput()
	return string(out)
}
```
![](../images/Pasted%20image%2020230310211445.png)
如果模板可控，那么可以使用`{{ .TodoFunc "cmd" }}`来调用所需方法。

## 参考
1. https://blog.takemyhand.xyz/2020/05/ssti-breaking-gos-template-engine-to.html
2. https://www.onsecurity.io/blog/go-ssti-method-research/
